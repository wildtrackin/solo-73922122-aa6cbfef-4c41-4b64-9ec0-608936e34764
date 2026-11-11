"""同步编排测试：真实本地 RTR 源、后台线程、断流保留旧版、代际冲突丢弃。"""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.rtr import ROA, Snapshot
from app.storage import RPKIStore
from app.sync import SyncManager
from rtr_source.server import (
    RTRHandler,
    RTRServer,
    RTRSourceState,
)


def wait_until(predicate, timeout=5.0, interval=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def start_rtr_source(mode="clean", dataset="baseline", expire=7200):
    state = RTRSourceState(expire_interval=expire)
    state.mode = mode
    state.dataset = dataset
    server = RTRServer(("127.0.0.1", 0), RTRHandler, state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state


class SyncManagerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "rpki.db")
        self.server, self.rtr_state = start_rtr_source()
        self.host, self.port = self.server.server_address
        self.store = RPKIStore(self.db_path)
        self.manager = SyncManager(self.store, self.host, self.port)

    def tearDown(self):
        self.server.shutdown()
        self.tmp.cleanup()

    def test_successful_sync_persists_snapshot(self):
        self.assertTrue(self.manager.start_sync())
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing()))
        self.assertIsNone(self.manager.status.last_error)
        version = self.store.current_version()
        self.assertIsNotNone(version)
        self.assertEqual(version.roa_count, 5)  # baseline 数据集 5 条
        roas = self.store.load_roas(version.version_id)
        self.assertEqual(roas[0].asn, 64500)

    def test_duplicate_sync_rejected_while_running(self):
        self.assertTrue(self.manager.start_sync())
        self.assertFalse(self.manager.start_sync())  # 进行中拒绝
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing()))
        # 完成后可以再次触发。
        self.assertTrue(self.manager.start_sync())
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing()))

    def test_failure_keeps_old_version(self):
        # 先成功同步一版。
        self.manager.start_sync()
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing()))
        first = self.store.current_version()
        self.assertIsNotNone(first)

        # 切换成 End of Data 前断流。
        self.rtr_state.set_mode("drop-eod")
        self.manager.start_sync()
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing()))
        self.assertIsNotNone(self.manager.status.last_error)
        current = self.store.current_version()
        self.assertEqual(current.version_id, first.version_id)
        self.assertEqual(current.serial, first.serial)

    def test_drop_reset_then_recover(self):
        self.rtr_state.set_mode("drop-reset")
        self.manager.start_sync()
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing()))
        self.assertIsNone(self.store.current_version())

        # 恢复正常后能成功同步，验证错误状态不影响后续尝试。
        self.rtr_state.set_mode("clean")
        self.manager.start_sync()
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing()))
        self.assertIsNotNone(self.store.current_version())

    def test_generation_conflict_discards_inflight_result(self):
        # 预置 v1，使本次同步开始时记录的代际为 1。
        self.store.commit_snapshot(
            Snapshot(1, 1, 7200, (ROA(1, "10.0.0.0/8", 8, 8, 1),)),
            expected_generation=0,
            eod_arrived_at=0.0,
        )
        # 分片模式制造足够长的同步窗口，在同步进行中由另一连接提交 v2，
        # 模拟另一个 Web 进程在同步期间替换了当前版本。
        self.rtr_state.set_mode("fragment")
        self.assertTrue(self.manager.start_sync())

        other = RPKIStore(self.db_path)
        other.commit_snapshot(
            Snapshot(2, 2, 7200, (ROA(2, "10.0.0.0/8", 8, 8, 2),)),
            expected_generation=1,
            eod_arrived_at=1.0,
        )
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing(), timeout=15))
        self.assertIn("丢弃", self.manager.status.last_error)
        # 本次结果被丢弃，v2 保持为当前版本。
        self.assertEqual(self.store.current_version().serial, 2)

    def test_expiry_computed_from_eod_arrival(self):
        before = time.time()
        self.manager.start_sync()
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing()))
        after = time.time()
        version = self.store.current_version()
        # expires_at 应落在 [before+7200, after+7200] 之间。
        self.assertGreaterEqual(version.expires_at, before + 7200 - 1)
        self.assertLessEqual(version.expires_at, after + 7200 + 1)

    def test_dataset_switch_increments_serial(self):
        self.manager.start_sync()
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing()))
        serial_v1 = self.store.current_version().serial

        self.rtr_state.set_dataset("alternate")
        self.manager.start_sync()
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing()))
        version = self.store.current_version()
        self.assertEqual(version.roa_count, 3)
        self.assertGreater(version.serial, serial_v1)

    def test_fragmented_transport_syncs_ok(self):
        self.rtr_state.set_mode("fragment")
        self.manager.start_sync()
        self.assertTrue(wait_until(lambda: not self.manager.is_syncing(), timeout=15))
        self.assertIsNone(self.manager.status.last_error)
        self.assertEqual(self.store.current_version().roa_count, 5)


if __name__ == "__main__":
    unittest.main()
