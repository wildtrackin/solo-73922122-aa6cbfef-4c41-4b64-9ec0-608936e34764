"""SQLite 版本化存储测试：原子提交、代际冲突、过期计算、跨连接一致性。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.rtr import ROA, Snapshot
from app.storage import GenerationConflict, RPKIStore


def make_snapshot(session=1, serial=10, expire=7200, roas=None):
    if roas is None:
        roas = [
            ROA(64500, "198.51.100.0/24", 24, 24, session),
            ROA(64501, "203.0.113.0/24", 24, 25, session),
        ]
    return Snapshot(session, serial, expire, tuple(roas))


class StorageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "rpki.db")
        self.store = RPKIStore(self.db_path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_version_initially(self):
        self.assertIsNone(self.store.current_version())
        self.assertEqual(self.store.generation(), 0)

    def test_commit_creates_version_and_roas(self):
        snap = make_snapshot()
        version = self.store.commit_snapshot(
            snap, expected_generation=0, eod_arrived_at=1000.0
        )
        self.assertEqual(version.version_id, 1)
        self.assertEqual(version.session_id, 1)
        self.assertEqual(version.serial, 10)
        self.assertEqual(version.roa_count, 2)
        # 到期 = EOD 到达时刻 + expire interval。
        self.assertEqual(version.expires_at, 1000.0 + 7200)
        self.assertFalse(version.is_expired(now=2000.0))
        self.assertTrue(version.is_expired(now=1000.0 + 7200))

        roas = self.store.load_roas(version.version_id)
        self.assertEqual(len(roas), 2)
        self.assertEqual(roas[0].asn, 64500)
        self.assertEqual(roas[1].max_length, 25)

    def test_failed_sync_keeps_old_version(self):
        first = self.store.commit_snapshot(
            make_snapshot(serial=1), expected_generation=0, eod_arrived_at=0.0
        )
        # 模拟同步失败：根本不调用 commit，旧版本必须原样保留。
        self.assertEqual(self.store.generation(), first.version_id)
        current = self.store.current_version()
        self.assertEqual(current.serial, 1)

    def test_generation_conflict_discards_result(self):
        self.store.commit_snapshot(
            make_snapshot(serial=1), expected_generation=0, eod_arrived_at=0.0
        )
        # 另一个“进程”（同库不同连接）先提交了 v2。
        other = RPKIStore(self.db_path)
        other.commit_snapshot(
            make_snapshot(serial=2), expected_generation=1, eod_arrived_at=10.0
        )
        # 本次同步开始时记录的代际仍是 1，但当前已是 2 -> 丢弃。
        with self.assertRaises(GenerationConflict):
            self.store.commit_snapshot(
                make_snapshot(serial=99),
                expected_generation=1,
                eod_arrived_at=20.0,
            )
        self.assertEqual(self.store.current_version().serial, 2)

    def test_versions_chain_and_readers_use_latest(self):
        v1 = self.store.commit_snapshot(
            make_snapshot(serial=1, roas=[ROA(1, "10.0.0.0/8", 8, 8, 1)]),
            expected_generation=0,
            eod_arrived_at=0.0,
        )
        v2 = self.store.commit_snapshot(
            make_snapshot(serial=2, roas=[ROA(2, "10.0.0.0/8", 8, 8, 1)]),
            expected_generation=1,
            eod_arrived_at=100.0,
        )
        self.assertEqual(self.store.generation(), v2.version_id)
        # 旧版本数据仍完整可读（同版完整数据）。
        self.assertEqual(self.store.load_roas(v1.version_id)[0].asn, 1)
        self.assertEqual(self.store.load_roas(v2.version_id)[0].asn, 2)

    def test_wal_files_created(self):
        self.store.commit_snapshot(
            make_snapshot(), expected_generation=0, eod_arrived_at=0.0
        )
        # WAL 模式会产生 -wal / -shm（检查点后可能合并，至少 journal_mode 正确）。
        import sqlite3

        conn = sqlite3.connect(self.db_path)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        conn.close()
        self.assertEqual(mode.lower(), "wal")


if __name__ == "__main__":
    unittest.main()
