"""手动同步编排：后台线程跑 RTR 全量拉取，查询路径永不阻塞。

状态机：
    idle -> syncing -> idle（成功 / failed 都回到 idle）

并发与一致性：
  * 同一进程内重复点击同步会收到 409（is_syncing）；
  * 同步在守护线程中执行，HTTP 查询不等待网络；
  * 开始时记录数据库代际，提交时若代际已变（另一个 Web 进程
    完成了更新的同步），本次结果直接丢弃；
  * 任何断流 / 协议错误 / 代际冲突都不会触碰当前版本，旧版继续可用。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from app.rtr import RTRError, fetch_reset_snapshot
from app.storage import GenerationConflict, RPKIStore, VersionInfo


@dataclass
class SyncStatus:
    state: str = "idle"  # "idle" | "syncing"
    last_started_at: float | None = None
    last_finished_at: float | None = None
    last_error: str | None = None
    last_success_version_id: int | None = None
    attempts: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "state": self.state,
                "last_started_at": self.last_started_at,
                "last_finished_at": self.last_finished_at,
                "last_error": self.last_error,
                "last_success_version_id": self.last_success_version_id,
                "attempts": self.attempts,
            }

    def begin(self) -> bool:
        """尝试进入同步中状态；已在同步则返回 False。"""
        with self._lock:
            if self.state == "syncing":
                return False
            self.state = "syncing"
            self.last_started_at = time.time()
            self.last_error = None
            self.attempts += 1
            return True

    def finish(self, error_message: str | None, success_version_id: int | None) -> None:
        with self._lock:
            self.state = "idle"
            self.last_finished_at = time.time()
            self.last_error = error_message
            if success_version_id is not None:
                self.last_success_version_id = success_version_id


class SyncManager:
    def __init__(self, store: RPKIStore, host: str, port: int):
        self._store = store
        self._host = host
        self._port = port
        self._status = SyncStatus()
        self._thread: threading.Thread | None = None

    @property
    def status(self) -> SyncStatus:
        return self._status

    def is_syncing(self) -> bool:
        return self._status.state == "syncing"

    def start_sync(self) -> bool:
        """触发一次后台同步。已在同步中返回 False，成功触发返回 True。"""
        if not self._status.begin():
            return False

        thread = threading.Thread(
            target=self._run_sync,
            name="rtr-sync",
            daemon=True,
        )
        self._thread = thread
        thread.start()
        return True

    def _run_sync(self) -> None:
        error_message: str | None = None
        saved_version: VersionInfo | None = None
        try:
            # 代际在网络交互之前读取：同步期间若另一进程替换了当前版本，
            # 提交时会检测到并丢弃本次结果。
            expected_generation = self._store.generation()
            snapshot = fetch_reset_snapshot(self._host, self._port)
            # End of Data 到达时刻以“完整 EOD PDU 解析成功”的时刻为准，
            # 到期 = 该时刻 + expire interval。
            eod_arrived_at = time.time()
            saved_version = self._store.commit_snapshot(
                snapshot,
                expected_generation=expected_generation,
                eod_arrived_at=eod_arrived_at,
            )
        except GenerationConflict as exc:
            error_message = f"版本已被其他进程替换，丢弃本次结果：{exc}"
        except RTRError as exc:
            error_message = f"同步失败，保留当前版本：{exc}"
        except Exception as exc:  # 防御性：任何意外都不得破坏当前版本
            error_message = f"同步异常，保留当前版本：{type(exc).__name__}: {exc}"
        finally:
            success_id = (
                saved_version.version_id if saved_version is not None else None
            )
            self._status.finish(error_message, success_id)
