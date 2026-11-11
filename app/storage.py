"""RPKI 授权的 SQLite 版本化存储。

设计要点：
  * 一个版本（version）对应一次完整成功的 Reset Query 同步，
    授权行与版本行在同一个事务里提交，读者永远只能看到完整的同版数据；
  * WAL 模式 + busy timeout，两个 Web 进程可同时打开同一个数据库文件，
    读写互不阻塞；
  * 同步期间当前版本被别的进程替换时，调用方通过 expected_generation
    检测代际冲突并丢弃本次结果；
  * 旧版本保留在库中（断流/错误时当前版本不动），只是不再被查询引用。
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass

from app.rtr import ROA, Snapshot

SCHEMA = """
CREATE TABLE IF NOT EXISTS versions (
    version_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL,
    serial          INTEGER NOT NULL,
    expire_interval INTEGER NOT NULL,
    synced_at       REAL    NOT NULL,
    expires_at      REAL    NOT NULL,
    roa_count       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS roas (
    version_id    INTEGER NOT NULL REFERENCES versions(version_id),
    asn           INTEGER NOT NULL,
    prefix        TEXT    NOT NULL,
    prefix_length INTEGER NOT NULL,
    max_length    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_roas_version ON roas(version_id);
"""


@dataclass(frozen=True)
class VersionInfo:
    version_id: int
    session_id: int
    serial: int
    expire_interval: int
    synced_at: float
    expires_at: float
    roa_count: int

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at


class StorageError(Exception):
    """存储层错误。"""


class GenerationConflict(StorageError):
    """提交时发现同步期间当前版本已被其他进程替换。"""


class RPKIStore:
    """线程安全的 SQLite 存储封装，每个操作使用独立连接。

    两个 Web 进程各自持有一个 RPKIStore 实例，但打开同一个文件，
    靠 SQLite WAL 实现跨进程并发与持久共享。
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._connect()  # 提前建库/设 WAL，让首个请求更快。

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.db_path,
            timeout=10.0,
            isolation_level=None,  # 显式事务，便于原子提交。
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(SCHEMA)
        return conn

    def current_version(self) -> VersionInfo | None:
        """返回最新版本；从未成功同步过时返回 None。"""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM versions ORDER BY version_id DESC LIMIT 1"
                ).fetchone()
                return _row_to_version(row) if row is not None else None
            finally:
                conn.close()

    def generation(self) -> int:
        """当前版本号即代际标识；无版本时为 0。"""
        version = self.current_version()
        return version.version_id if version is not None else 0

    def commit_snapshot(
        self,
        snapshot: Snapshot,
        *,
        expected_generation: int,
        eod_arrived_at: float,
    ) -> VersionInfo:
        """原子写入一次完整快照。

        ``expected_generation`` 是同步开始时看到的代际。提交前若库中
        当前版本已被其他进程替换（代际不一致），丢弃本次结果。
        到期时刻从 End of Data PDU 到达时刻起按 expire interval 计算。
        """
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT COALESCE(MAX(version_id), 0) AS gen FROM versions"
                ).fetchone()
                current_generation = int(row["gen"])
                if current_generation != expected_generation:
                    raise GenerationConflict(
                        f"同步开始时代际为 {expected_generation}，"
                        f"提交时已为 {current_generation}，丢弃本次结果"
                    )

                expires_at = eod_arrived_at + snapshot.expire_interval
                conn.execute("BEGIN IMMEDIATE")
                try:
                    cursor = conn.execute(
                        "INSERT INTO versions "
                        "(session_id, serial, expire_interval, synced_at, "
                        "expires_at, roa_count) VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            snapshot.session_id,
                            snapshot.serial,
                            snapshot.expire_interval,
                            eod_arrived_at,
                            expires_at,
                            len(snapshot.roas),
                        ),
                    )
                    new_version_id = cursor.lastrowid
                    conn.executemany(
                        "INSERT INTO roas "
                        "(version_id, asn, prefix, prefix_length, max_length) "
                        "VALUES (?, ?, ?, ?, ?)",
                        [
                            (
                                new_version_id,
                                roa.asn,
                                roa.prefix,
                                roa.prefix_length,
                                roa.max_length,
                            )
                            for roa in snapshot.roas
                        ],
                    )
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise
            finally:
                conn.close()

        saved = self.current_version()
        assert saved is not None and saved.version_id == new_version_id
        return saved

    def load_roas(self, version_id: int) -> list[ROA]:
        """读取指定版本的完整授权集合。

        只按完整版本号整体读取，查询永远基于同一份同版数据。
        """
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT asn, prefix, prefix_length, max_length "
                "FROM roas WHERE version_id = ? ORDER BY rowid",
                (version_id,),
            ).fetchall()
            return [
                ROA(
                    asn=int(row["asn"]),
                    prefix=row["prefix"],
                    prefix_length=int(row["prefix_length"]),
                    max_length=int(row["max_length"]),
                    session_id=0,
                )
                for row in rows
            ]
        finally:
            conn.close()


def _row_to_version(row: sqlite3.Row) -> VersionInfo:
    return VersionInfo(
        version_id=int(row["version_id"]),
        session_id=int(row["session_id"]),
        serial=int(row["serial"]),
        expire_interval=int(row["expire_interval"]),
        synced_at=float(row["synced_at"]),
        expires_at=float(row["expires_at"]),
        roa_count=int(row["roa_count"]),
    )
