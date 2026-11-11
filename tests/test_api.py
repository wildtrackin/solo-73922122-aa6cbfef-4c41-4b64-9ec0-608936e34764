"""API 端到端测试：通过 ASGI 调用 FastAPI 应用，覆盖完整核对流程。"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.storage import RPKIStore
from rtr_source.server import RTRHandler, RTRServer, RTRSourceState

try:
    import fastapi  # noqa: F401
    _HAS_FASTAPI = True
except ModuleNotFoundError:  # 本地最小环境没有 Web 依赖时跳过
    _HAS_FASTAPI = False


class ASGIClient:
    """最小 ASGI 测试客户端，避免引入 httpx 依赖。"""

    def __init__(self, app):
        self.app = app

    def request(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        async def run():
            payload = json.dumps(body).encode() if body is not None else b""
            messages: list[dict] = []

            async def receive():
                return {"type": "http.request", "body": payload, "more_body": False}

            async def send(message):
                messages.append(message)

            scope = {
                "type": "http",
                "http_version": "1.1",
                "method": method,
                "scheme": "http",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode()),
                ],
                "client": ("127.0.0.1", 12345),
                "server": ("testserver", 80),
            }
            await self.app(scope, receive, send)
            start = messages[0]
            chunks = [
                m["body"] for m in messages if m["type"] == "http.response.body"
            ]
            data = json.loads(b"".join(chunks).decode()) if chunks and b"".join(chunks) else {}
            return start["status"], data

        return asyncio.run(run())


def wait_until(predicate, timeout=10.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


@unittest.skipUnless(_HAS_FASTAPI, "环境未安装 fastapi，跳过 API 端到端测试")
class APITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["RTR_DB_PATH"] = str(Path(cls.tmp.name) / "api.db")

        cls.rtr_state = RTRSourceState(7200)
        cls.rtr_server = RTRServer(("127.0.0.1", 0), RTRHandler, cls.rtr_state)
        cls.rtr_thread = threading.Thread(
            target=cls.rtr_server.serve_forever, daemon=True
        )
        cls.rtr_thread.start()
        os.environ["RTR_HOST"] = "127.0.0.1"
        os.environ["RTR_PORT"] = str(cls.rtr_server.server_address[1])

        # 重新加载模块，让环境变量生效。
        import importlib

        import app.main as main_module
        importlib.reload(main_module)
        cls.main_module = main_module
        cls.client = ASGIClient(main_module.app)

    @classmethod
    def tearDownClass(cls):
        cls.rtr_server.shutdown()
        cls.tmp.cleanup()

    def test_01_validate_before_sync_is_unavailable(self):
        status, data = self.client.request("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertFalse(data["query_available"])
        self.assertIn("尚未同步", data["message"])

        status, data = self.client.request(
            "POST", "/api/validate", {"prefix": "198.51.100.0/24", "asn": "64500"}
        )
        self.assertEqual(status, 200)
        self.assertFalse(data["available"])
        self.assertEqual(data["state"], "Unavailable")

    def test_02_sync_and_validate_all_states(self):
        status, data = self.client.request("POST", "/api/sync")
        self.assertEqual(status, 200)
        self.assertTrue(data["started"])

        # 同步中再次触发 -> 409。
        status, data = self.client.request("POST", "/api/sync")
        self.assertEqual(status, 409)

        self.assertTrue(
            wait_until(
                lambda: not self.main_module.sync_manager.is_syncing(), timeout=15
            )
        )

        status, data = self.client.request("GET", "/api/status")
        self.assertTrue(data["query_available"])
        self.assertEqual(data["version"]["roa_count"], 5)

        # Valid：精确匹配。
        status, data = self.client.request(
            "POST", "/api/validate", {"prefix": "198.51.100.0/24", "asn": "64500"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["state"], "Valid")
        self.assertTrue(data["covering"])
        self.assertEqual(data["version"]["session_id"], 1234)

        # Invalid：有覆盖授权但 ASN 不匹配。
        status, data = self.client.request(
            "POST", "/api/validate", {"prefix": "198.51.100.0/24", "asn": "64999"}
        )
        self.assertEqual(data["state"], "Invalid")

        # NotFound：无任何覆盖。
        status, data = self.client.request(
            "POST", "/api/validate", {"prefix": "8.8.8.0/24", "asn": "15169"}
        )
        self.assertEqual(data["state"], "NotFound")

    def test_03_bad_input_returns_400(self):
        status, data = self.client.request(
            "POST", "/api/validate", {"prefix": "not-a-cidr", "asn": "1"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(data["detail"]["code"], "invalid_input")

        status, data = self.client.request(
            "POST", "/api/validate", {"prefix": "10.0.0.0/8", "asn": "0"}
        )
        self.assertEqual(status, 400)

    def test_04_expired_version_blocks_query(self):
        # 手动把到期时间改成过去，模拟过期版本。
        store: RPKIStore = self.main_module.store
        version = store.current_version()
        conn = store._connect()
        try:
            conn.execute(
                "UPDATE versions SET expires_at = ? WHERE version_id = ?",
                (time.time() - 10, version.version_id),
            )
        finally:
            conn.close()

        status, data = self.client.request(
            "POST", "/api/validate", {"prefix": "198.51.100.0/24", "asn": "64500"}
        )
        self.assertEqual(status, 200)
        self.assertFalse(data["available"])
        self.assertIn("过期", data["message"])


if __name__ == "__main__":
    unittest.main()
