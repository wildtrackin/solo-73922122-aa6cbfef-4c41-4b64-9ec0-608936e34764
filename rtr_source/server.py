"""本地演示用 RPKI-RTR 源（RFC 8210 v1）。

同时提供两个端口：
  * 8210/tcp：RTR 协议端口，每收到一个 Reset Query 就回送一份全量快照；
  * 8211/tcp：HTTP 控制端口，用于在网页演示中动态切换行为。

可切换的行为（mode）：
  clean        正常回送 Cache Response -> ROA* -> End of Data
  fragment     每个 PDU 拆成 3 字节的小 TCP 段发送（验证分片/粘包处理）
  drop-eod     发完 Cache Response 和 ROA 后在 End of Data 前断开
  drop-reset   只回 Cache Reset PDU 然后断开
  drop-mid     发送部分 ROA 后直接断开
  error        回 Error Report PDU 后断开

可切换的授权集合（dataset）：baseline 与 alternate，切换后序号递增。
"""

from __future__ import annotations

import json
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import BaseRequestHandler, ThreadingTCPServer

PROTOCOL_VERSION = 0
PDU_RESET_QUERY = 2
PDU_CACHE_RESPONSE = 3
PDU_IPV4_PREFIX = 4
PDU_END_OF_DATA = 7
PDU_CACHE_RESET = 8
PDU_ERROR_REPORT = 10

HEADER = struct.Struct("!BBHI")
IPV4_BODY = struct.Struct("!BBBBI")
EOD_BODY = struct.Struct("!IIII")

VALID_MODES = ("clean", "fragment", "drop-eod", "drop-reset", "drop-mid", "error")

# 两套演示授权（asn, prefix, maxLength）。
DATASETS: dict[str, list[tuple[int, str, int]]] = {
    "baseline": [
        (64500, "198.51.100.0/24", 24),
        (64500, "198.51.100.0/24", 26),
        (64501, "203.0.113.0/24", 24),
        (64502, "192.0.2.0/23", 24),
        (64503, "10.10.0.0/16", 20),
    ],
    "alternate": [
        (64510, "198.51.100.0/23", 24),
        (64501, "203.0.113.128/25", 25),
        (64599, "172.16.0.0/12", 16),
    ],
}

DEFAULT_EXPIRE_INTERVAL = 7200
FRAGMENT_CHUNK = 3
FRAGMENT_SLEEP = 0.02


class RTRSourceState:
    def __init__(self, expire_interval: int):
        self._lock = threading.Lock()
        self.mode = "clean"
        self.dataset = "baseline"
        self.session_id = 1234
        self.serial = 1
        self.expire_interval = expire_interval
        self.connection_count = 0

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "mode": self.mode,
                "dataset": self.dataset,
                "session_id": self.session_id,
                "serial": self.serial,
                "expire_interval": self.expire_interval,
                "connection_count": self.connection_count,
                "roa_count": len(DATASETS[self.dataset]),
                "valid_modes": list(VALID_MODES),
                "datasets": list(DATASETS),
            }

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"未知模式：{mode}")
        with self._lock:
            self.mode = mode

    def set_dataset(self, name: str) -> None:
        if name not in DATASETS:
            raise ValueError(f"未知授权集：{name}")
        with self._lock:
            if name != self.dataset:
                self.dataset = name
                self.serial += 1

    def begin_connection(self) -> dict:
        with self._lock:
            self.connection_count += 1
            return {
                "mode": self.mode,
                "dataset": self.dataset,
                "session_id": self.session_id,
                "serial": self.serial,
            }


def _cache_response(session_id: int) -> bytes:
    return HEADER.pack(PROTOCOL_VERSION, PDU_CACHE_RESPONSE, session_id, 8)


def _cache_reset() -> bytes:
    return HEADER.pack(PROTOCOL_VERSION, PDU_CACHE_RESET, 0, 8)


def _error_report() -> bytes:
    # error code 2 = no data available，无附加文本。
    return HEADER.pack(PROTOCOL_VERSION, PDU_ERROR_REPORT, 0, 12) + struct.pack("!I", 2)


def _ipv4_pdu(session_id: int, asn: int, prefix: str, max_length: int) -> bytes:
    network, prefix_length = prefix.split("/")
    prefix_length = int(prefix_length)
    packed = socket.inet_pton(socket.AF_INET, network)
    body = IPV4_BODY.pack(0, prefix_length, max_length, 0, asn) + packed
    return HEADER.pack(PROTOCOL_VERSION, PDU_IPV4_PREFIX, session_id, 20) + body


def _end_of_data(session_id: int, serial: int, expire_interval: int) -> bytes:
    refresh = min(3600, expire_interval // 2)
    retry = min(600, expire_interval // 4)
    body = EOD_BODY.pack(serial, refresh, retry, expire_interval)
    return HEADER.pack(PROTOCOL_VERSION, PDU_END_OF_DATA, session_id, 24) + body


class RTRHandler(BaseRequestHandler):
    def handle(self) -> None:
        state: RTRSourceState = self.server.state  # type: ignore[attr-defined]
        conn = self.request
        conn.settimeout(15)
        try:
            header = self._recv_exact(conn, 8)
        except (ConnectionError, socket.timeout, OSError):
            return
        if header is None or len(header) != 8:
            return
        version, pdu_type, session_id, length = HEADER.unpack(header)
        if version != PROTOCOL_VERSION or pdu_type != PDU_RESET_QUERY or length != 8:
            return

        ctx = state.begin_connection()
        mode = ctx["mode"]
        session = ctx["session_id"]
        serial = ctx["serial"]
        roas = DATASETS[ctx["dataset"]]

        def send(frame: bytes) -> None:
            if mode == "fragment":
                for i in range(0, len(frame), FRAGMENT_CHUNK):
                    conn.sendall(frame[i : i + FRAGMENT_CHUNK])
                    time.sleep(FRAGMENT_SLEEP)
            else:
                conn.sendall(frame)

        try:
            if mode == "drop-reset":
                conn.sendall(_cache_reset())
                time.sleep(0.05)
                return
            if mode == "error":
                conn.sendall(_error_report())
                time.sleep(0.05)
                return

            send(_cache_response(session))

            sent = 0
            for asn, prefix, max_length in roas:
                if mode == "drop-mid" and sent >= max(1, len(roas) // 2):
                    return  # 发送到一半直接断开，模拟断流。
                send(_ipv4_pdu(session, asn, prefix, max_length))
                sent += 1

            if mode == "drop-eod":
                time.sleep(0.05)
                return  # End of Data 前断开，客户端必须整轮判失败。

            send(_end_of_data(session, serial, state.expire_interval))
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        except (ConnectionError, BrokenPipeError, OSError):
            return

    @staticmethod
    def _recv_exact(conn: socket.socket, size: int) -> bytes | None:
        buffer = bytearray()
        while len(buffer) < size:
            chunk = conn.recv(size - len(buffer))
            if not chunk:
                return None
            buffer.extend(chunk)
        return bytes(buffer)


class ControlHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # 安静一点，避免刷屏。
        return

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/state", "/state/"):
            self._send_json(200, self.server.state.snapshot())  # type: ignore[attr-defined]
        elif self.path in ("/datasets", "/datasets/"):
            self._send_json(200, {"datasets": list(DATASETS)})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        state: RTRSourceState = self.server.state  # type: ignore[attr-defined]
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": f"请求体不是合法 JSON：{exc}"})
            return

        try:
            if self.path in ("/mode", "/mode/"):
                state.set_mode(str(body.get("mode", "")))
            elif self.path in ("/dataset", "/dataset/"):
                state.set_dataset(str(body.get("dataset", "")))
            else:
                self._send_json(404, {"error": "not found"})
                return
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        self._send_json(200, state.snapshot())


class RTRServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, state: RTRSourceState):
        self.state = state
        super().__init__(addr, handler)


class ControlServer(HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, state: RTRSourceState):
        self.state = state
        super().__init__(addr, handler)


def main() -> None:
    import os

    rtr_port = int(os.environ.get("RTR_SERVER_PORT", "8210"))
    control_port = int(os.environ.get("CONTROL_PORT", "8211"))
    expire = int(os.environ.get("EXPIRE_INTERVAL", str(DEFAULT_EXPIRE_INTERVAL)))

    state = RTRSourceState(expire_interval=expire)
    rtr_server = RTRServer(("0.0.0.0", rtr_port), RTRHandler, state)
    control_server = ControlServer(("0.0.0.0", control_port), ControlHandler, state)

    threading.Thread(target=rtr_server.serve_forever, name="rtr-tcp", daemon=True).start()
    threading.Thread(
        target=control_server.serve_forever, name="rtr-control", daemon=True
    ).start()
    print(
        f"RTR source listening on :{rtr_port} (RTR) and :{control_port} (control)",
        flush=True,
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        rtr_server.shutdown()
        control_server.shutdown()


if __name__ == "__main__":
    main()
