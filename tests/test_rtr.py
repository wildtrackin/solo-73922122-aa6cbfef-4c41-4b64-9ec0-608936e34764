"""RFC 8210 协议层测试：真实本地 TCP 回环，覆盖分片/粘包/断流/非法 PDU。"""

from __future__ import annotations

import socket
import struct
import threading
import unittest
from socketserver import BaseRequestHandler, ThreadingTCPServer

from app import rtr
from app.rtr import (
    PDU_CACHE_RESET,
    PDU_END_OF_DATA,
    PDU_ERROR_REPORT,
    PDU_IPV4_PREFIX,
    RTRNetworkError,
    RTRProtocolError,
    fetch_reset_snapshot,
)

H = struct.Struct("!BBHI")
IPV4 = struct.Struct("!BBBBI")
EOD = struct.Struct("!IIII")


def cache_response(session: int) -> bytes:
    return H.pack(0, 3, session, 8)


def ipv4_pdu(session: int, asn: int, prefix: str, max_len: int, flags: int = 0) -> bytes:
    network, plen = prefix.split("/")
    body = IPV4.pack(flags, int(plen), max_len, 0, asn) + socket.inet_aton(network)
    return H.pack(0, PDU_IPV4_PREFIX, session, 20) + body


def eod(session: int, serial: int = 10, expire: int = 7200) -> bytes:
    return H.pack(0, PDU_END_OF_DATA, session, 24) + EOD.pack(serial, 3600, 600, expire)


def reset_pdu() -> bytes:
    return H.pack(0, PDU_CACHE_RESET, 0, 8)


def error_pdu() -> bytes:
    return H.pack(0, PDU_ERROR_REPORT, 0, 12) + struct.pack("!I", 2)


class ScriptedHandler(BaseRequestHandler):
    """按 server.script_fn() 返回的字节序列应答，脚本可控发送方式与断流。"""

    def handle(self):
        conn = self.request
        conn.settimeout(5)
        request = conn.recv(8)
        if len(request) != 8:
            return
        server: ScriptedServer = self.server  # type: ignore[assignment]
        server.connected.set()
        try:
            server.script_fn(conn)
        except (ConnectionError, BrokenPipeError, OSError):
            pass


class ScriptedServer(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr):
        self.script_fn = lambda conn: None
        self.connected = threading.Event()
        super().__init__(addr, ScriptedHandler)

    def set_script(self, fn):
        self.script_fn = fn
        self.connected = threading.Event()


def start_server():
    server = ScriptedServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def valid_script(roas, *, chunk=None, session=42):
    def script(conn):
        frames = [cache_response(session)]
        for asn, prefix, max_len in roas:
            frames.append(ipv4_pdu(session, asn, prefix, max_len))
        frames.append(eod(session))
        payload = b"".join(frames)
        if chunk is None:
            conn.sendall(payload)  # 粘包：一次发出所有 PDU
        else:
            for i in range(0, len(payload), chunk):
                conn.sendall(payload[i : i + chunk])  # 分片
    return script


class RTRClientTest(unittest.TestCase):
    def setUp(self):
        self.server, self.thread = start_server()
        self.host, self.port = self.server.server_address

    def tearDown(self):
        self.server.shutdown()

    def fetch(self):
        return fetch_reset_snapshot(self.host, self.port, socket_timeout=5)

    def test_clean_snapshot_fields(self):
        roas = [
            (64500, "198.51.100.0/24", 24),
            (64501, "203.0.113.0/24", 25),
        ]
        self.server.set_script(valid_script(roas))
        snap = self.fetch()
        self.assertEqual(snap.session_id, 42)
        self.assertEqual(snap.serial, 10)
        self.assertEqual(snap.expire_interval, 7200)
        self.assertEqual(len(snap.roas), 2)
        self.assertEqual(snap.roas[0].asn, 64500)
        self.assertEqual(snap.roas[0].prefix, "198.51.100.0/24")
        self.assertEqual(snap.roas[0].max_length, 24)

    def test_fragmented_one_byte_at_a_time(self):
        roas = [(64500, "192.0.2.0/23", 24)]
        self.server.set_script(valid_script(roas, chunk=1))
        snap = self.fetch()
        self.assertEqual(len(snap.roas), 1)
        self.assertEqual(snap.roas[0].prefix, "192.0.2.0/23")

    def test_odd_chunk_sizes(self):
        roas = [
            (64500, "10.0.0.0/8", 16),
            (64501, "172.16.0.0/12", 20),
            (64502, "192.168.0.0/16", 32),
        ]
        for chunk in (3, 7, 13, 64):
            self.server.set_script(valid_script(roas, chunk=chunk))
            snap = self.fetch()
            self.assertEqual(len(snap.roas), 3, f"chunk={chunk} 应正确重组")

    def test_drop_before_eod_fails(self):
        def script(conn):
            conn.sendall(cache_response(7))
            conn.sendall(ipv4_pdu(7, 1, "10.0.0.0/8", 8))
            # 不发 End of Data，直接关闭。
        self.server.set_script(script)
        with self.assertRaises(RTRProtocolError):
            self.fetch()

    def test_drop_mid_pdu_fails(self):
        def script(conn):
            full = cache_response(7) + ipv4_pdu(7, 1, "10.0.0.0/8", 8)
            conn.sendall(full[:-3])  # 砍掉最后 3 字节再关闭。
        self.server.set_script(script)
        with self.assertRaises(RTRProtocolError):
            self.fetch()

    def test_cache_reset_rejected(self):
        def script(conn):
            conn.sendall(reset_pdu())
        self.server.set_script(script)
        with self.assertRaises(RTRProtocolError):
            self.fetch()

    def test_error_pdu_rejected(self):
        def script(conn):
            conn.sendall(error_pdu())
        self.server.set_script(script)
        with self.assertRaises(RTRProtocolError):
            self.fetch()

    def test_session_mismatch_rejected(self):
        def script(conn):
            conn.sendall(cache_response(7))
            conn.sendall(ipv4_pdu(8, 1, "10.0.0.0/8", 8))  # 会话号不一致
            conn.sendall(eod(7))
        self.server.set_script(script)
        with self.assertRaises(RTRProtocolError):
            self.fetch()

    def test_withdrawal_flag_rejected_in_reset(self):
        def script(conn):
            conn.sendall(cache_response(7))
            conn.sendall(ipv4_pdu(7, 1, "10.0.0.0/8", 8, flags=1))
            conn.sendall(eod(7))
        self.server.set_script(script)
        with self.assertRaises(RTRProtocolError):
            self.fetch()

    def test_bad_length_field_rejected(self):
        def script(conn):
            conn.sendall(H.pack(0, 3, 1, 99))  # 声称 99 字节但立刻关闭
        self.server.set_script(script)
        with self.assertRaises(RTRProtocolError):
            self.fetch()

    def test_bad_version_rejected(self):
        def script(conn):
            conn.sendall(H.pack(1, 3, 1, 8))
        self.server.set_script(script)
        with self.assertRaises(RTRProtocolError):
            self.fetch()

    def test_trailing_pdu_after_eod_rejected(self):
        def script(conn):
            payload = (
                cache_response(7)
                + ipv4_pdu(7, 1, "10.0.0.0/8", 8)
                + eod(7)
                + cache_response(7)
            )
            conn.sendall(payload)
        self.server.set_script(script)
        with self.assertRaises(RTRProtocolError):
            self.fetch()

    def test_invalid_prefix_length_rejected(self):
        def script(conn):
            conn.sendall(cache_response(7))
            conn.sendall(
                H.pack(0, PDU_IPV4_PREFIX, 7, 20)
                + IPV4.pack(0, 33, 32, 0, 1)
                + socket.inet_aton("10.0.0.0")
            )
            conn.sendall(eod(7))
        self.server.set_script(script)
        with self.assertRaises(RTRProtocolError):
            self.fetch()

    def test_over_1000_records_rejected(self):
        roas = [(i + 1, "10.0.0.0/8", 32) for i in range(rtr.MAX_IPV4_RECORDS + 1)]
        self.server.set_script(valid_script(roas))
        with self.assertRaises(RTRProtocolError) as ctx:
            self.fetch()
        self.assertIn("1000", str(ctx.exception))

    def test_connection_refused_is_network_error(self):
        with self.assertRaises(RTRNetworkError):
            fetch_reset_snapshot("127.0.0.1", 1, socket_timeout=2)

    def test_prefix_normalized(self):
        # 主机位非零的前缀应被规范化存储。
        self.server.set_script(valid_script([(1, "192.0.2.128/24", 24)]))
        snap = self.fetch()
        self.assertEqual(snap.roas[0].prefix, "192.0.2.0/24")


if __name__ == "__main__":
    unittest.main()
