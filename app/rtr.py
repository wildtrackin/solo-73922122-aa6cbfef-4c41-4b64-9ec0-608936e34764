"""RFC 8210 RPKI-RTR 客户端协议层。

只实现本项目需要的最小子集：
  * 发送 v1 Reset Query，请求全量快照；
  * 按每个 PDU 头部的 length 字段读取，天然兼容 TCP 分片与粘包；
  * 校验 Cache Response -> (IPv4 Prefix PDU)* -> End of Data 的完整会话；
  * 只接受 IPv4 授权，单次最多 MAX_IPV4_RECORDS 条。

任何协议层面的不合法（版本、长度、会话号、序号、PDU 类型、字段范围等）
都抛出 :class:`RTRProtocolError`，由调用方决定保留旧版本数据。
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass

PROTOCOL_VERSION = 0

PDU_SERIAL_NOTIFY = 0
PDU_SERIAL_QUERY = 1
PDU_RESET_QUERY = 2
PDU_CACHE_RESPONSE = 3
PDU_IPV4_PREFIX = 4
PDU_IPV6_PREFIX = 6
PDU_END_OF_DATA = 7
PDU_CACHE_RESET = 8
PDU_ERROR_REPORT = 10

# 本系统的硬性上限：一次全量同步最多 1000 条 IPv4 授权。
MAX_IPV4_RECORDS = 1000

# 单次 socket 读操作的最长等待（秒）。整个同步由调用方负责总超时策略，
# 这里保证任何一次 recv 都不会无限挂起，从而不阻塞查询线程之外的资源。
DEFAULT_SOCKET_TIMEOUT = 15.0

# RFC 8210 公共头部：version(u8) type(u8) session-id(u16) length(u32)，共 8 字节。
_PDU_HEADER = struct.Struct("!BBHI")
_CACHE_RESPONSE_BODY = struct.Struct("!HH")  # 2 字节保留 + 4 字节保留
_IPV4_PREFIX_BODY = struct.Struct("!BBBBI")  # flags, prefix-len, max-len, zero, ASN
_END_OF_DATA_BODY = struct.Struct("!IIII")  # serial, 4*interval, refresh, retry, expire
_ERROR_BODY_MIN = struct.Struct("!I")  # error PDU 至少带一个 4 字节 error code


class RTRError(Exception):
    """RTR 同步相关错误的基类。"""


class RTRProtocolError(RTRError):
    """对端行为不符合 RFC 8210 / 本系统约束。"""


class RTRNetworkError(RTRError):
    """连接、读写字节流层面的失败（断流、超时、拒绝连接等）。"""


@dataclass(frozen=True)
class ROA:
    """一条 IPv4 路由授权（IPv4 Prefix PDU 的有效载荷）。"""

    asn: int
    prefix: str  # 规范形式的 IPv4 前缀，例如 198.51.100.0/24
    prefix_length: int
    max_length: int
    session_id: int


@dataclass(frozen=True)
class Snapshot:
    """一次完整 Reset Query 拿到的全量快照。"""

    session_id: int
    serial: int
    expire_interval: int  # End of Data 中的 expire interval（秒）
    roas: tuple[ROA, ...]


class _PDUReader:
    """基于 length 字段的 PDU 帧读取器。

    TCP 是无边界字节流：一次 recv 可能只拿到半个 PDU（分片），
    也可能一次拿到多个 PDU（粘包）。这里先缓冲再按头部 length 切帧，
    两种情况都能正确处理。
    """

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buffer = bytearray()
        self._eof = False

    def _fill(self, needed: int) -> None:
        """确保缓冲区至少有 needed 字节。

        缓冲里已有完整数据时直接返回（处理粘包）；对端在数据凑齐前
        关闭则按协议错误抛出（处理分片传输中途断流）。
        """
        while len(self._buffer) < needed:
            try:
                chunk = self._sock.recv(4096)
            except (socket.timeout, TimeoutError) as exc:
                raise RTRNetworkError("等待 RTR PDU 超时") from exc
            except OSError as exc:
                raise RTRNetworkError(f"读取 RTR 字节流失败：{exc}") from exc
            if not chunk:
                self._eof = True
                if self._buffer:
                    raise RTRProtocolError(
                        f"连接在 PDU 完整到达前关闭：需要 {needed} 字节，"
                        f"仅剩 {len(self._buffer)} 字节"
                    )
                return
            self._buffer.extend(chunk)

    def read_pdu(self) -> tuple[int, int, int, bytes] | None:
        """读取一个完整 PDU，返回 (pdu_type, session_id, length, 完整 PDU 字节)。

        连接正常关闭且缓冲已耗尽时返回 None。
        """
        if self._eof and not self._buffer:
            return None
        self._fill(_PDU_HEADER.size)
        if not self._buffer:
            return None
        version, pdu_type, session_id, length = _PDU_HEADER.unpack(
            bytes(self._buffer[: _PDU_HEADER.size])
        )
        if version != PROTOCOL_VERSION:
            raise RTRProtocolError(f"不支持的 RTR 协议版本：{version}")
        # length 包含 8 字节头部；RFC 8210 定义的 PDU 最小就是 8 字节。
        if length < _PDU_HEADER.size or length > 0xFFFF:
            raise RTRProtocolError(f"PDU 长度字段非法：{length}")

        self._fill(length)
        frame = bytes(self._buffer[:length])
        del self._buffer[:length]
        return pdu_type, session_id, length, frame


def _build_reset_query() -> bytes:
    # Reset Query PDU：version=0, type=2, session-id=0, length=8
    return _PDU_HEADER.pack(PROTOCOL_VERSION, PDU_RESET_QUERY, 0, 8)


def _parse_error_pdu(frame: bytes) -> str:
    if len(frame) < _PDU_HEADER.size + _ERROR_BODY_MIN.size:
        return "对端发送 Error Report PDU（内容不完整）"
    (error_code,) = _ERROR_BODY_MIN.unpack(
        frame[_PDU_HEADER.size : _PDU_HEADER.size + _ERROR_BODY_MIN.size]
    )
    return f"对端发送 Error Report PDU，错误码 {error_code}"


def fetch_reset_snapshot(
    host: str,
    port: int,
    *,
    socket_timeout: float = DEFAULT_SOCKET_TIMEOUT,
) -> Snapshot:
    """连接 RTR 缓存，发 Reset Query，取一份完整的全量 IPv4 快照。

    只有从 Cache Response 到同会话 End of Data 的所有 PDU 全部合法，
    才返回 Snapshot；任何异常都会向上抛出，旧版本数据由存储层保留。
    """

    try:
        sock = socket.create_connection((host, port), timeout=socket_timeout)
    except OSError as exc:
        raise RTRNetworkError(f"无法连接 RTR 源 {host}:{port}：{exc}") from exc

    roas: list[ROA] = []
    try:
        sock.settimeout(socket_timeout)
        try:
            sock.sendall(_build_reset_query())
        except OSError as exc:
            raise RTRNetworkError(f"发送 Reset Query 失败：{exc}") from exc

        reader = _PDUReader(sock)

        # 1. 必须以 Cache Response 开场。
        first = reader.read_pdu()
        if first is None:
            raise RTRProtocolError("连接在 Cache Response 到达前关闭")
        pdu_type, session_id, length, frame = first
        if pdu_type != PDU_CACHE_RESPONSE:
            raise RTRProtocolError(
                f"Reset Query 后首个 PDU 应为 Cache Response(3)，实际为 {pdu_type}"
            )
        if length != 8:
            raise RTRProtocolError(f"Cache Response 长度应为 8，实际为 {length}")
        cache_session = session_id

        serial: int | None = None
        expire_interval: int | None = None

        # 2. 中间是任意个 IPv4 Prefix PDU，以 End of Data 收尾。
        while True:
            pdu = reader.read_pdu()
            if pdu is None:
                raise RTRProtocolError("连接在 End of Data 到达前关闭")
            pdu_type, pdu_session, length, frame = pdu

            if pdu_type == PDU_END_OF_DATA:
                if length != 24:
                    raise RTRProtocolError(
                        f"End of Data 长度应为 24，实际为 {length}"
                    )
                if pdu_session != cache_session:
                    raise RTRProtocolError(
                        f"End of Data 会话号 {pdu_session} 与 Cache Response "
                        f"会话号 {cache_session} 不一致"
                    )
                serial, refresh, retry, expire = _END_OF_DATA_BODY.unpack(
                    frame[8:24]
                )
                if refresh == 0 or retry == 0 or expire == 0:
                    raise RTRProtocolError(
                        "End of Data 的 refresh/retry/expire interval 不能为 0"
                    )
                if not (refresh <= expire and retry <= expire):
                    raise RTRProtocolError(
                        "End of Data 计时字段不满足 refresh/retry <= expire"
                    )
                expire_interval = expire
                break

            if pdu_type == PDU_CACHE_RESET:
                # Reset Query 模式下对端不应回 Cache Reset；按协议错误处理。
                raise RTRProtocolError(
                    "全量重置流程中收到 Cache Reset PDU，无法取得授权数据"
                )
            if pdu_type == PDU_ERROR_REPORT:
                raise RTRProtocolError(_parse_error_pdu(frame))
            if pdu_type == PDU_IPV6_PREFIX:
                # 本系统只处理 IPv4 授权；收到 IPv6 属于契约外数据，
                # 整轮同步判失败，避免悄悄丢失授权覆盖面。
                raise RTRProtocolError("本系统仅支持 IPv4 授权，收到 IPv6 Prefix PDU")
            if pdu_type != PDU_IPV4_PREFIX:
                raise RTRProtocolError(
                    f"Cache Response 与 End of Data 之间出现非法 PDU 类型 {pdu_type}"
                )

            if length != 20:
                raise RTRProtocolError(
                    f"IPv4 Prefix PDU 长度应为 20，实际为 {length}"
                )
            if pdu_session != cache_session:
                raise RTRProtocolError(
                    f"IPv4 Prefix PDU 会话号 {pdu_session} 与 Cache Response "
                    f"会话号 {cache_session} 不一致"
                )

            flags, prefix_len, max_len, _zero, asn = _IPV4_PREFIX_BODY.unpack(
                frame[8:16]
            )
            if flags == 1:
                # 全量快照中不允许出现撤回 PDU（RFC 8210 §5.54）。
                raise RTRProtocolError("全量快照中出现带 Withdrawal 标记的 PDU")
            if flags not in (0, 1):
                raise RTRProtocolError(f"IPv4 Prefix PDU flags 非法：{flags}")
            if not (0 <= prefix_len <= 32 and prefix_len <= max_len <= 32):
                raise RTRProtocolError(
                    f"前缀长度字段非法：prefix-length={prefix_len}, "
                    f"max-length={max_len}"
                )
            if not (0 < asn <= 0xFFFFFFFF):
                raise RTRProtocolError(f"ASN 字段非法：{asn}")

            if len(roas) >= MAX_IPV4_RECORDS:
                raise RTRProtocolError(
                    f"IPv4 授权数量超过上限 {MAX_IPV4_RECORDS} 条"
                )

            prefix_bytes = frame[16:20]
            prefix = socket.inet_ntop(socket.AF_INET, prefix_bytes)
            # 忽略主机位，按前缀长度规范化，保证存储与查询口径一致。
            network = str(
                ipaddress.ip_network(f"{prefix}/{prefix_len}", strict=False)
            )
            roas.append(
                ROA(
                    asn=asn,
                    prefix=network,
                    prefix_length=prefix_len,
                    max_length=max_len,
                    session_id=cache_session,
                )
            )

        # 3. End of Data 之后对端应关闭连接；若还有 trailing PDU 也判异常。
        extra = reader.read_pdu()
        if extra is not None:
            raise RTRProtocolError("End of Data 之后出现多余 PDU")

        return Snapshot(
            session_id=cache_session,
            serial=serial,
            expire_interval=expire_interval,
            roas=tuple(roas),
        )
    finally:
        try:
            sock.close()
        except OSError:
            pass
