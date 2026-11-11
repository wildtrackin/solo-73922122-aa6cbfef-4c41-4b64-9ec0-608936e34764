"""RFC 6483 路由起源校验（Route Origin Validation）。

判定规则（对一条待发布的 IPv4 前缀 + 起源 ASN）：
  * 找出所有覆盖该前缀的 ROA：ROA 前缀是待验证前缀的超网，且
    ROA 的 maxLength 不小于待验证前缀长度（maxLength 更小的 ROA
    无法“覆盖”该前缀，RFC 6483 §2.2）；
  * 任一覆盖授权同时满足 ASN 相等且 maxLength 允许该前缀长度 -> Valid；
  * 存在覆盖授权但没有任何一条匹配 ASN/maxLength -> Invalid；
  * 不存在任何覆盖授权 -> NotFound。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from app.rtr import ROA
from app.storage import VersionInfo


class ValidationInputError(ValueError):
    """用户输入的 CIDR 或 ASN 不合法。"""


@dataclass(frozen=True)
class MatchedROA:
    asn: int
    prefix: str
    prefix_length: int
    max_length: int
    asn_matches: bool
    length_allowed: bool


@dataclass(frozen=True)
class ValidationResult:
    state: str  # "Valid" | "Invalid" | "NotFound"
    prefix: str
    asn: int
    covering: tuple[MatchedROA, ...]
    version_id: int
    session_id: int
    serial: int
    expires_at: float

    @property
    def reason(self) -> str:
        if self.state == "Valid":
            matched = next(
                r for r in self.covering if r.asn_matches and r.length_allowed
            )
            return (
                f"授权 {matched.prefix} AS{matched.asn} "
                f"maxLength {matched.max_length} 覆盖该前缀且 ASN 匹配"
            )
        if self.state == "Invalid":
            detail = "；".join(
                f"{r.prefix} AS{r.asn}（maxLength {r.max_length}，"
                f"ASN {'匹配' if r.asn_matches else '不匹配'}）"
                for r in self.covering
            )
            return f"存在覆盖授权但 ASN 均不匹配：{detail}"
        return "当前授权集合中没有任何 ROA 覆盖该前缀"


def parse_prefix(raw: str) -> ipaddress.IPv4Network:
    """解析严格形式的 IPv4 CIDR（必须带前缀长度、不允许主机位）。"""
    text = (raw or "").strip()
    if not text:
        raise ValidationInputError("请输入 IPv4 CIDR，例如 198.51.100.0/24")
    if "/" not in text:
        raise ValidationInputError("必须带前缀长度，例如 198.51.100.0/24")
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise ValidationInputError(f"IPv4 CIDR 不合法：{exc}") from exc
    if network.version != 4:
        raise ValidationInputError("本核对页仅支持 IPv4 前缀")
    if network.is_multicast:
        raise ValidationInputError("不接受组播地址作为待发布前缀")
    return network


def parse_asn(raw: str | int) -> int:
    if isinstance(raw, int):
        value = raw
    else:
        text = (raw or "").strip().upper().replace("AS", "")
        if not text:
            raise ValidationInputError("请输入起源 ASN，例如 64500")
        try:
            value = int(text)
        except ValueError as exc:
            raise ValidationInputError("ASN 必须是 1-4294967295 的整数") from exc
    if not (1 <= value <= 0xFFFFFFFF):
        raise ValidationInputError("ASN 必须在 1-4294967295 之间（AS0 不接受）")
    return value


def evaluate(
    prefix_raw: str,
    asn_raw: str | int,
    roas: list[ROA],
    version: VersionInfo,
) -> ValidationResult:
    """基于一个完整版本的授权集合执行路由起源校验。"""
    network = parse_prefix(prefix_raw)
    asn = parse_asn(asn_raw)

    covering: list[MatchedROA] = []
    valid = False
    for roa in roas:
        roa_network = ipaddress.ip_network(roa.prefix)
        # 覆盖 = ROA 前缀是超网，且 maxLength 容纳待验证前缀长度。
        if roa_network.version != 4:
            continue
        if roa_network.supernet_of(network) and roa.max_length >= network.prefixlen:
            asn_matches = roa.asn == asn
            length_allowed = roa.max_length >= network.prefixlen
            covering.append(
                MatchedROA(
                    asn=roa.asn,
                    prefix=roa.prefix,
                    prefix_length=roa.prefix_length,
                    max_length=roa.max_length,
                    asn_matches=asn_matches,
                    length_allowed=length_allowed,
                )
            )
            if asn_matches and length_allowed:
                valid = True

    if valid:
        state = "Valid"
    elif covering:
        state = "Invalid"
    else:
        state = "NotFound"

    return ValidationResult(
        state=state,
        prefix=str(network),
        asn=asn,
        covering=tuple(covering),
        version_id=version.version_id,
        session_id=version.session_id,
        serial=version.serial,
        expires_at=version.expires_at,
    )
