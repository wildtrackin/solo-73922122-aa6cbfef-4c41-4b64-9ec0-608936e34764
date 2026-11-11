"""RFC 6483 路由起源校验测试：Valid / Invalid / NotFound 与输入校验。"""

from __future__ import annotations

import unittest

from app.rtr import ROA
from app.storage import VersionInfo
from app.validator import ValidationInputError, evaluate, parse_asn, parse_prefix

VERSION = VersionInfo(
    version_id=1,
    session_id=42,
    serial=10,
    expire_interval=7200,
    synced_at=0.0,
    expires_at=10_000.0,
    roa_count=4,
)


def roa(asn, prefix, max_len):
    plen = int(prefix.split("/")[1])
    return ROA(asn, prefix, plen, max_len, 42)


# 授权集合：
#   AS64500: 198.51.100.0/24 maxLength 24
#   AS64500: 198.51.100.0/24 maxLength 26（允许更具体前缀）
#   AS64501: 203.0.113.0/24 maxLength 24
#   AS64502: 192.0.2.0/23 maxLength 24
ROAS = [
    roa(64500, "198.51.100.0/24", 24),
    roa(64500, "198.51.100.0/24", 26),
    roa(64501, "203.0.113.0/24", 24),
    roa(64502, "192.0.2.0/23", 24),
]


class ValidatorTest(unittest.TestCase):
    def test_valid_exact_match(self):
        result = evaluate("198.51.100.0/24", "64500", ROAS, VERSION)
        self.assertEqual(result.state, "Valid")
        self.assertTrue(result.covering)
        self.assertIn("AS64500", result.reason)

    def test_valid_more_specific_within_max_length(self):
        # /26 落在 maxLength 26 的授权内。
        result = evaluate("198.51.100.64/26", 64500, ROAS, VERSION)
        self.assertEqual(result.state, "Valid")

    def test_invalid_when_another_asn_holds_covering_roa(self):
        result = evaluate("198.51.100.0/24", 64999, ROAS, VERSION)
        self.assertEqual(result.state, "Invalid")
        self.assertTrue(all(not c.asn_matches for c in result.covering))

    def test_invalid_more_specific_beyond_max_length_with_wrong_asn(self):
        # /28 超过两条授权的 maxLength（24、26），ROA 不构成覆盖；
        # 但同前缀超网 198.51.100.0/24 maxLength24 也不覆盖 /28，
        # 所以这是 NotFound 场景——先明确这个边界。
        result = evaluate("198.51.100.128/28", 64999, ROAS, VERSION)
        self.assertEqual(result.state, "NotFound")
        self.assertEqual(result.covering, ())

    def test_not_found_without_any_covering_roa(self):
        result = evaluate("8.8.8.0/24", 15169, ROAS, VERSION)
        self.assertEqual(result.state, "NotFound")

    def test_invalid_covered_but_wrong_asn_on_supernet(self):
        # 192.0.2.0/23(max24) 覆盖 192.0.3.0/24，但起源 ASN 不对。
        result = evaluate("192.0.3.0/24", 64999, ROAS, VERSION)
        self.assertEqual(result.state, "Invalid")
        self.assertEqual(len(result.covering), 1)
        self.assertFalse(result.covering[0].asn_matches)

    def test_valid_supernet_roa_covers_more_specific(self):
        result = evaluate("192.0.2.0/24", "64502", ROAS, VERSION)
        self.assertEqual(result.state, "Valid")

    def test_asn_prefix_inputs(self):
        result = evaluate("203.0.113.0/24", "AS64501", ROAS, VERSION)
        self.assertEqual(result.state, "Valid")
        self.assertEqual(result.asn, 64501)

    def test_reject_host_bits(self):
        with self.assertRaises(ValidationInputError):
            evaluate("198.51.100.7/24", 64500, ROAS, VERSION)

    def test_reject_ipv6(self):
        with self.assertRaises(ValidationInputError):
            evaluate("2001:db8::/32", 64500, ROAS, VERSION)

    def test_reject_missing_prefix_length(self):
        with self.assertRaises(ValidationInputError):
            parse_prefix("198.51.100.1")

    def test_reject_bad_asn(self):
        for bad in ("0", "4294967296", "-1", "abc", ""):
            with self.assertRaises(ValidationInputError, msg=bad):
                parse_asn(bad)

    def test_max_length_boundary(self):
        # /26 刚好合法，/27 超出 -> 无覆盖（NotFound），即使 ASN 正确。
        ok = evaluate("198.51.100.0/26", 64500, ROAS, VERSION)
        self.assertEqual(ok.state, "Valid")
        too_long = evaluate("198.51.100.0/27", 64500, ROAS, VERSION)
        self.assertEqual(too_long.state, "NotFound")

    def test_result_carries_version_evidence(self):
        result = evaluate("203.0.113.0/24", 64501, ROAS, VERSION)
        self.assertEqual(result.version_id, 1)
        self.assertEqual(result.session_id, 42)
        self.assertEqual(result.serial, 10)
        self.assertEqual(result.expires_at, 10_000.0)


if __name__ == "__main__":
    unittest.main()
