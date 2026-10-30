"""Offline regression checks for BestCF endpoint parsing and safe fallback semantics."""
import unittest
from bestcf import parse_endpoints


class BestCFParsingTest(unittest.TestCase):
    def test_dedup_and_https_port_filter(self):
        raw = (
            "162.159.198.1:443#KR\n"
            "49.238.238.150:2096#KR\n"
            "220.77.188.107:12386#not-standard-cloudflare-port\n"
            "162.159.198.1:443#duplicate\n"
        )
        self.assertEqual(
            parse_endpoints(raw),
            ["162.159.198.1:443", "49.238.238.150:2096"],
        )

    def test_flattened_source(self):
        raw = "162.159.198.1:443#KR 220.77.188.107:12386#skip 49.238.238.150:2096#KR"
        self.assertEqual(parse_endpoints(raw), ["162.159.198.1:443", "49.238.238.150:2096"])

    def test_reject_invalid_ip_port_and_domain(self):
        raw = "999.1.2.3:443\n1.2.3.4:0\nexample.org:443\n1.2.3.4:65536\n"
        self.assertEqual(parse_endpoints(raw), [])


if __name__ == "__main__":
    unittest.main()
