import unittest
from app.parsers.fingerprint import SourceFingerprinter


class TestSourceFingerprinter(unittest.TestCase):
    def setUp(self):
        self.fingerprinter = SourceFingerprinter()

    def test_cisco_fingerprint(self):
        payload = "2026-09-06T10:30:00Z R1 %SYS-5-CONFIG_I: Configured from console"
        res = self.fingerprinter.fingerprint(payload)
        self.assertEqual(res["vendor"], "Cisco")
        self.assertEqual(res["product"], "IOS Router")
        self.assertGreater(res["confidence"], 0.9)

    def test_acmeguard_fingerprint(self):
        payload = "2026-09-06T10:00:00Z FW01 ALLOW SRC=10.10.10.25 DST=172.16.1.20 SP=49152 DP=443 PROTO=TCP RULE=ALLOW_WEB"
        res = self.fingerprinter.fingerprint(payload)
        self.assertEqual(res["vendor"], "AcmeGuard")
        self.assertEqual(res["product"], "Firewall")

    def test_openvpn_fingerprint(self):
        payload = "2026-09-06T10:20:00Z alice CONNECTED SRC=203.0.113.10 VPN_IP=10.8.0.5"
        res = self.fingerprinter.fingerprint(payload)
        self.assertEqual(res["vendor"], "OpenVPN")
        self.assertEqual(res["product"], "VPN Gateway")

    def test_unknown_log_does_not_hallucinate(self):
        payload = "foo=1 bar=2 baz=3"
        res = self.fingerprinter.fingerprint(payload)
        self.assertIsNone(res["vendor"])
        self.assertIsNone(res["product"])
        self.assertLess(res["confidence"], 0.3)


if __name__ == "__main__":
    unittest.main()
