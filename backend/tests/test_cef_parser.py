import unittest
from pathlib import Path

from app.parsers.cef import CEFParser
from app.processing.processor import ULPFProcessor


class TestCEFParser(unittest.TestCase):

    def setUp(self):
        self.parser = CEFParser()
        mapping_dir = Path(__file__).resolve().parent.parent / "app" / "mapping" / "definitions"
        self.processor = ULPFProcessor(str(mapping_dir))

    def test_1_acmeguard_vpn_login(self):
        """
        TEST 1:
        CEF:0|AcmeGuard|Perimeter Firewall|8.4.1|1001|VPN User Login|5|rt=Sep 07 2026 10:25:00 UTC src=192.0.2.70 suser=analyst act=login outcome=success msg=Remote access established

        Expected:
        rt = "Sep 07 2026 10:25:00 UTC"
        msg = "Remote access established"
        user.name = "analyst"
        event.action = "login"
        event.outcome = "success"
        event.type = "authentication"
        """
        raw = (
            "CEF:0|AcmeGuard|Perimeter Firewall|8.4.1|1001|VPN User Login|5|"
            "rt=Sep 07 2026 10:25:00 UTC src=192.0.2.70 suser=analyst act=login outcome=success msg=Remote access established"
        )

        # 1. Parser verification
        self.assertTrue(self.parser.can_parse(raw))
        parsed = self.parser.parse(raw)
        fields = parsed.fields

        self.assertEqual(fields.get("rt"), "Sep 07 2026 10:25:00 UTC")
        self.assertEqual(fields.get("src"), "192.0.2.70")
        self.assertEqual(fields.get("suser"), "analyst")
        self.assertEqual(fields.get("act"), "login")
        self.assertEqual(fields.get("outcome"), "success")
        self.assertEqual(fields.get("msg"), "Remote access established")
        self.assertEqual(fields.get("name"), "VPN User Login")
        self.assertEqual(fields.get("signature_id"), "1001")
        self.assertEqual(fields.get("device_version"), "8.4.1")

        # 2. Canonical Semantic Normalization verification
        result = self.processor.process(raw)
        self.assertTrue(result["processing"]["valid"])

        event = result["event"]
        user = result["user"]
        source = result["source"]
        observer = result["observer"]
        security = result["security"]

        # Exact user requirements
        self.assertEqual(user.get("name"), "analyst")
        self.assertNotEqual(user.get("name"), "VPN User Login")
        self.assertEqual(event.get("action"), "login")
        self.assertEqual(event.get("outcome"), "success")
        self.assertEqual(event.get("type"), "authentication")
        self.assertEqual(event.get("category"), "authentication")
        self.assertEqual(event.get("severity"), 5)

        # Header metadata assertions
        self.assertEqual(source.get("ip"), "192.0.2.70")
        self.assertEqual(observer.get("vendor"), "AcmeGuard")
        self.assertEqual(observer.get("product"), "Perimeter Firewall")
        self.assertEqual(observer.get("version"), "8.4.1")
        self.assertEqual(security.get("signature"), "1001")

        # Source fields preservation in extensions
        source_fields = result.get("extensions", {}).get("source_fields", {})
        self.assertEqual(source_fields.get("rt"), "Sep 07 2026 10:25:00 UTC")
        self.assertEqual(source_fields.get("msg"), "Remote access established")

    def test_2_multiple_fields_with_spaces(self):
        """
        TEST 2:
        CEF event with multiple fields whose values contain spaces.
        """
        raw = (
            "CEF:0|SecurityCorp|NextGen Guard|3.2.0|AUTH_02|Session Opened|3|"
            "src=10.0.0.15 msg=Authenticated user session initiated via corporate portal "
            "cs1=Security Operations Center cs2=East Coast Primary Cluster "
            "suser=security_analyst act=user session grant outcome=success"
        )
        parsed = self.parser.parse(raw)
        fields = parsed.fields

        self.assertEqual(fields.get("src"), "10.0.0.15")
        self.assertEqual(fields.get("msg"), "Authenticated user session initiated via corporate portal")
        self.assertEqual(fields.get("cs1"), "Security Operations Center")
        self.assertEqual(fields.get("cs2"), "East Coast Primary Cluster")
        self.assertEqual(fields.get("suser"), "security_analyst")
        self.assertEqual(fields.get("act"), "user session grant")
        self.assertEqual(fields.get("outcome"), "success")

        result = self.processor.process(raw)
        self.assertEqual(result["user"]["name"], "security_analyst")
        self.assertEqual(result["event"]["outcome"], "success")

    def test_3_escaped_characters(self):
        """
        TEST 3:
        CEF event with escaped characters.
        """
        raw = (
            r"CEF:0|Vendor\|Corp|Proxy\\Gateway|2.1|HTTP_GET|HTTP Access Request|4|"
            r"src=172.16.0.4 msg=Host\=server1 failed with error\\code\ndetails "
            r"suser=admin\\corp act=connect\=established outcome=success"
        )
        parsed = self.parser.parse(raw)
        fields = parsed.fields

        # Check unescaped header fields
        self.assertEqual(parsed.vendor, "Vendor|Corp")
        self.assertEqual(parsed.product, "Proxy\\Gateway")

        # Check unescaped extension values
        self.assertEqual(fields.get("src"), "172.16.0.4")
        self.assertEqual(fields.get("msg"), "Host=server1 failed with error\\code\ndetails")
        self.assertEqual(fields.get("suser"), "admin\\corp")
        self.assertEqual(fields.get("act"), "connect=established")
        self.assertEqual(fields.get("outcome"), "success")

        result = self.processor.process(raw)
        self.assertEqual(result["user"]["name"], "admin\\corp")

    def test_4_existing_simple_cef_events(self):
        """
        TEST 4:
        Existing simple CEF events must continue working.
        """
        raw = "CEF:0|CheckPoint|VPN-1|R80|drop|Drop packet|5|src=10.0.0.50 dst=192.168.1.1 spt=443 dpt=53 proto=UDP act=drop"

        parsed = self.parser.parse(raw)
        fields = parsed.fields

        self.assertEqual(fields.get("src"), "10.0.0.50")
        self.assertEqual(fields.get("dst"), "192.168.1.1")
        self.assertEqual(fields.get("spt"), "443")
        self.assertEqual(fields.get("dpt"), "53")
        self.assertEqual(fields.get("proto"), "UDP")
        self.assertEqual(fields.get("act"), "drop")

        result = self.processor.process(raw)
        self.assertTrue(result["processing"]["valid"])
        self.assertEqual(result["source"]["ip"], "10.0.0.50")
        self.assertEqual(result["destination"]["ip"], "192.168.1.1")
        self.assertEqual(result["source"]["port"], 443)
        self.assertEqual(result["destination"]["port"], 53)
        self.assertEqual(result["network"]["protocol"], "UDP")
        self.assertEqual(result["event"]["action"], "drop")
        self.assertEqual(result["event"]["outcome"], "failure")
        self.assertEqual(result["event"]["type"], "denied")


if __name__ == "__main__":
    unittest.main()
