import unittest
from app.parsers.generic import GenericAdaptiveParser


class TestGenericAdaptiveParser(unittest.TestCase):
    def setUp(self):
        self.parser = GenericAdaptiveParser()

    def test_json_classification(self):
        payload = '{"source_ip": "10.0.0.1", "destination_ip": "192.168.1.2", "action": "ALLOW"}'
        res = self.parser.classify(payload)
        self.assertEqual(res["format"], "json")
        self.assertGreaterEqual(res["confidence"], 0.9)

    def test_nested_json_classification(self):
        payload = '{"timestamp": "2026-09-06T10:00:00Z", "network": {"src": "10.0.0.1", "dst": "10.0.0.2"}}'
        res = self.parser.classify(payload)
        self.assertEqual(res["format"], "nested_json")
        self.assertGreaterEqual(res["confidence"], 0.95)

    def test_key_value_classification(self):
        payload = "src=10.0.0.1 dst=192.168.1.2 action=DENY protocol=TCP sport=45021 dport=443"
        res = self.parser.classify(payload)
        self.assertIn(res["format"], ("key_value", "firewall"))
        self.assertGreaterEqual(res["confidence"], 0.85)

    def test_web_access_classification(self):
        payload = '192.168.1.50 - - [06/Sep/2026:12:00:00 +0000] "GET /admin/dashboard HTTP/1.1" 200 4502'
        res = self.parser.classify(payload)
        self.assertEqual(res["format"], "web_access")
        self.assertGreaterEqual(res["confidence"], 0.9)

    def test_structure_extraction(self):
        payload = 'src=10.0.0.1 dst=192.168.1.2 action=DENY msg="Invalid credential"'
        struct = self.parser.extract_structure(payload)
        raw_fields = struct["raw_fields"]
        self.assertEqual(raw_fields.get("src"), "10.0.0.1")
        self.assertEqual(raw_fields.get("dst"), "192.168.1.2")
        self.assertEqual(raw_fields.get("action"), "DENY")
        self.assertEqual(raw_fields.get("msg"), "Invalid credential")


if __name__ == "__main__":
    unittest.main()
