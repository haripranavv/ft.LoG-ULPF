import unittest
from app.parsers.csv_parser import CSVParser
from app.parsers.yaml_parser import YAMLParser
from app.parsers.key_value import KeyValueParser
from app.processing.processor import get_processor
from app.storage.raw_storage import raw_storage


class TestNewParsers(unittest.TestCase):
    def test_csv_parser(self):
        parser = CSVParser()
        log = "2026-09-14T10:00:00Z, 192.168.1.100, 10.0.0.1, 443, TCP, ALLOW"
        self.assertTrue(parser.can_parse(log))
        parsed = parser.parse(log)
        self.assertEqual(parsed.source_format, "csv")
        self.assertEqual(parsed.fields.get("src_ip"), "192.168.1.100")
        self.assertEqual(parsed.fields.get("dst_ip"), "10.0.0.1")
        self.assertEqual(parsed.fields.get("action"), "ALLOW")

    def test_yaml_parser(self):
        parser = YAMLParser()
        log = "timestamp: 2026-09-14T10:00:00Z\nsrc_ip: 10.10.10.5\naction: BLOCK\nrule: MALWARE_DROP"
        self.assertTrue(parser.can_parse(log))
        parsed = parser.parse(log)
        self.assertEqual(parsed.source_format, "yaml")
        self.assertEqual(parsed.fields.get("src_ip"), "10.10.10.5")
        self.assertEqual(parsed.fields.get("action"), "BLOCK")

    def test_key_value_quoted_values(self):
        parser = KeyValueParser()
        log = 'timestamp=2026-09-14T12:00:00Z user=alice msg="Suspicious login from internal subnet" status=ALERT'
        self.assertTrue(parser.can_parse(log))
        parsed = parser.parse(log)
        self.assertEqual(parsed.fields.get("user"), "alice")
        self.assertEqual(parsed.fields.get("msg"), "Suspicious login from internal subnet")
        self.assertEqual(parsed.fields.get("status"), "ALERT")

    def test_merkle_batch_root(self):
        hashes = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        ]
        root = raw_storage.compute_merkle_root(hashes)
        self.assertTrue(len(root) == 64)
        # Verify determinism
        self.assertEqual(root, raw_storage.compute_merkle_root(hashes))

    def test_e2e_processor_csv(self):
        processor = get_processor()
        log = "2026-09-14T10:00:00Z, 192.168.1.100, 10.0.0.1, 443, TCP, ALLOW"
        res = processor.process(log)
        self.assertTrue(res["processing"]["valid"])
        self.assertEqual(res["source"]["ip"], "192.168.1.100")
        self.assertEqual(res["destination"]["ip"], "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
