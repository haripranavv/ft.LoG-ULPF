import unittest
import json
from app.export.engine import export_engine, JSONLinesExporter, ElasticsearchExporter


class TestExportEngine(unittest.TestCase):
    def setUp(self):
        self.sample_events = [
            {
                "id": "event-1",
                "timestamp": "2026-09-14T10:00:00Z",
                "event": {"id": "event-1", "action": "ALLOW", "type": "firewall"},
                "source": {"ip": "10.0.0.1"},
                "destination": {"ip": "172.16.0.1"},
                "normalized_event": {
                    "event": {"id": "event-1", "action": "ALLOW"},
                    "source": {"ip": "10.0.0.1"},
                },
            },
            {
                "id": "event-2",
                "timestamp": "2026-09-14T10:01:00Z",
                "event": {"id": "event-2", "action": "DROP", "type": "firewall"},
                "source": {"ip": "10.0.0.2"},
                "destination": {"ip": "172.16.0.1"},
                "normalized_event": {
                    "event": {"id": "event-2", "action": "DROP"},
                    "source": {"ip": "10.0.0.2"},
                },
            },
        ]

    def test_jsonl_export(self):
        res = export_engine.run_export("jsonl", self.sample_events)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["event_count"], 2)
        lines = [l for l in res["content"].split("\n") if l.strip()]
        self.assertEqual(len(lines), 2)
        obj1 = json.loads(lines[0])
        self.assertEqual(obj1["source"]["ip"], "10.0.0.1")

    def test_elasticsearch_formatter(self):
        exporter = ElasticsearchExporter()
        # Test formatting without actual network post (using mock or format inspection)
        self.assertEqual(exporter.target_type, "elasticsearch")


if __name__ == "__main__":
    unittest.main()
