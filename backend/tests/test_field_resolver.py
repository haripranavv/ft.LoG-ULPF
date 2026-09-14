import unittest
from app.normalization.field_resolver import CanonicalFieldResolver


class TestCanonicalFieldResolver(unittest.TestCase):
    def setUp(self):
        self.resolver = CanonicalFieldResolver()

    def test_known_network_aliases(self):
        res1 = self.resolver.resolve_field("srcaddr", "10.0.0.1")
        self.assertEqual(res1["canonical_candidate"], "source.ip")
        self.assertGreaterEqual(res1["confidence"], 0.95)
        self.assertFalse(res1["requires_review"])

        res2 = self.resolver.resolve_field("destinationAddress", "172.16.0.5")
        self.assertEqual(res2["canonical_candidate"], "destination.ip")
        self.assertGreaterEqual(res2["confidence"], 0.95)

    def test_user_and_action_aliases(self):
        res1 = self.resolver.resolve_field("username", "admin_sec")
        self.assertEqual(res1["canonical_candidate"], "user.name")
        self.assertGreaterEqual(res1["confidence"], 0.95)

        res2 = self.resolver.resolve_field("event_action", "DENY")
        self.assertEqual(res2["canonical_candidate"], "event.action")
        self.assertGreaterEqual(res2["confidence"], 0.95)

    def test_ambiguous_fields(self):
        res = self.resolver.resolve_field("id")
        self.assertTrue(res["requires_review"])
        self.assertIn("event.id", res["candidates"])
        self.assertIn("user.id", res["candidates"])

    def test_resolve_all_batch(self):
        fields = {
            "src": "10.10.10.10",
            "dst": "20.20.20.20",
            "sport": 443,
            "action": "ALLOW",
            "user": "alice",
        }
        batch = self.resolver.resolve_all(fields)
        self.assertEqual(len(batch["resolutions"]), 5)
        self.assertGreater(batch["average_confidence"], 0.9)
        self.assertFalse(batch["review_required"])


if __name__ == "__main__":
    unittest.main()
