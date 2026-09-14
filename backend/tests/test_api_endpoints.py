import unittest
from fastapi.testclient import TestClient
from app.main import app


class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        login_res = self.client.post("/api/auth/login", json={"username": "admin", "password": "ulpf_admin_2026"})
        if login_res.status_code == 200:
            token = login_res.json()["token"]
            self.client.headers.update({"Authorization": f"Bearer {token}"})

    def test_health(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")

    def test_capabilities(self):
        res = self.client.get("/api/devices/capabilities")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["lan"]["supported"])

    def test_list_devices(self):
        res = self.client.get("/api/devices")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

    def test_list_mappings(self):
        res = self.client.get("/api/mappings")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)
        self.assertGreater(len(res.json()), 0)

    def test_list_exports(self):
        res = self.client.get("/api/exports")
        self.assertEqual(res.status_code, 200)
        self.assertIn("supported_targets", res.json())
        self.assertIn("jsonl", res.json()["supported_targets"])

    def test_ingest_payload(self):
        log = "2026-09-06T10:00:00Z FW01 ALLOW SRC=10.10.10.25 DST=172.16.1.20 SP=49152 DP=443 PROTO=TCP RULE=ALLOW_WEB USER=alice"
        res = self.client.post("/api/ingest/payload", json={
            "filename": "firewall.log",
            "content": log,
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["valid_count"], 1)
        self.assertTrue(len(data["sha256_hash"]) == 64)
        self.assertTrue(len(data["batch_merkle_root"]) == 64)


if __name__ == "__main__":
    unittest.main()
