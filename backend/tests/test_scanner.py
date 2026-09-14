import unittest
from app.scanner.engine import scanner


class TestDeviceScanner(unittest.TestCase):
    def test_capabilities(self):
        caps = scanner.get_capabilities()
        self.assertIn("os", caps)
        self.assertTrue(caps["lan"]["supported"])

    def test_oui_vendor_lookup(self):
        vendor, dtype, conf = scanner.resolve_vendor("00:1E:0B:12:34:56")
        self.assertEqual(vendor, "HP Inc")
        self.assertEqual(dtype, "printer")
        self.assertGreater(conf, 0.9)

        vendor, dtype, conf = scanner.resolve_vendor("C0:25:A5:11:22:33")
        self.assertEqual(vendor, "Cisco Systems")
        self.assertEqual(dtype, "switch")

    def test_infer_device_type(self):
        dtype, conf = scanner.infer_device_type("lan", "main-office-printer-01", None, None)
        self.assertEqual(dtype, "printer")

        dtype, conf = scanner.infer_device_type("lan", "hq-camera-east", None, None)
        self.assertEqual(dtype, "camera")

        dtype, conf = scanner.infer_device_type("lan", "core-router-gateway", None, None)
        self.assertEqual(dtype, "router")

    def test_lan_discovery(self):
        devices = scanner.scan_lan()
        self.assertIsInstance(devices, list)
        print(f"\n[Scanner Test] Real LAN devices discovered: {len(devices)}")
        if devices:
            print(f"Sample device: {devices[0]}")


if __name__ == "__main__":
    unittest.main()
