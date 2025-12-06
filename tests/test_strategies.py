import unittest
from rsc_exploit.strategies import AssetnoteStrategy, MsanftStrategy, SplitPayloadStrategy, VercelStrategy

class TestStrategies(unittest.TestCase):
    def test_assetnote_instantiation(self):
        s = AssetnoteStrategy("http://example.com", "id")
        self.assertIsInstance(s, AssetnoteStrategy)
        self.assertEqual(s.target_url, "http://example.com")

    def test_msanft_instantiation(self):
        s = MsanftStrategy("http://example.com", "id")
        self.assertIsInstance(s, MsanftStrategy)

    def test_split_payload_instantiation(self):
        s = SplitPayloadStrategy("http://example.com", "id")
        self.assertIsInstance(s, SplitPayloadStrategy)

    def test_vercel_instantiation(self):
        s = VercelStrategy("http://example.com", "id")
        self.assertIsInstance(s, VercelStrategy)

    def test_waf_bypass_config(self):
        s = AssetnoteStrategy("http://example.com", "id", waf_bypass=True, waf_bypass_size=256)
        self.assertTrue(s.waf_bypass)
        self.assertEqual(s.waf_bypass_size, 256)

if __name__ == "__main__":
    unittest.main()
