import unittest
from unittest.mock import Mock
from rsc_exploit.strategies import SplitPayloadStrategy

class TestSplitPayloadStrategy(unittest.TestCase):
    def setUp(self):
        self.strategy = SplitPayloadStrategy("http://example.com", "id")

    def test_payload_generation(self):
        payload = self.strategy.build_payload()
        # payload is (data, content_type)
        self.assertIn("RSC_SPLIT_", payload[0])
        self.assertIn("throw new Error", payload[0])
        self.assertIn("process.mainModule.require('child_process')", payload[0])

    def test_check_vulnerability_success(self):
        response = Mock()
        # Simulate a valid error response with output
        response.text = "Error: RSC_SPLIT_uid=0(root) gid=0(root) groups=0(root)\n    at /app/page.js:10:5"
        response.status_code = 200 # Status code doesn't matter as much now, but let's be realistic
        
        is_vuln, output = self.strategy.check_vulnerability(response)
        self.assertTrue(is_vuln)
        self.assertEqual(output, "uid=0(root) gid=0(root) groups=0(root)")

    def test_check_vulnerability_reflection(self):
        response = Mock()
        # Simulate reflected source code (false positive)
        # This happens when the server just prints back the payload string
        response.text = "Error: RSC_SPLIT_' + res"
        
        is_vuln, output = self.strategy.check_vulnerability(response)
        self.assertFalse(is_vuln)
        self.assertIsNone(output)

        # Another variation of reflection
        response.text = 'Error: RSC_SPLIT_" + res'
        is_vuln, output = self.strategy.check_vulnerability(response)
        self.assertFalse(is_vuln)

    def test_check_vulnerability_fail(self):
        response = Mock()
        response.text = "Some random error or content"
        
        is_vuln, output = self.strategy.check_vulnerability(response)
        self.assertFalse(is_vuln)
        self.assertIsNone(output)

if __name__ == "__main__":
    unittest.main()
