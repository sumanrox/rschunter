import unittest
from rsc_exploit.utils import normalize_url

class TestNormalization(unittest.TestCase):
    def test_basic_domain(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")

    def test_http_scheme(self):
        self.assertEqual(normalize_url("http://example.com"), "http://example.com")

    def test_https_scheme(self):
        self.assertEqual(normalize_url("https://example.com"), "https://example.com")

    def test_trailing_slash(self):
        self.assertEqual(normalize_url("https://example.com/"), "https://example.com")

    def test_path_preservation(self):
        self.assertEqual(normalize_url("https://example.com/path"), "https://example.com/path")

    def test_path_trailing_slash_removal(self):
        self.assertEqual(normalize_url("https://example.com/path/"), "https://example.com/path")

    def test_whitespace(self):
        self.assertEqual(normalize_url("  example.com  "), "https://example.com")

if __name__ == "__main__":
    unittest.main()
