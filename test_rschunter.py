import unittest
import os
import json
from unittest.mock import MagicMock, patch
from rschunter import UrlParser, RscScanner, MassScanner, ScanResult, generateReport

class TestUrlParser(unittest.TestCase):
    def test_normalizeUrl(self):
        self.assertEqual(UrlParser.normalizeUrl("example.com"), "https://example.com")
        self.assertEqual(UrlParser.normalizeUrl("http://example.com"), "http://example.com")
        self.assertEqual(UrlParser.normalizeUrl("example.com/path"), "https://example.com/path")
        self.assertEqual(UrlParser.normalizeUrl("invalid"), "https://invalid")

    def test_extractDomain(self):
        self.assertEqual(UrlParser.extractDomain("https://example.com/foo"), "example.com")

class TestRscScanner(unittest.TestCase):
    @patch('rschunter.requests.Session')
    def test_scanUrl_passive(self, mock_session):
        # Mock response
        mock_response = MagicMock()
        mock_response.headers = {'Content-Type': 'text/x-component'}
        mock_response.text = "some content"
        mock_session.return_value.get.return_value = mock_response
        
        scanner = RscScanner()
        # Mock the session instance created in __init__
        scanner.session = mock_session.return_value
        
        result = scanner.scanUrl("https://example.com")
        self.assertTrue(result.vulnerable)
        self.assertTrue(result.passiveDetected)
        self.assertIn("Content-Type: text/x-component", result.details)

class TestMassScanner(unittest.TestCase):
    def test_executeCommand(self):
        scanner = MassScanner(execCommand="echo Hello {}")
        output = scanner.executeCommand("World")
        self.assertEqual(output, "Hello World")

    def test_executeCommand_none(self):
        scanner = MassScanner()
        output = scanner.executeCommand("World")
        self.assertIsNone(output)

class TestReporting(unittest.TestCase):
    def test_generateReport(self):
        results = [
            ScanResult(
                url="https://vuln.com",
                vulnerable=True,
                passiveDetected=True,
                activeDetected=False,
                endpointVulnerable=False,
                details=["Vuln found"],
                timestamp="2023-01-01",
                execOutput="Command ran"
            ),
            ScanResult(
                url="https://clean.com",
                vulnerable=False,
                passiveDetected=False,
                activeDetected=False,
                endpointVulnerable=False,
                details=[],
                timestamp="2023-01-01"
            )
        ]
        
        filename = "test_report.txt"
        generateReport(results, filename)
        
        with open(filename, 'r') as f:
            content = f.read()
            self.assertIn("https://vuln.com", content)
            self.assertIn("Vuln found", content)
            self.assertIn("Command ran", content)
            self.assertNotIn("https://clean.com", content)
        
        os.remove(filename)

if __name__ == '__main__':
    unittest.main()
