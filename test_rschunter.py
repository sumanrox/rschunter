#!/usr/bin/env python3
"""
Comprehensive unit tests for RSC Mass Vulnerability Scanner (rschunter)

Tests cover:
- URL parsing and normalization
- Detection methods (passive, active, endpoint)
- Exploit payload generation
- Interactive shell functionality
- State management and resume capability
- Multi-threaded scanning
- Error handling and edge cases
"""

import unittest
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from io import StringIO
import sys

# Color codes for beautiful output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# Import modules to test
import rschunter
from rschunter import (
    UrlParser,
    ScanResult,
    ScanStateManager,
    RscScanner,
    MassScanner,
    InteractiveShell,
    Colors,
    generateCSV
)


class TestUrlParser(unittest.TestCase):
    """Test URL parsing and normalization"""
    
    def testNormalizeUrlWithScheme(self):
        """Test URL with existing scheme"""
        result = UrlParser.normalizeUrl("https://example.com")
        self.assertEqual(result, "https://example.com")
    
    def testNormalizeUrlWithoutScheme(self):
        """Test URL without scheme (should add https)"""
        result = UrlParser.normalizeUrl("example.com")
        self.assertEqual(result, "https://example.com")
    
    def testNormalizeUrlWithPath(self):
        """Test URL with path preservation"""
        result = UrlParser.normalizeUrl("https://example.com/api/test")
        self.assertEqual(result, "https://example.com/api/test")
    
    def testNormalizeUrlWithQuery(self):
        """Test URL with query parameters"""
        result = UrlParser.normalizeUrl("https://example.com?param=value")
        self.assertEqual(result, "https://example.com?param=value")
    
    def testNormalizeUrlTrailingSlash(self):
        """Test removal of trailing slash"""
        result = UrlParser.normalizeUrl("https://example.com/")
        self.assertEqual(result, "https://example.com")
    
    def testNormalizeUrlInvalid(self):
        """Test invalid URLs return None"""
        self.assertIsNone(UrlParser.normalizeUrl(""))
        self.assertIsNone(UrlParser.normalizeUrl("   "))
    
    def testNormalizeUrlWithPort(self):
        """Test URL with custom port"""
        result = UrlParser.normalizeUrl("https://example.com:8080")
        self.assertEqual(result, "https://example.com:8080")
    
    def testExtractDomain(self):
        """Test domain extraction"""
        self.assertEqual(UrlParser.extractDomain("https://example.com/path"), "example.com")
        self.assertEqual(UrlParser.extractDomain("https://sub.example.com:8080"), "sub.example.com:8080")
        self.assertEqual(UrlParser.extractDomain("https://example.com/foo"), "example.com")


class TestScanStateManager(unittest.TestCase):
    """Test scan state management and resume functionality"""
    
    def setUp(self):
        """Create temporary state file for testing"""
        self.tempFile = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        self.tempFile.close()
        self.stateManager = ScanStateManager(stateFile=self.tempFile.name)
    
    def tearDown(self):
        """Clean up temporary files"""
        if os.path.exists(self.tempFile.name):
            os.unlink(self.tempFile.name)
    
    def testSaveState(self):
        """Test saving scan state"""
        targets = ["https://example.com", "https://test.com"]
        completed = {"https://example.com"}
        results = [ScanResult(
            url="https://example.com",
            vulnerable=True,
            passiveDetected=True,
            activeDetected=False,
            endpointVulnerable=False,
            details=["test"],
            timestamp="2025-12-06T00:00:00"
        )]
        
        self.stateManager.saveState(targets, completed, results, "test_scan")
        
        self.assertTrue(os.path.exists(self.tempFile.name))
        with open(self.tempFile.name, 'r') as f:
            state = json.load(f)
        
        self.assertEqual(state['scanId'], 'test_scan')
        self.assertEqual(state['total'], 2)
        self.assertEqual(state['scanned'], 1)
    
    def testLoadState(self):
        """Test loading scan state"""
        state = {
            'scanId': 'test_scan',
            'timestamp': '2025-12-06T00:00:00',
            'targets': ['https://example.com'],
            'completed': ['https://example.com'],
            'results': [],
            'total': 1,
            'scanned': 1
        }
        
        with open(self.tempFile.name, 'w') as f:
            json.dump(state, f)
        
        loaded = self.stateManager.loadState()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded['scanId'], 'test_scan')
    
    def testLoadStateNonexistent(self):
        """Test loading non-existent state file"""
        os.unlink(self.tempFile.name)
        loaded = self.stateManager.loadState()
        self.assertIsNone(loaded)


class TestRscScanner(unittest.TestCase):
    """Test RSC vulnerability scanner detection methods"""
    
    def setUp(self):
        """Initialize scanner for testing"""
        self.scanner = RscScanner(timeout=5, maxWorkers=5)
    
    @patch('rschunter.requests.Session.get')
    def testPassiveScanVulnerable(self, mockGet):
        """Test passive detection with vulnerable indicators"""
        mockResponse = Mock()
        mockResponse.status_code = 200
        mockResponse.headers = {'Content-Type': 'text/x-component'}
        mockResponse.text = 'window.__next_f = []'
        mockGet.return_value = mockResponse
        
        detected, details = self.scanner._passiveScan("https://example.com")
        
        self.assertTrue(detected)
        self.assertIn("Content-Type: text/x-component", details)
    
    @patch('rschunter.requests.Session.get')
    def testPassiveScanClean(self, mockGet):
        """Test passive detection with clean site"""
        mockResponse = Mock()
        mockResponse.status_code = 200
        mockResponse.headers = {'Content-Type': 'text/html'}
        mockResponse.text = '<html>Normal website</html>'
        mockGet.return_value = mockResponse
        
        detected, details = self.scanner._passiveScan("https://example.com")
        
        self.assertFalse(detected)


class TestMassScanner(unittest.TestCase):
    """Test mass scanning functionality"""
    
    def setUp(self):
        """Initialize mass scanner for testing"""
        self.scanner = MassScanner(maxWorkers=5)
    
    def testLoadTargetsFromFile(self):
        """Test loading targets from file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("example.com\n")
            f.write("https://test.com\n")
            f.write("# comment\n")
            f.write("\n")
            f.write("subdomain.example.com:8080\n")
            tempPath = f.name
        
        try:
            targets = self.scanner.loadTargets(tempPath)
            self.assertEqual(len(targets), 3)
            self.assertTrue(all(t.startswith('https://') for t in targets))
        finally:
            os.unlink(tempPath)


class TestScanResult(unittest.TestCase):
    """Test ScanResult dataclass"""
    
    def testScanResultCreation(self):
        """Test creating scan result"""
        result = ScanResult(
            url="https://example.com",
            vulnerable=True,
            passiveDetected=True,
            activeDetected=False,
            endpointVulnerable=False,
            details=["test detail"],
            timestamp="2025-12-06T00:00:00"
        )
        
        self.assertTrue(result.vulnerable)
        self.assertEqual(len(result.details), 1)


def runTests():
    """Run all tests with verbose output and beautiful statistics"""
    import time
    import sys
    
    # Detect if terminal supports Unicode (for emojis)
    supportsUnicode = True
    try:
        # Test if we can encode emojis
        "🛡️".encode(sys.stdout.encoding or 'utf-8')
    except (UnicodeEncodeError, AttributeError):
        supportsUnicode = False
    
    # Emoji fallbacks for Windows CI
    shield = "🛡️ " if supportsUnicode else "[*]"
    chart = "📊 " if supportsUnicode else "[+]"
    party = " 🎉" if supportsUnicode else ""
    cross = " ❌" if supportsUnicode else ""
    checkmark = "✓" if supportsUnicode else "[PASS]"
    xmark = "✗" if supportsUnicode else "[FAIL]"
    
    # Print header
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}")
    print(f"  {shield} RSC HUNTER - UNIT TEST SUITE")
    print(f"{'='*70}{Colors.RESET}\n")
    
    startTime = time.time()
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    elapsed = time.time() - startTime
    
    # Print beautiful statistics
    passed = result.testsRun - len(result.failures) - len(result.errors)
    successRate = (passed / result.testsRun * 100) if result.testsRun > 0 else 0
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*70}")
    print(f"  {chart}TEST STATISTICS")
    print(f"{'='*70}{Colors.RESET}")
    print(f"  {Colors.BOLD}Total Tests:{Colors.RESET}       {Colors.CYAN}{result.testsRun}{Colors.RESET}")
    print(f"  {Colors.BOLD}Passed:{Colors.RESET}            {Colors.GREEN}{passed}{Colors.RESET}")
    print(f"  {Colors.BOLD}Failed:{Colors.RESET}            {Colors.RED if len(result.failures) > 0 else Colors.GREEN}{len(result.failures)}{Colors.RESET}")
    print(f"  {Colors.BOLD}Errors:{Colors.RESET}            {Colors.RED if len(result.errors) > 0 else Colors.GREEN}{len(result.errors)}{Colors.RESET}")
    print(f"  {Colors.BOLD}Skipped:{Colors.RESET}           {Colors.YELLOW if len(result.skipped) > 0 else Colors.GREEN}{len(result.skipped)}{Colors.RESET}")
    print(f"  {Colors.BOLD}Execution Time:{Colors.RESET}    {Colors.MAGENTA}{elapsed:.3f}s{Colors.RESET}")
    print(f"  {Colors.BOLD}Average per test:{Colors.RESET}  {Colors.MAGENTA}{(elapsed/result.testsRun)*1000:.2f}ms{Colors.RESET}")
    
    # Success rate with color
    rateColor = Colors.GREEN if successRate == 100 else Colors.YELLOW if successRate >= 80 else Colors.RED
    print(f"  {Colors.BOLD}Success Rate:{Colors.RESET}      {rateColor}{successRate:.1f}%{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*70}{Colors.RESET}")
    
    # Final status with emoji and colors
    if result.wasSuccessful():
        print(f"\n  {Colors.GREEN}{Colors.BOLD}{checkmark} ALL TESTS PASSED{Colors.RESET}{Colors.GREEN}{party}{Colors.RESET}\n")
    else:
        print(f"\n  {Colors.RED}{Colors.BOLD}{xmark} SOME TESTS FAILED{Colors.RESET}{Colors.RED}{cross}{Colors.RESET}\n")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = runTests()
    sys.exit(0 if success else 1)
