#!/usr/bin/env python3
"""Test URL normalization with various input formats"""

import sys
sys.path.insert(0, '/home/spectre/Projects/.dotfiles/exploits/CVE-2025-55182/rschunter')

from rschunter import UrlParser

test_cases = [
    # Basic domains
    ("example.com", "https://example.com"),
    ("sub.example.com", "https://sub.example.com"),
    ("domain.co.uk", "https://domain.co.uk"),
    
    # Domains with ports
    ("example.com:8080", "https://example.com:8080"),
    ("api.example.com:443", "https://api.example.com:443"),
    
    # Domains with paths
    ("example.com/api", "https://example.com/api"),
    ("example.com/api/v1", "https://example.com/api/v1"),
    ("example.com/path?query=1", "https://example.com/path?query=1"),
    
    # Full URLs (should preserve)
    ("https://example.com", "https://example.com"),
    ("http://example.com", "http://example.com"),
    ("https://example.com:8443/api", "https://example.com:8443/api"),
    
    # Local IPs (should use http)
    ("192.168.0.58:3000", "http://192.168.0.58:3000"),
    ("192.168.1.1", "http://192.168.1.1"),
    ("10.0.0.1:8080", "http://10.0.0.1:8080"),
    ("127.0.0.1:3000", "http://127.0.0.1:3000"),
    ("localhost:3000", "http://localhost:3000"),
    ("localhost", "http://localhost"),
    
    # Local IPs with paths
    ("192.168.0.58:3000/admin", "http://192.168.0.58:3000/admin"),
    ("localhost:8080/api/v1", "http://localhost:8080/api/v1"),
    
    # Private class B (172.16-31.x.x)
    ("172.16.0.1", "http://172.16.0.1"),
    ("172.31.255.255", "http://172.31.255.255"),
    ("172.20.0.1:8080", "http://172.20.0.1:8080"),
    
    # Public IPs (should use https)
    ("8.8.8.8", "https://8.8.8.8"),
    ("1.1.1.1:443", "https://1.1.1.1:443"),
    
    # Edge cases
    ("example.com/", "https://example.com"),  # trailing slash removed
    ("https://example.com/", "https://example.com"),  # trailing slash removed
    ("//example.com", "https://example.com"),  # scheme-relative
    
    # With full URLs (preserve scheme)
    ("http://192.168.0.58:3000", "http://192.168.0.58:3000"),
    ("https://192.168.0.58:3000", "https://192.168.0.58:3000"),  # user override
]

print("\n" + "="*80)
print("🧪 URL NORMALIZATION TEST SUITE")
print("="*80 + "\n")

passed = 0
failed = 0

for input_url, expected in test_cases:
    result = UrlParser.normalizeUrl(input_url)
    status = "✅" if result == expected else "❌"
    
    if result == expected:
        passed += 1
    else:
        failed += 1
        print(f"{status} FAIL: {input_url}")
        print(f"   Expected: {expected}")
        print(f"   Got:      {result}\n")

print("-"*80)
print(f"\n📊 Results: {passed}/{len(test_cases)} passed, {failed} failed")

if failed == 0:
    print("🎉 ALL TESTS PASSED!\n")
else:
    print(f"❌ {failed} tests failed\n")

sys.exit(0 if failed == 0 else 1)
