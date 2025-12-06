# RSC Hunter v2.3.0 - Release Notes

## 🚀 Major Release: Advanced Detection & Evasion Capabilities

Released: December 6, 2025

This release brings significant enhancements to RSC Hunter, incorporating advanced research from the security community (Assetnote) and adding production-ready features for real-world penetration testing and bug bounty hunting.

---

## 🎯 Key Features

### 1. X-Action-Redirect Header Detection (CRITICAL)

**Impact:** Definitive RCE proof detection

The scanner now detects RCE output reflection in the `X-Action-Redirect` response header - a technique discovered by security researchers that provides 100% confidence in vulnerability verification.

```bash
# Automatically detected in passive scans
python3 rschunter.py --url https://target.com
```

**Technical Details:**
- Detects `/login?a=11111` pattern (result of 41*271)
- Adds 100 confidence points to scoring system
- Based on research by @xEHLE_ and Assetnote team
- Provides definitive proof of code execution

### 2. WAF Bypass Mode

**Impact:** Evade Web Application Firewalls

Many production WAFs only inspect the first portion of HTTP request bodies. This feature prepends random junk data to bypass content-based detection rules.

```bash
# Enable with default 128KB junk data
python3 rschunter.py targets.txt --waf-bypass

# Custom junk data size
python3 rschunter.py targets.txt --waf-bypass --waf-bypass-size 256

# Automatically increases timeout to 20s
```

**Features:**
- Random parameter names to avoid signature detection
- Configurable junk data size (default: 128KB)
- Automatic timeout adjustment
- Effective against content-based WAF rules

### 3. Vercel WAF Bypass

**Impact:** Bypass Vercel-specific protections

Specialized payload structure for Vercel's WAF, using alternative multipart encoding and escaped characters.

```bash
python3 rschunter.py --url https://example.vercel.app --vercel-waf-bypass
```

**Technical Approach:**
- Alternative multipart structure
- Escaped dollar signs (`\u0024`)
- Additional form fields for signature bypass
- Targets Vercel-specific parsing behavior

### 4. Windows Target Support

**Impact:** Scan Windows-based Next.js applications

Automatically switches from Unix shell commands to PowerShell, enabling testing of Windows Server deployments.

```bash
python3 rschunter.py --url https://windows-target.com --windows
```

**Behavior:**
- Unix: `echo $((41*271))`
- Windows: `powershell -c "41*271"`
- Automatic syntax adjustment for exploit payloads
- Compatible with Windows Server environments

### 5. Redirect Following

**Impact:** Improved coverage for multi-language sites

Automatically follows same-host redirects to test final destinations (e.g., `/` → `/en/` → `/en/dashboard`).

```bash
# Enabled by default
python3 rschunter.py --url https://example.com

# Disable if needed
python3 rschunter.py --url https://example.com --no-follow-redirects
```

**Security:**
- Only follows same-host redirects
- Cross-origin redirects are not followed
- Prevents infinite redirect loops (max: 10)
- Adds redirect information to scan results

### 6. Mitigation Detection

**Impact:** Reduced false positives

Automatically detects and filters hosts protected by Vercel or Netlify mitigations.

**Detected Mitigations:**
- `Server: vercel` header
- `Server: netlify` header
- `Netlify-Vary` header presence

**Benefits:**
- Reduces noise in scan results
- Focuses efforts on truly vulnerable targets
- Improves report accuracy

---

## 📊 Enhanced Detection System

### Updated Scoring System

| Indicator | Points | Description |
|-----------|--------|-------------|
| **X-Action-Redirect** | 100 | 🆕 RCE proof - Output reflection |
| `text/x-component` | 100 | Definitive RSC response |
| `window.__next_f` | 80 | Next.js flight data |
| x-middleware-subrequest | 50 | Exploit condition header |
| RSC payload structure | 50 | `{"then": "$..."}` format |
| ... | ... | ... |

---

## 🛠️ Technical Improvements

### New Utility Functions

```python
generate_junk_data(size_kb: int) -> Tuple[str, str]
"""Generate random junk data for WAF bypass"""

resolve_redirects(url: str, session, timeout: int, max_redirects: int) -> str
"""Follow same-host redirects only"""

is_mitigated_host(response: requests.Response) -> bool
"""Check if host has Vercel/Netlify mitigations"""
```

### RscScanner Class Updates

```python
class RscScanner:
    def __init__(
        self,
        timeout: int = 10,
        maxWorkers: int = 10,
        wafBypass: bool = False,          # 🆕
        wafBypassSize: int = 128,         # 🆕
        windowsMode: bool = False,        # 🆕
        vercelWafBypass: bool = False,    # 🆕
        followRedirects: bool = True      # 🆕
    ):
        ...
```

---

## 📚 Documentation Updates

### New README Sections

1. **Advanced Features**
   - WAF bypass mode with examples
   - Vercel WAF bypass
   - Windows target support
   - Redirect following configuration
   - Combined usage examples

2. **Command Reference**
   - Updated options table with all new flags
   - Comprehensive flag descriptions
   - Default values clearly marked

3. **Detection Methodology**
   - Mitigation detection explanation
   - Updated scoring system
   - X-Action-Redirect technique details

### Updated CHANGELOG

Comprehensive v2.3.0 entry with:
- All new features documented
- Technical implementation details
- Credits to research community
- Migration guide for users

---

## ✅ Testing & Validation

### Test Results

```
======================================================================
  🛡️  RSC HUNTER - UNIT TEST SUITE
======================================================================

----------------------------------------------------------------------
Ran 15 tests in 0.003s

OK

  Total Tests:       15
  Passed:            15
  Failed:            0
  Errors:            0
  Success Rate:      100.0%
======================================================================
```

### Backward Compatibility

✅ All existing functionality preserved
✅ No breaking changes
✅ Default behavior unchanged
✅ New features opt-in via flags

---

## 🔄 Migration Guide

### For Existing Users

No changes required! All new features are opt-in:

```bash
# Your existing commands work exactly the same
python3 rschunter.py targets.txt
python3 rschunter.py --url https://example.com -sh

# Enable new features as needed
python3 rschunter.py targets.txt --waf-bypass --windows
```

### Recommended Configuration for Maximum Coverage

```bash
# Bug bounty / penetration testing
python3 rschunter.py targets.txt \
  --waf-bypass \
  --follow-redirects \
  --threads 20 \
  -sh

# Windows-heavy environments
python3 rschunter.py windows-targets.txt \
  --windows \
  --vercel-waf-bypass \
  --threads 15
```

---

## 🙏 Credits

### Research & Inspiration

- **Assetnote Security Research Team** - react2shell-scanner implementation
  - Adam Kues, Tomais Williamson, Dylan Pindur, Patrik Grobshäuser, Shubham Shah
- **@xEHLE_** - X-Action-Redirect header RCE reflection technique
- **@galnagli** - Vulnerability research contributions
- **@maple3142** - Original RCE PoC disclosure

### Community

- Security community for CVE-2025-55182 analysis
- Reddit researchers for attack surface mapping
- Shodan query optimization contributors

---

## 📦 Installation

### Update from v2.2.0

```bash
cd rschunter/
git pull origin main  # or download latest release

# No new dependencies required!
# Existing `requests` and `urllib3` are sufficient
```

### Fresh Installation

```bash
# Clone repository
git clone https://github.com/sumanrox/rschunter.git
cd rschunter/

# Install dependencies
pip3 install requests urllib3

# Test installation
python3 rschunter.py --help
python3 test_rschunter.py
```

---

## 🔮 Future Roadmap

Planned for v2.4.0:
- HTTP/2 support for modern deployments
- Custom user-agent rotation
- Proxy support for distributed scanning
- JSON output format for automation
- Performance profiling mode

---

## 📄 License

This tool is provided for educational and authorized security testing purposes only. Use responsibly and ethically.

---

## 📞 Support

- **GitHub Issues**: https://github.com/sumanrox/rschunter/issues
- **Documentation**: https://github.com/sumanrox/rschunter
- **Author**: Suman Roy (@sumanrox)
  - Website: https://sumanroy.in
  - GitHub: https://github.com/sumanrox

---

**RSC Hunter v2.3.0** - Production-ready vulnerability scanner with advanced evasion capabilities.

🛡️ Happy Hunting! 🎯
