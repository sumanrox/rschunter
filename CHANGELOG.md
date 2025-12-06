# RSC Hunter - Version History

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Web UI for results visualization
- Plugin system for custom detection methods
- Database backend for large-scale scanning
- Automated Nuclei template updates

## [2.5.0] - 2025-12-07

### Added
- **Proxy Support** (`--proxy`)
  - Route all traffic through proxy for inspection (Burp Suite, mitmproxy, ZAP)
  - Command-line flag: `--proxy http://127.0.0.1:8080`
  - Environment variable support: `HTTP_PROXY`, `HTTPS_PROXY`
  - Automatic SSL verification disable for MITM proxies
  - Clean output with suppressed SSL warnings
  - Perfect for debugging and analyzing exploit traffic

### Fixed
- **Interactive Shell Exit** (`-sh` flag)
  - Shell now exits immediately when typing `exit` during large scans
  - Background scan continues as daemon thread (doesn't block exit)
  - Added `should_exit` Event flag for clean shutdown
  - Fixed blocking `scanComplete.wait()` calls after shell exit
  - Improved user experience for long-running scans

## [2.4.0] - 2025-12-07

### Changed - Major Refactoring & Reliability Improvements
- **Modular Architecture**
  - Split monolithic code into clean modules: `lib/exploits.py`, `lib/validators.py`, `lib/utils.py`
  - Improved code maintainability and testability
  - Easier to extend with new exploitation methods
  
- **Exploitation Method Reordering** (Critical Fix)
  - Method 3 (msanft's PoC) now PRIMARY - most reliable method
  - Method 2 (Assetnote format) as alternative fallback
  - Method 1 (Function constructor) as last resort
  - Based on real-world testing against vulnerable servers
  
- **Method 3 Optimization**
  - Now sends directly to base URL only (no endpoint enumeration)
  - Matches msanft's proven working exploit exactly
  - Significantly improved success rate on actual vulnerable targets
  - Reduced false negatives

- **Smart URL Normalization** (Major UX Improvement)
  - Handles ALL input formats: domains, IPs, full URLs, with/without ports/paths
  - Automatic scheme detection: `http://` for private IPs, `https://` for public
  - Supports: `example.com`, `192.168.1.1:3000`, `localhost:8080`, `api.com/v1`
  - Preserves explicit schemes: `http://site.com` stays as `http://`
  - No more SSL errors on local IPs - automatically uses correct protocol
  - Handles private IP ranges: 10.x, 192.168.x, 172.16-31.x, 127.x, 169.254.x
  - 29/29 test cases passing for various URL formats

### Added
- **Debug Flag** (`--debug`)
  - Clean output by default (user-friendly)
  - Verbose logging only when explicitly requested
  - Shows RCE validation details, response previews, digest extraction
  - Helpful for troubleshooting and understanding exploit flow
  
- **Enhanced Validation**
  - RCE validation now non-blocking (advisory only)
  - Scanner continues exploitation even if validation fails
  - Prevents false negatives from strict validation
  - Uses `echo $((41*271))` → 11111 marker in X-Action-Redirect header

### Fixed
- **URL Handling**
  - Fixed URL corruption bugs ("scanning..." error)
  - Proper urljoin usage throughout codebase
  - Eliminated relative URL errors
  
- **Variable Name Typos**
  - Fixed `Noneresult` → `None` causing NameError
  - Code cleanup and consistency improvements
  
- **Debug Output Spam**
  - Removed excessive debug prints cluttering output
  - All debug messages now respect `--debug` flag
  - Clean, professional output by default

### Technical Details
- Method 3 payload structure matches msanft's PoC exactly
- Sends to base URL first (most reliable approach)
- Only tries alternative endpoints if Method 3 fails
- Improved digest extraction from NEXT_REDIRECT errors

## [2.3.0] - 2025-12-06

### Added - Advanced Detection & Evasion Capabilities
- **X-Action-Redirect Header Detection** (Critical Feature)
  - Definitive RCE proof detection via header reflection
  - Detects `/login?a=11111` pattern (math operation result)
  - 100 confidence points in scoring system
  - Based on Assetnote research methodology
  
- **Redirect Following Logic**
  - Automatically follows same-host redirects
  - Tests root path first, then redirect destination
  - Cross-origin redirects are not followed (security measure)
  - Configurable with `--follow-redirects` / `--no-follow-redirects`
  - Improves coverage for sites with language redirects (e.g., `/` → `/en/`)
  
- **WAF Bypass Mode**
  - `--waf-bypass` flag to evade Web Application Firewalls
  - Prepends random junk data to multipart request body
  - Configurable size with `--waf-bypass-size` (default: 128KB)
  - Automatically increases timeout to 20 seconds
  - Effective against content-based WAF rules
  - Random parameter names to avoid detection
  
- **Vercel WAF Bypass**
  - `--vercel-waf-bypass` flag for Vercel-specific protection
  - Alternative payload structure with escaped dollar signs
  - Additional form field for signature bypass
  - Targets Vercel-specific WAF parsing behavior
  
- **Windows Target Support**
  - `--windows` flag for Windows-based Next.js apps
  - Switches from Unix shell to PowerShell payloads
  - Command format: `powershell -c "command"`
  - Automatically adjusts exploit syntax
  - Compatible with Windows Server environments
  
- **Mitigation Detection & Filtering**
  - Automatically detects Vercel/Netlify mitigations
  - Checks for `Server: vercel`, `Server: netlify` headers
  - Detects `Netlify-Vary` header presence
  - Filters false positives from mitigated hosts
  - Reduces noise in scan results

### Enhanced
- **Detection System**
  - Added X-Action-Redirect to scoring system (100 points)
  - Improved REACT2SHELL_PROBE with mitigation checks
  - Enhanced error-based detection accuracy
  - Better false positive filtering
  
- **Exploitation**
  - Updated `_exploitMethod2()` with Windows support
  - Added WAF bypass junk data injection
  - Vercel-specific payload structure
  - Increased timeout for WAF bypass mode
  
- **Documentation**
  - Comprehensive advanced features section in README
  - New command reference table with all flags
  - Usage examples for WAF bypass, Windows mode
  - Mitigation detection explanation
  - Updated scoring system table
  
- **Help Menu**
  - Added "Advanced Features" examples section
  - New "Advanced Options" argument group
  - Updated feature list with new capabilities
  - Configuration display for advanced modes

### Technical
- New utility functions: `generate_junk_data()`, `resolve_redirects()`, `is_mitigated_host()`
- RscScanner class expanded with 5 new parameters
- MassScanner class updated for parameter pass-through
- Main function enhanced with configuration display
- All tests passing (15/15) - full backward compatibility maintained

### Credits
- Inspired by Assetnote's react2shell-scanner research
- X-Action-Redirect technique from @xEHLE_
- Community contributions to CVE-2025-55182 analysis

## [2.2.0] - 2025-12-06

### Added
- **Nuclei Template Integration**
  - Comprehensive `nuclei-template.yaml` for ProjectDiscovery Nuclei
  - 5 request layers (passive, active, REACT2SHELL_PROBE, endpoint testing)
  - Multi-matcher logic with confidence levels (high, medium, low)
  - 7 detection matchers:
    - react2shell-probe-confirmed (high confidence)
    - rsc-multiple-indicators (high confidence)
    - rsc-content-type (medium confidence)
    - middleware-headers-present (medium confidence)
    - shodan-indicators (medium confidence)
    - error-based-detection (medium confidence)
    - flight-protocol-patterns (informational)
  - Comprehensive extractors (version, headers, digest, patterns)
  - Template validated with Nuclei v3.4.7
  - Ready for submission to nuclei-templates repository
- **Author Credits Section**
  - Beautiful credits display in argparse help menu
  - Suman Roy (@sumanrox) attribution with GitHub and website
  - Research credits for contributors
  - Enhanced visual formatting with ANSI colors
  - Tool repository links
- **Documentation**
  - Dedicated Nuclei Integration section in README
  - Usage examples for Nuclei scanning
  - ProjectDiscovery workflow integration guide
  - Template submission instructions
  - Template structure and matcher explanations

### Enhanced
- Help menu now includes author credits with visual hierarchy
- README acknowledgments section with full attribution
- Professional presentation suitable for community submission

## [2.1.0] - 2025-12-06

### Added
- **Enhanced Detection Methods** (Based on security research)
  - REACT2SHELL_PROBE benign marker detection (no OS command execution)
  - `__NEXT_DATA__` runtime marker fingerprinting
  - Shodan-identified headers detection:
    - x-nextjs-prerender (30 points)
    - x-nextjs-stale-time (25 points)
    - x-middleware-rewrite (40 points - critical)
    - x-middleware-subrequest (50 points - exploit condition)
  - Enhanced Vary header analysis:
    - Vary: RSC (35 points)
    - Vary: Next-Router-State-Tree (30 points)
    - Vary: Next-Router-Prefetch (20 points)
- **Colorized Help Menu**
  - ANSI color coding for improved readability
  - Color-coded sections (examples in cyan, warnings in yellow, CVE info in red)
  - Enhanced visual hierarchy with emoji indicators
  - Shodan query examples in help text
- **Documentation Updates**
  - Real-world attack surface analysis (Reddit research)
  - Shodan query narrowing methodology (756K → 350 hosts)
  - Exploit condition requirements
  - REACT2SHELL_PROBE detection explanation
  - Research credits and acknowledgments

### Enhanced
- Passive scanning now includes 15+ detection indicators (up from 9)
- Error-based detection uses benign probe instead of direct exploitation
- Detection confidence scoring updated with new indicators
- README with comprehensive research findings
- Help menu readability with colors and better organization

### Security
- Benign detection probe eliminates OS command execution during scanning
- Safer for automated/mass scanning operations
- Based on peer-reviewed research methodologies

### References
- Security research community - Laboratory and detection methods
- Reddit security community - Real-world attack surface analysis
- Shodan - Attack surface enumeration

## [2.0.0] - 2025-12-06

### Added
- Interactive shell mode for single and mass scanning (`-sh` flag)
- Dual exploit methods with intelligent fallback
  - Primary: Function constructor injection
  - Fallback: `__proto__` pollution with `_response._prefix`
- Enhanced detection capabilities (9+ indicators)
  - Error-based detection with payload injection
  - Flight Protocol pattern recognition
  - Next.js build artifact detection
  - Version extraction from headers
- Multi-target management in interactive shell
  - Live vulnerability discovery updates
  - Target switching with `switch` command
  - Real-time background scanning
- Configurable thread count (`--threads` flag)
- Single URL scanning support (`--url` flag)
- Beautiful test statistics output
- Comprehensive unit test suite (15 tests)

### Enhanced
- Detection scoring system with weighted confidence
- Endpoint testing with error analysis
- State management for resume capability
- URL parsing and normalization
- Progress tracking and reporting

### Fixed
- Thread safety in state management
- Clean target filtering in mass shell mode
- Resume functionality with partial scans

## [1.0.0] - 2025-12-05

### Added
- Initial release
- Mass scanning with concurrent processing
- Smart URL parsing and normalization
- Resumable/pauseable scans with state management
- Command execution on vulnerable targets
- Beautiful console output with color coding
- Progress tracking and summary reports
- Comprehensive error handling
- Automatic reporting to file

### Features
- Passive detection (Content-Type, patterns)
- Active fingerprinting (RSC headers)
- Endpoint vulnerability checking
- Multi-threaded scanning (configurable workers)
- Session management with retry logic
- State persistence for long scans

---

## Version Numbering

RSC Hunter follows semantic versioning:

- **Major version** (X.0.0): Breaking changes, major architecture updates
- **Minor version** (0.X.0): New features, enhancements (backward compatible)
- **Patch version** (0.0.X): Bug fixes, documentation updates

## Upgrade Guide

### From 1.x to 2.x

No breaking changes for basic usage. New features are additive:

```bash
# Old usage still works
python3 rschunter.py targets.txt

# New features available
python3 rschunter.py targets.txt -sh --threads 20
python3 rschunter.py --url https://example.com -sh
```

## Links

- [GitHub Repository](https://github.com/YOUR_USERNAME/rschunter)
- [Issue Tracker](https://github.com/YOUR_USERNAME/rschunter/issues)
- [Releases](https://github.com/YOUR_USERNAME/rschunter/releases)
- [Contributing Guide](CONTRIBUTING.md)
