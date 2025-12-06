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
