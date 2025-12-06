# RSC Hunter

A powerful, multi-threaded scanner and exploit tool for React Server Component (RSC) vulnerabilities. This tool is designed to identify and exploit RCE vulnerabilities in RSC implementations, supporting various bypass techniques and strategies.

> **Note**: Due to the enormous complexity of maintaining a full interactive shell and other heavy features, we have decided to remove them. This project now focuses strictly on edge-case handling, behavioral analysis, and reliable detection of RSC vulnerabilities. We believe a simpler, more focused tool serves the community better.

## Features

*   **Multi-Strategy Scanning**: Automatically tries multiple exploit strategies (Assetnote, Msanft, Split Payload).
*   **Multi-Threading**: Scans large lists of targets quickly using concurrent threads.
*   **WAF Bypass**: Includes junk data injection to evade Web Application Firewalls.
*   **Vercel Bypass**: Specific strategy to bypass Vercel's security protections.
*   **False Positive Reduction**: Advanced filtering to ignore reflected source code and ensure accurate results.
*   **CSV Export**: Save vulnerable hosts and their details to a CSV file for reporting.
*   **Proxy Support**: Route traffic through HTTP/HTTPS proxies (e.g., Burp Suite).

## Installation

1.  **Prerequisites**: Python 3.6+
2.  **Install Dependencies**:
    ```bash
    pip install requests
    ```

## Usage Guide

### Basic Scan
Scan a single URL to check for vulnerabilities.
```bash
python3 rschunter.py -u https://example.com
```

### Bulk Scan
Scan a list of URLs from a file (one URL per line).
```bash
python3 rschunter.py -l targets.txt
```

### Execute Custom Commands
Execute a specific command on vulnerable targets (default is `id`).
```bash
python3 rschunter.py -u https://example.com -c "whoami"
```

### Save Results
Save the list of vulnerable hosts to a CSV file.
```bash
python3 rschunter.py -l targets.txt --save vulnerable.csv
```

### WAF Bypass
Enable junk data injection to bypass WAFs.
```bash
python3 rschunter.py -u https://example.com --waf-bypass
```

### Vercel Targets
Enable the Vercel-specific bypass strategy.
```bash
python3 rschunter.py -u https://example.com --vercel
```

### Using a Proxy
Route traffic through a proxy (useful for debugging with Burp Suite).
```bash
python3 rschunter.py -u https://example.com --proxy http://127.0.0.1:8080
```

## Advanced Options

| Argument | Description |
| :--- | :--- |
| `-u, --url` | Target URL to scan. |
| `-l, --list` | Path to a file containing a list of targets. |
| `-c, --cmd` | Command to execute (default: `id`). |
| `-t, --threads` | Number of concurrent threads (default: 10). |
| `--check` | Safe mode: Checks for vulnerability without running custom commands. |
| `--waf-bypass-size` | Size of junk data in KB (default: 128). |
| `-v, --verbose` | Enable verbose output for debugging. |

## Disclaimer
This tool is for educational and authorized testing purposes only. Usage of this tool for attacking targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
