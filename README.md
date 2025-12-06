# RSC Hunter (rschunter)

**RSC Hunter** is a high-performance, concurrent vulnerability scanner designed to detect and exploit **CVE-2025-55182** (React Server Components Information Disclosure). It features smart URL parsing, multi-threaded scanning, and built-in command execution capabilities for verified targets.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![CVE](https://img.shields.io/badge/CVE-2025--55182-critical)

## 🚀 Features

- **Mass Scanning**: Concurrent processing for high-speed scanning of thousands of targets.
- **Smart Parsing**: Automatically handles various URL formats (domains, IPs, with/without protocol).
- **Resumable Scans**: Pause and resume scans at any time using state management.
- **Command Execution**: Automatically execute commands on vulnerable targets using the `-exec` flag.
- **Detailed Reporting**: Generates human-readable reports (`rsc-report.txt`) and JSON state files.
- **Beautiful Output**: Color-coded terminal output for easy monitoring.

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/rschunter.git
   cd rschunter
   ```

2. Install dependencies:
   ```bash
   pip3 install requests
   ```

## 🛠 Usage

### Basic Scan
Scan a list of targets from a file:
```bash
python3 rschunter.py targets.txt
```

### Command Execution
Execute a command on every vulnerable target found:
```bash
python3 rschunter.py targets.txt -exec "npm audit fix"
```
*Note: The command runs on the **remote target** via CVE-2025-55182 exploitation.*

### Resume Scan
Resume a previously interrupted scan:
```bash
python3 rschunter.py --resume
```

### Custom Output
Specify a custom report filename:
```bash
python3 rschunter.py targets.txt -o my_report.txt
```

## 📋 Input Format

The input file should contain one target per line. Comments (`#`) and empty lines are ignored.

```text
example.com
https://sub.domain.com
http://192.168.1.1:8080
# This is a comment
test.com/path
```

## 🔍 Detection Logic

RSC Hunter uses a multi-stage detection process:
1. **Passive Scan**: Checks for `text/x-component` Content-Type and Next.js specific global variables (`window.__next_f`).
2. **Active Fingerprint**: Sends requests with `RSC: 1` headers and analyzes `Vary` headers and response bodies.
3. **Endpoint Fuzzing**: Probes common RSC endpoints like `/_next/data` and `/adfa` for information disclosure.

## ⚠️ Disclaimer

This tool is for educational purposes and authorized security testing only. Unauthorized scanning of systems you do not own is illegal. The authors are not responsible for misuse.

## 🤝 Contributing

Contributions are welcome! Please submit a Pull Request.
