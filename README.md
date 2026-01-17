# 🔍 Web Vulnerability Scanner

A lightweight, cross-platform terminal tool that scans websites for common security vulnerabilities and generates detailed reports directly in your terminal.

![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-blue)
![Python](https://img.shields.io/badge/python-3.7%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Features

- 🛡️ **Security Header Analysis** - Detects missing security headers (X-Frame-Options, CSP, HSTS, X-Content-Type-Options)
- 🔐 **Form Security Checks** - Identifies forms without CSRF protection and insecure HTTP methods
- 🔒 **SSL/HTTPS Verification** - Validates encrypted connections
- 📁 **Exposed File Detection** - Scans for common sensitive files (.env, .git, config files)
- 🎨 **Color-Coded Reports** - Easy-to-read severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- ⚡ **Fast & Lightweight** - No heavy dependencies, runs instantly

## 🚀 Quick Start

### Installation

1. Clone the repository:
```bash
git clone https://github.com/v0ttrix/Virus-Detection-Tool.git
cd Virus-Detection-Tool
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Usage

Simply run the scanner with any website URL:

```bash
python scanner.py <website-url>
```

## 📖 Examples

**Scan a website:**
```bash
python scanner.py example.com
```

**Scan with HTTPS:**
```bash
python scanner.py https://mywebsite.com
```

**Sample Output:**
```
[*] Scanning https://example.com...
============================================================

[+] VULNERABILITY REPORT
============================================================

[CRITICAL] Exposed file: .env
  └─ Sensitive information leak

[HIGH] Missing X-Frame-Options header
  └─ Clickjacking vulnerability

[HIGH] Form without CSRF token
  └─ CSRF attacks possible

[MEDIUM] Missing CSP header
  └─ XSS attacks easier

============================================================
Total vulnerabilities found: 4
```

## 🔍 What It Checks

| Check | Description | Severity |
|-------|-------------|----------|
| Security Headers | X-Frame-Options, CSP, HSTS, X-Content-Type-Options | HIGH/MEDIUM |
| CSRF Protection | Validates forms have CSRF tokens | HIGH |
| SSL/HTTPS | Ensures encrypted communication | HIGH |
| Exposed Files | .env, .git/config, phpinfo.php, wp-config.php | CRITICAL |
| Form Methods | Detects insecure GET methods for forms | LOW |

## 💻 System Requirements

- Python 3.7 or higher
- Internet connection
- Works on Linux, Windows, and macOS

## 📦 Dependencies

- `requests` - HTTP library
- `beautifulsoup4` - HTML parsing

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## 📄 License

MIT License - feel free to use this tool for personal or commercial projects.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always obtain permission before scanning websites you don't own.
