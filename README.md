# Web Vulnerability Scanner

A cross-platform terminal tool for scanning websites and generating vulnerability reports.

![Demo](demo.jpg)

## Download

**Linux:** [Download webscan](https://github.com/v0ttrix/Virus-Detection-Tool/releases/latest/download/webscan)

After downloading:
```bash
chmod +x webscan
./webscan <website-url>
```

## Usage

```bash
./webscan example.com
./webscan https://mywebsite.com
```

## Features

- **SQL Injection Detection** - Error-based and time-based SQLi testing
- **Memory Leak Detection** - Identifies potential memory issues and resource leaks
- **Code Quality Analysis** - Detects debug mode, exposed errors, dangerous functions
- **Security Headers** - Analyzes X-Frame-Options, CSP, HSTS, etc.
- **Form Security** - Checks for CSRF tokens and insecure methods
- **SSL/HTTPS Verification** - Ensures encrypted communication
- **Exposed Files Detection** - Scans for .env, config files, backups
- **Risk Scoring Algorithm** - Calculates overall security risk (0-100)
- **Color-coded Severity** - CRITICAL, HIGH, MEDIUM, LOW levels
- **Actionable Recommendations** - Specific fixes for detected issues

## Build from Source

```bash
git clone https://github.com/v0ttrix/Virus-Detection-Tool.git
cd Virus-Detection-Tool
pip install -r requirements.txt
python scanner.py <website-url>
```

## Compatibility

- Linux
- Windows
- macOS

## License

MIT
