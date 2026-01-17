# Web Vulnerability Scanner

A cross-platform terminal tool for scanning websites and generating vulnerability reports.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py <website-url>
```

### Examples

```bash
python scanner.py example.com
python scanner.py https://mywebsite.com
```

## Features

- Security header analysis (X-Frame-Options, CSP, HSTS, etc.)
- Form security checks (CSRF tokens, HTTP methods)
- SSL/HTTPS verification
- Common exposed file detection
- Color-coded severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Terminal-based vulnerability report

## Compatibility

- Linux
- Windows
- macOS

## License

MIT
