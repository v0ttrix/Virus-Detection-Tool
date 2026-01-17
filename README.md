# Web Vulnerability Scanner

A cross-platform terminal tool for scanning websites and generating vulnerability reports.

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

- Security header analysis (X-Frame-Options, CSP, HSTS, etc.)
- Form security checks (CSRF tokens, HTTP methods)
- SSL/HTTPS verification
- Common exposed file detection
- Color-coded severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Terminal-based vulnerability report

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
