#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re

class WebVulnerabilityScanner:
    def __init__(self, url):
        self.url = url if url.startswith('http') else f'http://{url}'
        self.vulnerabilities = []
        
    def scan(self):
        print(f"\n[*] Scanning {self.url}...")
        print("=" * 60)
        
        self.check_headers()
        self.check_forms()
        self.check_ssl()
        self.check_common_files()
        
        self.generate_report()
    
    def check_headers(self):
        try:
            r = requests.get(self.url, timeout=5)
            headers = r.headers
            
            if 'X-Frame-Options' not in headers:
                self.vulnerabilities.append(("HIGH", "Missing X-Frame-Options header", "Clickjacking vulnerability"))
            
            if 'X-Content-Type-Options' not in headers:
                self.vulnerabilities.append(("MEDIUM", "Missing X-Content-Type-Options", "MIME sniffing possible"))
            
            if 'Strict-Transport-Security' not in headers and self.url.startswith('https'):
                self.vulnerabilities.append(("MEDIUM", "Missing HSTS header", "Man-in-the-middle attacks possible"))
            
            if 'Content-Security-Policy' not in headers:
                self.vulnerabilities.append(("MEDIUM", "Missing CSP header", "XSS attacks easier"))
                
        except Exception as e:
            self.vulnerabilities.append(("ERROR", "Connection failed", str(e)))
    
    def check_forms(self):
        try:
            r = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                if form.get('method', '').lower() == 'get':
                    self.vulnerabilities.append(("LOW", "Form using GET method", "Sensitive data in URL"))
                
                if not form.find('input', {'name': re.compile('csrf|token', re.I)}):
                    self.vulnerabilities.append(("HIGH", "Form without CSRF token", "CSRF attacks possible"))
                    
        except Exception as e:
            pass
    
    def check_ssl(self):
        if not self.url.startswith('https'):
            self.vulnerabilities.append(("HIGH", "No HTTPS", "Unencrypted communication"))
    
    def check_common_files(self):
        common_files = ['.git/config', 'phpinfo.php', '.env', 'config.php', 'wp-config.php']
        
        for file in common_files:
            try:
                test_url = urljoin(self.url, file)
                r = requests.get(test_url, timeout=3)
                if r.status_code == 200:
                    self.vulnerabilities.append(("CRITICAL", f"Exposed file: {file}", "Sensitive information leak"))
            except:
                pass
    
    def generate_report(self):
        print("\n[+] VULNERABILITY REPORT")
        print("=" * 60)
        
        if not self.vulnerabilities:
            print("\n✓ No vulnerabilities detected!")
            return
        
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "ERROR": 4}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x[0], 5))
        
        for severity, title, description in sorted_vulns:
            color = {
                "CRITICAL": "\033[91m",
                "HIGH": "\033[91m",
                "MEDIUM": "\033[93m",
                "LOW": "\033[94m",
                "ERROR": "\033[90m"
            }.get(severity, "")
            reset = "\033[0m"
            
            print(f"\n{color}[{severity}]{reset} {title}")
            print(f"  └─ {description}")
        
        print("\n" + "=" * 60)
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <website-url>")
        sys.exit(1)
    
    scanner = WebVulnerabilityScanner(sys.argv[1])
    scanner.scan()
