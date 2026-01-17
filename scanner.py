#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import re
import time

class WebVulnerabilityScanner:
    def __init__(self, url):
        self.url = url if url.startswith('http') else f'http://{url}'
        self.vulnerabilities = []
        self.risk_score = 0
        
    def scan(self):
        print(f"\n[*] Scanning {self.url}...")
        print("=" * 60)
        
        self.check_headers()
        self.check_forms()
        self.check_ssl()
        self.check_common_files()
        self.check_sqli()
        self.check_memory_leaks()
        self.check_code_quality()
        
        self.generate_report()
    
    def check_headers(self):
        try:
            r = requests.get(self.url, timeout=5)
            headers = r.headers
            
            if 'X-Frame-Options' not in headers:
                self.add_vuln("HIGH", "Missing X-Frame-Options header", "Clickjacking vulnerability")
            
            if 'X-Content-Type-Options' not in headers:
                self.add_vuln("MEDIUM", "Missing X-Content-Type-Options", "MIME sniffing possible")
            
            if 'Strict-Transport-Security' not in headers and self.url.startswith('https'):
                self.add_vuln("MEDIUM", "Missing HSTS header", "Man-in-the-middle attacks possible")
            
            if 'Content-Security-Policy' not in headers:
                self.add_vuln("MEDIUM", "Missing CSP header", "XSS attacks easier")
            
            if 'Server' in headers:
                self.add_vuln("LOW", f"Server header exposed: {headers['Server']}", "Information disclosure")
                
        except Exception as e:
            self.add_vuln("ERROR", "Connection failed", str(e))
    
    def check_forms(self):
        try:
            r = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                if form.get('method', '').lower() == 'get':
                    self.add_vuln("LOW", "Form using GET method", "Sensitive data in URL")
                
                if not form.find('input', {'name': re.compile('csrf|token', re.I)}):
                    self.add_vuln("HIGH", "Form without CSRF token", "CSRF attacks possible")
                    
        except Exception as e:
            pass
    
    def check_ssl(self):
        if not self.url.startswith('https'):
            self.add_vuln("HIGH", "No HTTPS", "Unencrypted communication")
    
    def check_common_files(self):
        common_files = ['.git/config', 'phpinfo.php', '.env', 'config.php', 'wp-config.php', '.DS_Store', 'backup.sql']
        
        for file in common_files:
            try:
                test_url = urljoin(self.url, file)
                r = requests.get(test_url, timeout=3)
                if r.status_code == 200:
                    self.add_vuln("CRITICAL", f"Exposed file: {file}", "Sensitive information leak")
            except:
                pass
    
    def check_sqli(self):
        """SQL Injection detection using error-based and time-based techniques"""
        try:
            r = requests.get(self.url, timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            # Find all links with parameters
            links = soup.find_all('a', href=True)
            test_params = []
            
            for link in links[:10]:  # Limit to first 10 links
                parsed = urlparse(urljoin(self.url, link['href']))
                if parsed.query:
                    test_params.append(urljoin(self.url, link['href']))
            
            # SQL injection payloads
            sqli_payloads = ["'", "1' OR '1'='1", "1' AND '1'='2", "' OR 1=1--", "'; DROP TABLE users--"]
            sql_errors = [
                r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQLSyntaxErrorException",
                r"PostgreSQL.*ERROR", r"Warning.*pg_.*", r"valid PostgreSQL result",
                r"SQLite.*error", r"SQLITE_ERROR", r"sqlite3.OperationalError",
                r"ORA-[0-9]{5}", r"Oracle error", r"Microsoft SQL Server",
                r"ODBC SQL Server Driver", r"SQLServer JDBC Driver"
            ]
            
            for test_url in test_params[:5]:  # Test first 5 URLs
                parsed = urlparse(test_url)
                params = parse_qs(parsed.query)
                
                for param in params:
                    for payload in sqli_payloads[:3]:  # Test 3 payloads per param
                        try:
                            test_params_dict = params.copy()
                            test_params_dict[param] = payload
                            
                            test_response = requests.get(
                                f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                params=test_params_dict,
                                timeout=3
                            )
                            
                            # Check for SQL errors
                            for error_pattern in sql_errors:
                                if re.search(error_pattern, test_response.text, re.I):
                                    self.add_vuln("CRITICAL", f"SQL Injection in parameter: {param}", 
                                                f"Payload '{payload}' triggered SQL error")
                                    return
                            
                            # Time-based detection
                            time_payload = "1' AND SLEEP(3)--"
                            start = time.time()
                            requests.get(
                                f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                                params={param: time_payload},
                                timeout=5
                            )
                            elapsed = time.time() - start
                            
                            if elapsed > 2.5:
                                self.add_vuln("CRITICAL", f"Time-based SQL Injection in: {param}",
                                            "Database delay detected")
                                return
                                
                        except requests.Timeout:
                            self.add_vuln("HIGH", f"Possible SQL Injection in: {param}", 
                                        "Request timeout on injection payload")
                            return
                        except:
                            pass
                            
        except Exception as e:
            pass
    
    def check_memory_leaks(self):
        """Detect potential memory leak indicators"""
        try:
            responses = []
            for i in range(3):
                r = requests.get(self.url, timeout=5)
                responses.append(r)
            
            # Check for growing response sizes
            sizes = [len(r.content) for r in responses]
            if sizes[2] > sizes[0] * 1.5:
                self.add_vuln("MEDIUM", "Potential memory leak detected", 
                            "Response size growing significantly across requests")
            
            # Check for session/memory indicators in headers
            for r in responses:
                if 'X-Runtime' in r.headers:
                    try:
                        runtime = float(r.headers['X-Runtime'])
                        if runtime > 2.0:
                            self.add_vuln("LOW", "Slow response time detected", 
                                        f"Server processing time: {runtime}s - possible resource leak")
                    except:
                        pass
                        
        except Exception as e:
            pass
    
    def check_code_quality(self):
        """Analyze code quality issues from response"""
        try:
            r = requests.get(self.url, timeout=5)
            content = r.text.lower()
            
            # Check for debug mode indicators
            debug_patterns = [
                (r'debug\s*=\s*true', "Debug mode enabled"),
                (r'error_reporting\s*\(\s*e_all', "Full error reporting enabled"),
                (r'display_errors\s*=\s*on', "Error display enabled"),
                (r'<pre>.*traceback.*</pre>', "Stack trace exposed"),
                (r'exception.*at line \d+', "Exception details exposed")
            ]
            
            for pattern, desc in debug_patterns:
                if re.search(pattern, content, re.I | re.DOTALL):
                    self.add_vuln("HIGH", "Debug information exposed", desc)
                    break
            
            # Check for commented-out code
            if re.search(r'<!--.*(?:password|key|secret|token).*-->', content, re.I | re.DOTALL):
                self.add_vuln("HIGH", "Sensitive data in HTML comments", "Credentials or keys in comments")
            
            # Check for inline JavaScript with potential issues
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.I)
            for script in scripts[:5]:
                if re.search(r'eval\s*\(', script, re.I):
                    self.add_vuln("MEDIUM", "Dangerous eval() usage detected", "Code injection risk")
                if re.search(r'document\.write\s*\(', script, re.I):
                    self.add_vuln("LOW", "document.write() usage detected", "XSS and performance issues")
                    
        except Exception as e:
            pass
    
    def add_vuln(self, severity, title, description):
        """Add vulnerability and update risk score"""
        self.vulnerabilities.append((severity, title, description))
        score_map = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "ERROR": 0}
        self.risk_score += score_map.get(severity, 0)
    
    def generate_report(self):
        print("\n[+] VULNERABILITY REPORT")
        print("=" * 60)
        
        if not self.vulnerabilities:
            print("\n✓ No vulnerabilities detected!")
            print(f"\n🛡️  Risk Score: 0/100 (SECURE)")
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
        
        # Risk assessment algorithm
        risk_level = "LOW"
        risk_color = "\033[92m"  # Green
        
        if self.risk_score >= 50:
            risk_level = "CRITICAL"
            risk_color = "\033[91m"  # Red
        elif self.risk_score >= 30:
            risk_level = "HIGH"
            risk_color = "\033[91m"
        elif self.risk_score >= 15:
            risk_level = "MEDIUM"
            risk_color = "\033[93m"  # Yellow
        
        print(f"\n{risk_color}🛡️  Risk Score: {self.risk_score}/100 ({risk_level})\033[0m")
        
        # Recommendations
        if self.risk_score > 0:
            print("\n[!] RECOMMENDATIONS:")
            if any(v[0] == "CRITICAL" for v in self.vulnerabilities):
                print("  • Address CRITICAL vulnerabilities immediately")
            if any("SQL Injection" in v[1] for v in self.vulnerabilities):
                print("  • Implement parameterized queries and input validation")
            if any("CSRF" in v[1] for v in self.vulnerabilities):
                print("  • Add CSRF tokens to all forms")
            if any("Debug" in v[1] or "error" in v[2].lower() for v in self.vulnerabilities):
                print("  • Disable debug mode in production")
            if not self.url.startswith('https'):
                print("  • Enable HTTPS with valid SSL certificate")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <website-url>")
        sys.exit(1)
    
    scanner = WebVulnerabilityScanner(sys.argv[1])
    scanner.scan()
