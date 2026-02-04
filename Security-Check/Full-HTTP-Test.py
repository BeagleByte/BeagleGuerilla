#!/usr/bin/env python3
"""
Comprehensive security tester for Tor hidden services
Tests for information disclosure, security headers, and common vulnerabilities
"""

import socks
import socket
import ssl
import sys
import json
from urllib.parse import urljoin


def setup_tor():
    """Configure socket to use Tor SOCKS proxy"""
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    socket.socket = socks.socksocket


def send_request(host, port, method="GET", path="/", headers=None, timeout=30):
    """Send HTTP request and return response"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if port == 443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))

        # Build request
        request_headers = headers or {}
        request_headers.setdefault('Host', host)
        request_headers.setdefault('User-Agent', 'SecurityTester/1.0')
        request_headers.setdefault('Connection', 'close')

        request = f"{method} {path} HTTP/1.1\r\n"
        for key, value in request_headers.items():
            request += f"{key}: {value}\r\n"
        request += "\r\n"

        sock.send(request.encode())
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()
        return response.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error: {str(e)}"


def parse_response(response):
    """Parse HTTP response into headers and body"""
    try:
        parts = response.split('\r\n\r\n', 1)
        header_part = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_part.split('\r\n')
        status_line = lines[0]
        headers = {}

        for line in lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.lower()] = value

        return status_line, headers, body
    except:
        return None, {}, ""


def test_information_disclosure(host, port=80):
    """Test for information disclosure vulnerabilities"""
    print(f"\n{'=' * 70}")
    print(f"INFORMATION DISCLOSURE TESTS - {host}:{port}")
    print(f"{'=' * 70}\n")

    findings = []

    # Test 1: Check Server header
    print("[*] Test 1: Checking Server header...")
    response = send_request(host, port)
    status, headers, body = parse_response(response)

    server_header = headers.get('server', '')
    if server_header:
        if any(keyword in server_header.lower() for keyword in ['werkzeug', 'python', 'flask', 'waitress', 'gunicorn']):
            findings.append({
                'severity': 'MEDIUM',
                'issue': 'Server version disclosure',
                'detail': f"Server header reveals: {server_header}",
                'recommendation': 'Remove or obfuscate Server header'
            })
            print(f"  [!] FOUND: Server header discloses version: {server_header}")
        else:
            print(f"  [+] Server header present but generic: {server_header}")
    else:
        print("  [+] PASS: No Server header found")

    # Test 2: Check X-Powered-By
    print("\n[*] Test 2: Checking X-Powered-By header...")
    powered_by = headers.get('x-powered-by', '')
    if powered_by:
        findings.append({
            'severity': 'LOW',
            'issue': 'X-Powered-By header disclosure',
            'detail': f"X-Powered-By: {powered_by}",
            'recommendation': 'Remove X-Powered-By header'
        })
        print(f"  [!] FOUND: X-Powered-By: {powered_by}")
    else:
        print("  [+] PASS: No X-Powered-By header")

    # Test 3: Check for other identifying headers
    print("\n[*] Test 3: Checking for identifying headers...")
    identifying_headers = ['x-aspnet-version', 'x-aspnetmvc-version', 'x-runtime',
                           'x-version', 'x-generator']
    for header in identifying_headers:
        if header in headers:
            findings.append({
                'severity': 'LOW',
                'issue': f'Identifying header: {header}',
                'detail': f"{header}: {headers[header]}",
                'recommendation': f'Remove {header} header'
            })
            print(f"  [!] FOUND: {header}: {headers[header]}")

    if not any(h in headers for h in identifying_headers):
        print("  [+] PASS: No identifying headers found")

    # Test 4: Error page disclosure
    print("\n[*] Test 4: Testing error page disclosure...")
    error_response = send_request(host, port, path='/nonexistent-page-test-12345')
    error_status, error_headers, error_body = parse_response(error_response)

    if any(keyword in error_body.lower() for keyword in
           ['traceback', 'werkzeug', 'flask', 'python', 'exception', 'file "/']):
        findings.append({
            'severity': 'HIGH',
            'issue': 'Error page information disclosure',
            'detail': 'Error pages reveal stack traces or system paths',
            'recommendation': 'Implement custom error pages and disable debug mode'
        })
        print("  [!] FOUND: Error page reveals sensitive information")
        print(f"      Snippet: {error_body[:200]}...")
    else:
        print("  [+] PASS: Error pages don't reveal sensitive info")

    # Test 5: Check HTTP methods
    print("\n[*] Test 5: Testing HTTP methods...")
    methods_to_test = ['OPTIONS', 'TRACE', 'PUT', 'DELETE', 'PATCH']
    dangerous_methods = []

    for method in methods_to_test:
        method_response = send_request(host, port, method=method)
        method_status, _, _ = parse_response(method_response)
        if method_status and '200' in method_status:
            dangerous_methods.append(method)

    if dangerous_methods:
        findings.append({
            'severity': 'MEDIUM',
            'issue': 'Dangerous HTTP methods enabled',
            'detail': f"Methods allowed: {', '.join(dangerous_methods)}",
            'recommendation': 'Disable unnecessary HTTP methods'
        })
        print(f"  [!] FOUND: Dangerous methods enabled: {', '.join(dangerous_methods)}")
    else:
        print("  [+] PASS: No dangerous methods enabled")

    # Test 6: Directory listing
    print("\n[*] Test 6: Testing for directory listing...")
    dir_response = send_request(host, port, path='/')
    _, _, dir_body = parse_response(dir_response)

    if 'index of' in dir_body.lower() or '<title>directory listing' in dir_body.lower():
        findings.append({
            'severity': 'HIGH',
            'issue': 'Directory listing enabled',
            'detail': 'Directory listing exposes file structure',
            'recommendation': 'Disable directory listing'
        })
        print("  [!] FOUND: Directory listing may be enabled")
    else:
        print("  [+] PASS: No directory listing detected")

    return findings, headers


def test_security_headers(headers):
    """Test for security headers"""
    print(f"\n{'=' * 70}")
    print("SECURITY HEADERS TESTS")
    print(f"{'=' * 70}\n")

    findings = []

    security_headers = {
        'x-content-type-options': {
            'expected': 'nosniff',
            'severity': 'MEDIUM',
            'description': 'Prevents MIME type sniffing'
        },
        'x-frame-options': {
            'expected': ['DENY', 'SAMEORIGIN'],
            'severity': 'MEDIUM',
            'description': 'Prevents clickjacking attacks'
        },
        'x-xss-protection': {
            'expected': '1',
            'severity': 'LOW',
            'description': 'Enables XSS filter (legacy)'
        },
        'strict-transport-security': {
            'expected': 'max-age',
            'severity': 'HIGH',
            'description': 'Enforces HTTPS connections'
        },
        'content-security-policy': {
            'expected': None,
            'severity': 'HIGH',
            'description': 'Prevents XSS and injection attacks'
        },
        'referrer-policy': {
            'expected': None,
            'severity': 'LOW',
            'description': 'Controls referrer information'
        }
    }

    for header, config in security_headers.items():
        value = headers.get(header, '')

        if not value:
            findings.append({
                'severity': config['severity'],
                'issue': f'Missing security header: {header}',
                'detail': config['description'],
                'recommendation': f'Add {header} header'
            })
            print(f"  [!] MISSING: {header}")
            print(f"      Purpose: {config['description']}")
        else:
            expected = config['expected']
            if expected:
                if isinstance(expected, list):
                    if not any(exp.lower() in value.lower() for exp in expected):
                        print(f"  [~] WEAK: {header}: {value}")
                    else:
                        print(f"  [+] FOUND: {header}: {value}")
                elif expected.lower() not in value.lower():
                    print(f"  [~] WEAK: {header}: {value}")
                else:
                    print(f"  [+] FOUND: {header}: {value}")
            else:
                print(f"  [+] FOUND: {header}: {value}")

    return findings


def test_common_vulnerabilities(host, port=80):
    """Test for common web vulnerabilities"""
    print(f"\n{'=' * 70}")
    print("COMMON VULNERABILITY TESTS")
    print(f"{'=' * 70}\n")

    findings = []

    # Test 1: .git directory exposure
    print("[*] Test 1: Checking for .git directory exposure...")
    git_response = send_request(host, port, path='/.git/config')
    git_status, _, git_body = parse_response(git_response)

    if git_status and '200' in git_status:
        findings.append({
            'severity': 'CRITICAL',
            'issue': '.git directory exposed',
            'detail': 'Source code may be accessible',
            'recommendation': 'Block access to .git directory'
        })
        print("  [!] CRITICAL: .git directory is accessible!")
    else:
        print("  [+] PASS: .git directory not accessible")

    # Test 2: Common sensitive files
    print("\n[*] Test 2: Checking for sensitive files...")
    sensitive_files = [
        '/.env', '/config.py', '/settings.py', '/.DS_Store',
        '/backup.sql', '/database.sql', '/config.json', '/secrets.json'
    ]

    for file_path in sensitive_files:
        file_response = send_request(host, port, path=file_path)
        file_status, _, _ = parse_response(file_response)

        if file_status and '200' in file_status:
            findings.append({
                'severity': 'HIGH',
                'issue': f'Sensitive file exposed: {file_path}',
                'detail': 'Configuration or backup file accessible',
                'recommendation': f'Block access to {file_path}'
            })
            print(f"  [!] FOUND: {file_path} is accessible")

    if not any('Sensitive file exposed' in f['issue'] for f in findings):
        print("  [+] PASS: No sensitive files found")

    # Test 3: robots.txt analysis
    print("\n[*] Test 3: Analyzing robots.txt...")
    robots_response = send_request(host, port, path='/robots.txt')
    robots_status, _, robots_body = parse_response(robots_response)

    if robots_status and '200' in robots_status and 'disallow' in robots_body.lower():
        print("  [i] robots.txt found - Check for sensitive paths:")
        for line in robots_body.split('\n')[:10]:
            if 'disallow' in line.lower():
                print(f"      {line.strip()}")
    else:
        print("  [i] No robots.txt or no disallowed paths")

    return findings


def generate_report(all_findings, headers, host):
    """Generate final security report"""
    print(f"\n{'=' * 70}")
    print("SECURITY ASSESSMENT REPORT")
    print(f"{'=' * 70}\n")
    print(f"Target: {host}")
    print(f"Total findings: {len(all_findings)}\n")

    # Count by severity
    severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for finding in all_findings:
        severity_count[finding['severity']] += 1

    print("Findings by severity:")
    for severity, count in severity_count.items():
        if count > 0:
            print(f"  {severity}: {count}")

    print(f"\n{'=' * 70}")
    print("DETAILED FINDINGS")
    print(f"{'=' * 70}\n")

    for i, finding in enumerate(all_findings, 1):
        print(f"[{i}] {finding['severity']} - {finding['issue']}")
        print(f"    Detail: {finding['detail']}")
        print(f"    Recommendation: {finding['recommendation']}")
        print()

    # Overall security score
    score = 100
    score -= severity_count['CRITICAL'] * 25
    score -= severity_count['HIGH'] * 15
    score -= severity_count['MEDIUM'] * 8
    score -= severity_count['LOW'] * 3
    score = max(0, score)

    print(f"{'=' * 70}")
    print(f"OVERALL SECURITY SCORE: {score}/100")
    print(f"{'=' * 70}\n")

    if score >= 80:
        print("✓ Good security posture")
    elif score >= 60:
        print("⚠ Moderate security - improvements needed")
    else:
        print("✗ Poor security - immediate action required")


def main():
    if len(sys.argv) < 2:
        print("Usage: python security_test.py <onion_address> [port]")
        print("Example: python security_test.py example.onion 80")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80

    print(f"\n{'#' * 70}")
    print(f"# ONION SERVICE SECURITY SCANNER")
    print(f"# Target: {host}:{port}")
    print(f"{'#' * 70}")

    setup_tor()

    all_findings = []

    # Run all tests
    try:
        disclosure_findings, headers = test_information_disclosure(host, port)
        all_findings.extend(disclosure_findings)

        header_findings = test_security_headers(headers)
        all_findings.extend(header_findings)

        vuln_findings = test_common_vulnerabilities(host, port)
        all_findings.extend(vuln_findings)

        generate_report(all_findings, headers, host)

    except Exception as e:
        print(f"\n[!] Error during testing: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()