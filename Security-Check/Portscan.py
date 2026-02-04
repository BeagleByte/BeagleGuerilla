#!/usr/bin/env python3
"""
Tor Port Scanner - Scans ports through Tor network
Requires: pip install PySocks
Also requires Tor to be running (default: localhost:9050)
"""

import socket
import socks
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Tor SOCKS proxy configuration
TOR_PROXY_HOST = '127.0.0.1'
TOR_PROXY_PORT = 9050

# Common ports to scan (customize as needed)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3306, 3389, 5000, 5432, 5900, 8080, 8443, 9050, 9051, 9053, 27017
]

def check_tor_connection():
    """Verify Tor is running and accessible"""
    try:
        socks.set_default_proxy(socks.SOCKS5, TOR_PROXY_HOST, TOR_PROXY_PORT)
        socket.socket = socks.socksocket

        # Test connection by checking IP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("check.torproject.org", 80))
        s.close()
        return True
    except Exception as e:
        print(f"[!] Error connecting to Tor: {e}")
        print(f"[!] Make sure Tor is running on {TOR_PROXY_HOST}:{TOR_PROXY_PORT}")
        return False

def get_tor_ip():
    """Get current Tor exit node IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("api.ipify.org", 80))
        s.send(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\n\r\n")
        response = s.recv(1024).decode()
        s.close()
        ip = response.split('\r\n\r\n')[1].strip()
        return ip
    except:
        return "Unknown"

def scan_port(target, port, timeout=3):
    """Scan a single port through Tor"""
    try:
        # Create socket with SOCKS proxy
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, TOR_PROXY_HOST, TOR_PROXY_PORT)
        s.settimeout(timeout)

        # Attempt connection
        result = s.connect_ex((target, port))
        s.close()

        if result == 0:
            return port, True
        else:
            return port, False
    except Exception as e:
        return port, False

def scan_ports(target, ports, max_threads=10):
    """Scan multiple ports with threading"""
    print(f"\n[*] Starting scan of {target}")
    print(f"[*] Scanning {len(ports)} ports through Tor")
    print(f"[*] Using {max_threads} threads")
    print(f"[*] Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    open_ports = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all port scan tasks
        future_to_port = {
            executor.submit(scan_port, target, port): port
            for port in ports
        }

        # Process completed scans
        completed = 0
        for future in as_completed(future_to_port):
            port, is_open = future.result()
            completed += 1

            if is_open:
                print(f"[+] Port {port:5d}/tcp  OPEN")
                open_ports.append(port)

            # Progress indicator
            if completed % 10 == 0 or completed == len(ports):
                sys.stdout.write(f"\r[*] Progress: {completed}/{len(ports)} ports scanned")
                sys.stdout.flush()

    print("\n")
    return open_ports

def is_onion_address(address):
    """Check if address is a .onion domain"""
    return address.lower().endswith('.onion')

def main():
    """Main function"""
    print("="*60)
    print("Tor Port Scanner")
    print("="*60)

    # Check Tor connection
    print("\n[*] Checking Tor connection...")
    if not check_tor_connection():
        sys.exit(1)

    print("[+] Tor connection established")

    # Get target first to determine if it's onion
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("\n[?] Enter target hostname or IP (.onion supported): ").strip()

    if not target:
        print("[!] No target specified")
        sys.exit(1)

    # Check if scanning onion service
    if is_onion_address(target):
        print(f"[+] Detected onion address: {target}")
        print("[+] Traffic will remain within Tor network (no exit node)")
    else:
        tor_ip = get_tor_ip()
        print(f"[+] Current Tor exit IP: {tor_ip}")
        print(f"[+] Scanning clearnet target: {target}")



    # Get port range
    print("\n[?] Port scan options:")
    print("    1. Common ports (21, 22, 23, 25, 53, 80, etc.)")
    print("    2. Custom port range")
    print("    3. Single port")

    choice = input("[?] Choose option (1/2/3): ").strip()

    if choice == '1':
        ports = COMMON_PORTS
    elif choice == '2':
        start = int(input("[?] Start port: "))
        end = int(input("[?] End port: "))
        ports = list(range(start, end + 1))
    elif choice == '3':
        port = int(input("[?] Port number: "))
        ports = [port]
    else:
        print("[!] Invalid choice")
        sys.exit(1)

    # Perform scan
    open_ports = scan_ports(target, ports)

    # Summary
    print("="*60)
    print("Scan Summary")
    print("="*60)
    print(f"Target: {target}")
    print(f"Scanned: {len(ports)} ports")
    print(f"Open: {len(open_ports)} ports")

    if open_ports:
        print(f"\nOpen ports: {', '.join(map(str, sorted(open_ports)))}")
    else:
        print("\nNo open ports found")

    print(f"\nScan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)