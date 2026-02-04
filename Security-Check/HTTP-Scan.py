import socks
import socket
import ssl
import sys


def setup_tor_connection():
    """Configure socket to use Tor SOCKS proxy"""
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    socket.socket = socks.socksocket


def grab_banner_http(host, port=80, timeout=30):
    """Grab banner from HTTP service via Tor"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send HTTP HEAD request
        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        sock.send(request.encode())

        # Receive response
        banner = sock.recv(4096).decode('utf-8', errors='ignore')
        sock.close()

        return banner
    except Exception as e:
        return f"Error: {str(e)}"


def grab_banner_https(host, port=443, timeout=30):
    """Grab banner from HTTPS service via Tor"""
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.connect((host, port))

        # Send HTTP HEAD request
        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        ssl_sock.send(request.encode())

        # Receive response
        banner = ssl_sock.recv(4096).decode('utf-8', errors='ignore')
        ssl_sock.close()

        return banner
    except Exception as e:
        return f"Error: {str(e)}"


def extract_server_info(banner):
    """Extract server version from banner"""
    lines = banner.split('\n')
    server_info = []

    for line in lines:
        lower_line = line.lower()
        if any(header in lower_line for header in ['server:', 'x-powered-by:', 'x-aspnet-version:']):
            server_info.append(line.strip())

    return server_info if server_info else ["Server header not found"]


def main():
    if len(sys.argv) < 2:
        print("Usage: python onion_banner_grab.py <onion_address>")
        print("Example: python onion_banner_grab.py example.onion")
        print("\nNote: Requires Tor to be running on 127.0.0.1:9050")
        sys.exit(1)

    host = sys.argv[1]

    if not host.endswith('.onion'):
        print("[!] Warning: Target doesn't appear to be a .onion address")

    print(f"\n[*] Banner Grabbing for: {host}")
    print("[*] Connecting through Tor...")
    print("=" * 60)

    # Setup Tor connection
    setup_tor_connection()

    # Check port 80
    print(f"\n[+] Checking HTTP (port 80)...")
    http_banner = grab_banner_http(host, 80)
    server_info = extract_server_info(http_banner)
    for info in server_info:
        print(f"    {info}")
    print(f"\nFull response:\n{http_banner[:500]}")

    # Check port 443
    print(f"\n[+] Checking HTTPS (port 443)...")
    https_banner = grab_banner_https(host, 443)
    server_info = extract_server_info(https_banner)
    for info in server_info:
        print(f"    {info}")
    print(f"\nFull response:\n{https_banner[:500]}")


if __name__ == "__main__":
    main()