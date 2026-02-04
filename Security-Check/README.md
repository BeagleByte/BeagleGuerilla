## Security-Check


### Portscan after hidden service with flask backend is running
```
python Portscan.py
============================================================
Tor Port Scanner
============================================================

[*] Checking Tor connection...
[+] Tor connection established

[?] Enter target hostname or IP (.onion supported): example.onion
[+] Detected onion address: example.onion
[+] Traffic will remain within Tor network (no exit node)

[?] Port scan options:
1. Common ports (21, 22, 23, 25, 53, 80, etc.)
2. Custom port range
3. Single port
[?] Choose option (1/2/3): 1

[*] Starting scan of example.onion
[*] Scanning 20 ports through Tor
[*] Using 10 threads
[*] Scan started at 2026-01-20 17:29:14

[+] Port    80/tcp  OPEN
[*] Progress: 20/20 ports scanned

============================================================
Scan Summary
============================================================
Target: example.onion
Scanned: 20 ports
Open: 1 ports

Open ports: 80

Scan completed at 2026-01-20 17:29:18
============================================================
```

## Banner grabbing and versions

```bash
python HTTP-Scan.py example.onion

[*] Banner Grabbing for: example.onion
[*] Connecting through Tor...
============================================================

[+] Checking HTTP (port 80)...
    Server: Werkzeug/3.1.5 Python/3.12.12

Full response:
HTTP/1.1 200 OK
Server: Werkzeug/3.1.5 Python/3.12.12
Date: Wed, 21 Jan 2026 04:05:35 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 678
Connection: close



[+] Checking HTTPS (port 443)...
    Server header not found

```
Server running not on 443 (HTTPS) but on 80 (HTTP). We can see information discloser for the server version which is not ok.

### Mitigation
#### run app.py with waitress

Remove the server version infos in app.py if you run it with waitress instead of flask

### Complete Testing Checklist
#### Run through this checklist:

 - No Server header or generic value only
 - No X-Powered-By header
 - All security headers present (CSP, X-Frame-Options, etc.)
 - Error pages don't leak info (no stack traces)
 - No .git directory accessible
 - No .env or config files accessible 
 - No directory listing enabled 
 - Dangerous HTTP methods disabled (TRACE, OPTIONS with full disclosure)
 - Running as non-root user 
 - Debug mode disabled 
 - Proper file permissions (read-only)
 - Rate limiting implemented (if needed)
 - Input validation on all endpoints 
 - No verbose logging to stdout