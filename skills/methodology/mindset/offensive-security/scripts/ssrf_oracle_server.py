#!/usr/bin/env python3
"""SSRF oracle server — serves individual characters at /pos/N endpoints.
Usage: python3 ssrf_oracle.py <port> [secret_message]
"""
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
SECRET = sys.argv[2] if len(sys.argv) > 2 else "flag{ssrf_data_exfiltration_success}"


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path
        
        if p.startswith("/pos/"):
            try:
                idx = int(p[5:])
                body = SECRET[idx] if 0 <= idx < len(SECRET) else "?"
            except ValueError:
                body = "?"
        elif p == "/full":
            body = SECRET
        elif p == "/len":
            body = str(len(SECRET))
        else:
            body = "OK"
        
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())
        sys.stderr.write("[HIT] %s -> '%s'\n" % (p, body))
    
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "100")
        self.end_headers()
    
    def log_message(self, *a): pass

print(f"[*] SSRF oracle on port {PORT}, secret={SECRET}")
HTTPServer(("0.0.0.0", PORT), H).serve_forever()
