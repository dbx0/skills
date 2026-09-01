#!/usr/bin/env python3
"""Simple HTTP server with proper charset headers for markdown/text files.

Usage: python3 server.py [PORT] [DIRECTORY]

Default: port 9090, current directory
"""
import http.server
import socketserver
import os
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
DIRECTORY = sys.argv[2] if len(sys.argv) > 2 else "."


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, format, *args):
        pass  # suppress logs

    def guess_type(self, path):
        """Override to add charset=utf-8 for text files."""
        mimetype = super().guess_type(path)
        if isinstance(mimetype, tuple):
            mimetype = mimetype[0]
        if mimetype and mimetype.startswith("text/"):
            return f"{mimetype}; charset=utf-8"
        return mimetype

socketserver.TCPServer.allow_reuse_address = True

with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    print(f"Serving on 0.0.0.0:{PORT} (directory: {DIRECTORY})")
    httpd.serve_forever()
