#!/usr/bin/env python3
"""Recover original source from a .js.map and scan it for secrets.

usage: maprecover.py <mapfile> <origin_url> <outdir>
Writes recovered sources under <outdir>/<host>/<original path> and prints a
summary line plus any secret hits (delegated to scan_secrets.py rules).
"""
import json
import os
import re
import sys
import subprocess

HOME = os.path.expanduser("~")
BANK = os.path.join(HOME, "gm", "secretregex.txt")
SCANNER = os.path.join(HOME, "gm", "scan_secrets.py")

# paths that are our own dependencies, not GM source
VENDOR = re.compile(r"(node_modules|webpack/bootstrap|/~/|core-js|regenerator-runtime)", re.I)


def safe(p):
    p = p.replace("webpack://", "").replace("../", "").lstrip("./")
    p = re.sub(r"[^A-Za-z0-9._/\-]", "_", p)
    return p.strip("/") or "unnamed"


def main():
    mapfile, origin, outdir = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        with open(mapfile, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except Exception as exc:
        print(f"[parse fail] {origin}: {exc}", file=sys.stderr)
        return

    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    if not contents:
        print(f"NOCONTENT\t{origin}\t{len(sources)} sources listed, no sourcesContent")
        return

    host = re.sub(r"^https?://", "", origin).split("/")[0]
    base = os.path.join(outdir, host)
    own = 0
    written = []
    for i, src in enumerate(sources):
        if i >= len(contents):
            break
        body = contents[i]
        if not body:
            continue
        if VENDOR.search(src or ""):
            continue
        own += 1
        dest = os.path.join(base, safe(src))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(body)
            written.append((dest, src))
        except OSError:
            continue

    print(f"RECOVERED\t{origin}\t{own} first-party files of {len(sources)} sources")
    for dest, src in written:
        try:
            out = subprocess.run(
                ["python3", SCANNER, BANK, dest, f"{origin}::{src}"],
                capture_output=True, text=True, timeout=60,
            ).stdout.strip()
        except Exception:
            continue
        if out:
            print(out)


if __name__ == "__main__":
    main()
