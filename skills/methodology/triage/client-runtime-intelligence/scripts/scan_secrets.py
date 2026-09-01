#!/usr/bin/env python3
"""Scan files for hardcoded secrets + source-map / uncompiled-code indicators.

usage: scan_secrets.py <regexbank> <file> [origin_url]
prints TSV: RULE \t origin \t file \t match(truncated) \t context(truncated)
"""
import re
import sys
import os
import json

# obvious non-secrets / library noise that produce generic-rule false positives
NOISE = re.compile(
    r"(?i)(example|sample|dummy|placeholder|your[_-]?(api|key|token)|xxxx+|"
    r"0{12,}|1234567890|lorem|test[_-]?key|foo|bar|changeme|<[a-z_]+>|"
    r"\$\{[^}]+\}|%[a-z_]+%|\{\{[^}]+\}\})"
)


def load_bank(path):
    rules = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#") or "|" not in line:
                continue
            name, pattern = line.split("|", 1)
            try:
                rules.append((name, re.compile(pattern)))
            except re.error as exc:
                print(f"[bad regex] {name}: {exc}", file=sys.stderr)
    return rules


def main():
    bank, target = sys.argv[1], sys.argv[2]
    origin = sys.argv[3] if len(sys.argv) > 3 else target
    rules = load_bank(bank)
    try:
        with open(target, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"[read fail] {target}: {exc}", file=sys.stderr)
        return
    text = raw.decode("utf-8", "replace")

    out = []

    # --- source map / uncompiled source indicators ---
    for m in re.finditer(r"//[#@]\s*sourceMappingURL=([^\s*'\"]+)", text):
        out.append(("SOURCEMAP_REF", m.group(1)[:200], ""))
    if '"sourcesContent"' in text or "'sourcesContent'" in text:
        out.append(("INLINE_SOURCESCONTENT", "sourcesContent present in asset", ""))
    if re.search(r"\.(tsx?|jsx|vue|svelte)\b", text) and "webpack://" in text:
        out.append(("WEBPACK_SOURCE_PATHS", "webpack:// original source paths", ""))
    # unminified heuristic: real newlines + indentation + comments, long file
    lines = text.count("\n")
    if len(text) > 20000 and lines > 200 and (len(text) / max(lines, 1)) < 120:
        if re.search(r"^\s{2,}(//|/\*|\*)", text, re.M):
            out.append(("LIKELY_UNMINIFIED", f"{lines} lines, avg {len(text)//max(lines,1)} chars/line", ""))

    # --- secret rules ---
    seen = set()
    for name, rx in rules:
        for m in rx.finditer(text):
            val = m.group(0)
            if len(val) > 400:
                continue
            key = (name, val[:120])
            if key in seen:
                continue
            seen.add(key)
            if name.startswith("GENERIC") and NOISE.search(val):
                continue
            start = max(0, m.start() - 70)
            ctx = text[start:m.end() + 70].replace("\n", " ").replace("\t", " ")
            out.append((name, val[:200], ctx[:300]))
            if len(seen) > 400:
                break

    for name, val, ctx in out:
        print(f"{name}\t{origin}\t{os.path.basename(target)}\t{val}\t{ctx}")


if __name__ == "__main__":
    main()
