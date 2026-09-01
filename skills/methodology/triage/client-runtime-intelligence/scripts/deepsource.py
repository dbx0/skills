#!/usr/bin/env python3
"""Second-pass analysis of recovered first-party source.

Regex secret-banks miss credentials that are *returned* rather than *assigned*
(e.g. `function getGameClientSecret() { return "6yHP..." }`). This pass instead:
  1. flags any secret-ish identifier (function/const/property name), then reports the
     string literals in its vicinity;
  2. reports every high-entropy quoted literal regardless of surrounding syntax;
  3. inventories endpoints/hostnames for the attack-surface map.

usage: deepsource.py <recovered_root>
"""
import math
import os
import re
import sys
from collections import defaultdict

SECRET_NAME = re.compile(
    r"(client[_\-]?secret|clientsecret|api[_\-]?key|apikey|secret[_\-]?key|"
    r"access[_\-]?key|auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|"
    r"private[_\-]?key|passwd|password|credential|subscription[_\-]?key|"
    r"connection[_\-]?string|sas[_\-]?token|bearer|salt|signing[_\-]?key)",
    re.I)

LITERAL = re.compile(r"""(?<![\w])["']([A-Za-z0-9+/=_\-\.]{16,200})["']""")
URLRE = re.compile(r"""https?://[A-Za-z0-9._\-]+(?::\d+)?[^\s"'`,;)\]}]*""")

# literals that are obviously not credentials
BORING = re.compile(
    r"^(https?|/|\./|\.\./|[0-9.]+$|[a-f0-9]{7,8}$)|"
    r"(application/|text/|image/|utf-8|multipart|Bearer$|"
    r"^[A-Za-z]+(Component|Module|Service|Controller|Directive|Pipe)$|"
    r"^(true|false|null|undefined)$)", re.I)
WORDY = re.compile(r"^[a-z]+([A-Z][a-z]+)*$")          # camelCase identifiers
DASHY = re.compile(r"^[a-z0-9]+([-_][a-z0-9]+)+$")     # kebab/snake names
PATHY = re.compile(r"^[\w\-./]+\.(js|ts|tsx|jsx|css|scss|html|json|png|svg|jpg|woff2?)$", re.I)


def entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def interesting(lit):
    if len(lit) < 16 or BORING.search(lit):
        return False
    if WORDY.match(lit) or DASHY.match(lit) or PATHY.match(lit):
        return False
    e = entropy(lit)
    if e < 3.4:
        return False
    # require mixed character classes, like real key material
    classes = sum(bool(re.search(p, lit)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    if classes < 2:
        return False
    return True


def main():
    root = sys.argv[1]
    named_hits, entropy_hits, urls = [], [], set()

    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if re.search(r"\.(png|jpg|jpeg|gif|svg|woff2?|ttf|eot|ico|map)$", fn, re.I):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except OSError:
                continue
            if len(lines) > 20000:
                continue

            for i, line in enumerate(lines):
                if len(line) > 4000:
                    continue
                for m in URLRE.finditer(line):
                    urls.add(m.group(0)[:200])

                if SECRET_NAME.search(line):
                    # gather literals on this line and the next few
                    window = "".join(lines[i:i + 6])
                    lits = [l for l in LITERAL.findall(window)
                            if len(l) >= 12 and not BORING.search(l)
                            and not PATHY.match(l)]
                    if lits:
                        named_hits.append((rel, i + 1, line.strip()[:150],
                                           list(dict.fromkeys(lits))[:6]))

                for m in LITERAL.finditer(line):
                    lit = m.group(1)
                    if interesting(lit):
                        entropy_hits.append((rel, i + 1, lit, round(entropy(lit), 2),
                                             line.strip()[:130]))

    print("=" * 70)
    print(f"SECRET-NAMED IDENTIFIERS WITH NEARBY LITERALS: {len(named_hits)}")
    print("=" * 70)
    for rel, ln, ctx, lits in named_hits[:120]:
        print(f"\n[{rel}:{ln}]\n  ctx: {ctx}\n  literals: {lits}")

    print("\n" + "=" * 70)
    print(f"HIGH-ENTROPY LITERALS: {len(entropy_hits)}")
    print("=" * 70)
    seen = set()
    for rel, ln, lit, e, ctx in entropy_hits:
        if lit in seen:
            continue
        seen.add(lit)
        print(f"\n[{rel}:{ln}] H={e}\n  {lit}\n  ctx: {ctx}")
        if len(seen) > 150:
            print("  ... truncated")
            break

    print("\n" + "=" * 70)
    print(f"UNIQUE URLS/ENDPOINTS: {len(urls)}")
    print("=" * 70)
    with open(os.path.join(os.path.dirname(root), "out", "recovered_urls.txt"),
              "w", encoding="utf-8") as fh:
        fh.write("\n".join(sorted(urls)) + "\n")
    print("(written to out/recovered_urls.txt)")


if __name__ == "__main__":
    main()
