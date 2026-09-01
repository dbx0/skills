#!/usr/bin/env python3
"""Decode fintech APK obfuscated strings: repeating-XOR, per-decoder-class key."""
import re, sys, os, subprocess

APK = sys.argv[1] if len(sys.argv) > 1 else "apk/base.apk"
CACHE = "/tmp/jadx_cls"


def parse_java_literal(raw):
    """Java string-literal body -> actual char list (chars are already decoded UTF-8;
    only backslash escapes need expanding)."""
    out, i = [], 0
    while i < len(raw):
        c = raw[i]
        if c == "\\" and i + 1 < len(raw):
            n = raw[i + 1]
            if n == "u":
                out.append(chr(int(raw[i + 2:i + 6], 16))); i += 6; continue
            m = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
                 "0": "\0", "\\": "\\", '"': '"', "'": "'"}
            if n in m:
                out.append(m[n]); i += 2; continue
            if n.isdigit():                       # octal
                j = i + 1
                while j < len(raw) and j < i + 4 and raw[j].isdigit():
                    j += 1
                out.append(chr(int(raw[i + 1:j], 8))); i = j; continue
        out.append(c); i += 1
    return out


def jadx_class(cls):
    d = os.path.join(CACHE, cls.replace("$", "_S_"))
    if not os.path.isdir(d):
        subprocess.run(["jadx", "-j", "4", "--single-class", cls, "-d", d, APK],
                       capture_output=True)
    for root, _, fs in os.walk(d):
        for f in fs:
            if f.endswith(".java"):
                return open(os.path.join(root, f), encoding="utf-8", errors="replace").read()
    return ""


def bytes_of(src):
    """Only the byte[] initializer block, not stray (byte)0 casts in loop bodies."""
    m = re.search(r"byte\[\]\s+\$?\w*\s*=\s*\{(.*?)\}", src, re.S)
    if not m:
        return []
    vals = re.findall(r"\(byte\)\s*\(?\s*(-?\d+)\s*\)?", m.group(1))
    return [int(v) & 255 for v in vals]

_keycache = {}


def key_for(decoder_pkg):
    """decoder p<N>.C$ -> its XOR key (built from two byte-array classes)."""
    if decoder_pkg in _keycache:
        return _keycache[decoder_pkg]
    src = jadx_class(f"{decoder_pkg}.C$")
    m = re.search(r"p(\d+)\.C\$\.\$\(\)", src)          # holder class it calls
    holder = f"p{m.group(1)}" if m else None
    if not holder:
        _keycache[decoder_pkg] = None
        return None
    hsrc = jadx_class(f"{holder}.C$")
    k1 = bytes_of(hsrc)
    m2 = re.search(r"byte\[\]\s+\w+\s*=\s*p(\d+)\.C\$\.\$", hsrc)
    if m2:
        k2 = bytes_of(jadx_class(f"p{m2.group(1)}.C$"))
        n = max(len(k1), len(k2))
        k = [((k1[i] if i < len(k1) else 0) ^ (k2[i] if i < len(k2) else 0)) for i in range(n)]
    else:
        k = k1
    _keycache[decoder_pkg] = k
    return k


def decode(decoder_pkg, literal):
    k = key_for(decoder_pkg)
    if not k:
        return None
    chars = parse_java_literal(literal)
    return "".join(chr(ord(c) ^ k[i % len(k)]) for i, c in enumerate(chars))


def decode_file(path):
    """Find every p<N>.C$.$("...") in a decompiled file and decode it."""
    src = open(path, encoding="utf-8", errors="replace").read()
    out = []
    for m in re.finditer(r'p(\d+)\.C\$\.\$\("((?:[^"\\]|\\.)*)"\)', src):
        pkg = f"p{m.group(1)}"
        try:
            d = decode(pkg, m.group(2))
        except Exception:
            d = None
        if d:
            out.append((pkg, d))
    return out


if __name__ == "__main__":
    for f in sys.argv[2:]:
        print(f"=== {f}")
        for pkg, d in decode_file(f):
            printable = d if all(32 <= ord(c) < 127 or c in "\n\t" for c in d) else repr(d)
            print(f"  [{pkg}] {printable}")
