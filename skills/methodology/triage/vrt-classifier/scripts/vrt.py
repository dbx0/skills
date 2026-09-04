#!/usr/bin/env python3
"""Bugcrowd VRT lookup / classification helper.

Data: references/*.json, mirrored from bugcrowd/vulnerability-rating-taxonomy.

Usage:
  vrt.py search <keywords...>     fuzzy search entry names -> ranked candidates
  vrt.py show <id-path>           full record: priority, CWE, CVSS, remediation
  vrt.py list [category-id]       list categories, or children of a category
  vrt.py flat [--priority N]      dump every leaf as TSV (id, name, P, CWE, CVSS)

id-path is dot-separated, e.g.:
  server_side_injection.sql_injection.blind
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REF = os.path.join(os.path.dirname(HERE), "references")


def load(name):
    with open(os.path.join(REF, name)) as fh:
        return json.load(fh)


def index_mapping(nodes, prefix=(), out=None, key=None):
    """Flatten a mapping file (cvss_v3/cwe) into {id-path: value}."""
    out = {} if out is None else out
    for node in nodes or []:
        path = prefix + (node["id"],)
        if node.get(key) is not None:
            out[".".join(path)] = node[key]
        index_mapping(node.get("children"), path, out, key)
    return out


def walk(nodes, prefix=(), names=(), parent_priority=None):
    """Yield (id-path, name-path, priority, is_leaf) for every VRT node."""
    for node in nodes or []:
        path = prefix + (node["id"],)
        npath = names + (node["name"],)
        # An explicit priority wins, including an explicit null (= "Varies").
        # A missing key means the node inherits its parent's priority.
        priority = node["priority"] if "priority" in node else parent_priority
        kids = node.get("children")
        yield ".".join(path), " > ".join(npath), priority, not kids
        yield from walk(kids, path, npath, priority)


def build():
    vrt = load("vrt.json")
    cvss = index_mapping(load("cvss_v3.json")["content"], key="cvss_v3")
    cwe = index_mapping(load("cwe.json")["content"], key="cwe")
    rows = list(walk(vrt["content"]))
    return vrt, rows, cvss, cwe


def lookup_inherited(table, idpath):
    """Mappings are sparse; fall back to the nearest ancestor that has a value."""
    parts = idpath.split(".")
    while parts:
        hit = table.get(".".join(parts))
        if hit is not None:
            return hit
        parts.pop()
    return None


def pstr(p):
    return "Varies" if p is None else "P%d" % p


def cmd_search(terms):
    _, rows, cvss, cwe = build()
    # Split on whitespace too, so a quoted "stored xss" behaves like two terms.
    words = [w.lower() for t in terms for w in t.split()]
    scored = []
    for idpath, name, priority, leaf in rows:
        hay = (idpath.replace("_", " ") + " " + name).lower()
        score = sum(3 if re.search(r"\b%s\b" % re.escape(w), hay) else
                    (1 if w in hay else 0) for w in words)
        if score:
            # Prefer leaves: those are the entries Bugcrowd wants on a report.
            scored.append((score + (1 if leaf else 0), idpath, name, priority))
    if not scored:
        print("no match; try fewer/broader keywords or `vrt.py list`")
        return 1
    for score, idpath, name, priority in sorted(scored, reverse=True)[:15]:
        c = lookup_inherited(cwe, idpath) or []
        print("%-6s %-58s %s" % (pstr(priority), idpath, name))
        if c:
            print("       %s | %s" % (",".join(c), lookup_inherited(cvss, idpath) or "-"))
    return 0


def cmd_show(idpath):
    vrt, rows, cvss, cwe = build()
    match = [r for r in rows if r[0] == idpath]
    if not match:
        print("unknown id-path: %s (use `vrt.py search`)" % idpath)
        return 1
    _, name, priority, leaf = match[0]
    print("id       : %s" % idpath)
    print("name     : %s" % name)
    print("priority : %s%s" % (pstr(priority), "" if leaf else "  (not a leaf: pick a child)"))
    print("cwe      : %s" % ",".join(lookup_inherited(cwe, idpath) or ["-"]))
    print("cvss v3  : %s" % (lookup_inherited(cvss, idpath) or "-"))
    print("release  : %s" % vrt["metadata"]["release_date"][:10])
    kids = [r for r in rows if r[0].startswith(idpath + ".")
            and r[0].count(".") == idpath.count(".") + 1]
    if kids:
        print("\nchildren:")
        for k, kname, kp, _ in kids:
            print("  %-6s %s" % (pstr(kp), k))
    advice = index_mapping(load("remediation_advice.json")["content"], key="remediation_advice")
    text = lookup_inherited(advice, idpath)
    if text:
        print("\nremediation:\n%s" % text.strip())
    return 0


def cmd_list(category=None):
    _, rows, _, _ = build()
    depth = 0 if not category else category.count(".") + 1
    for idpath, name, priority, _ in rows:
        if idpath.count(".") != depth:
            continue
        if category and not idpath.startswith(category + "."):
            continue
        print("%-6s %-58s %s" % (pstr(priority), idpath, name))
    return 0


def cmd_flat(args):
    want = None
    if "--priority" in args:
        want = int(args[args.index("--priority") + 1])
    _, rows, cvss, cwe = build()
    for idpath, name, priority, leaf in rows:
        if not leaf or (want is not None and priority != want):
            continue
        print("\t".join([idpath, name, pstr(priority),
                         ",".join(lookup_inherited(cwe, idpath) or []),
                         lookup_inherited(cvss, idpath) or ""]))
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd, args = argv[1], argv[2:]
    if cmd == "search" and args:
        return cmd_search(args)
    if cmd == "show" and args:
        return cmd_show(args[0])
    if cmd == "list":
        return cmd_list(args[0] if args else None)
    if cmd == "flat":
        return cmd_flat(args)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
