#!/usr/bin/env python3
"""
Evidence Store CLI for OSS Forensics investigations.
Manages a JSON evidence store with content hashing and verification.
"""

import json
import hashlib
import argparse
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

STORE_VERSION = 1


def load_store(path: str) -> Dict[str, Any]:
    """Load evidence store from file."""
    if not os.path.exists(path):
        return {
            "version": STORE_VERSION,
            "created": datetime.now(timezone.utc).isoformat(),
            "evidence": {}
        }
    with open(path, 'r') as f:
        return json.load(f)


def save_store(store: Dict[str, Any], path: str) -> None:
    """Save evidence store to file."""
    store["updated"] = datetime.now(timezone.utc).isoformat()
    with open(path, 'w') as f:
        json.dump(store, f, indent=2)


def compute_hash(content: str) -> str:
    """Compute SHA256 hash of content."""
    return "sha256:" + hashlib.sha256(content.encode('utf-8')).hexdigest()


def generate_id(prefix: str, store: Dict) -> str:
    """Generate next evidence ID."""
    existing = [k for k in store["evidence"].keys() if k.startswith(prefix)]
    nums = []
    for e in existing:
        try:
            nums.append(int(e.split('-')[1]))
        except (IndexError, ValueError):
            pass
    next_num = max(nums, default=0) + 1
    return f"{prefix}-{next_num:04d}"


def add_evidence(store: Dict, source: str, obs_type: str, content: str,
                 ioc_ref: Optional[str] = None, verification: str = "UNVERIFIED",
                 notes: str = "") -> str:
    """Add evidence to store. Returns evidence ID."""
    ev_id = generate_id("EV", store)
    content_hash = compute_hash(content)

    store["evidence"][ev_id] = {
        "id": ev_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "type": obs_type,
        "ioc_ref": ioc_ref,
        "content_sha256": content_hash,
        "content": content,
        "verification": verification,
        "notes": notes
    }
    return ev_id


def list_evidence(store: Dict, source_filter: Optional[str] = None,
                  type_filter: Optional[str] = None,
                  verification_filter: Optional[str] = None) -> List[Dict]:
    """List evidence with optional filters."""
    results = []
    for ev_id, ev in sorted(store["evidence"].items()):
        if source_filter and ev["source"] != source_filter:
            continue
        if type_filter and ev["type"] != type_filter:
            continue
        if verification_filter and ev["verification"] != verification_filter:
            continue
        # Return summary without full content
        summary = {k: v for k, v in ev.items() if k != "content"}
        results.append(summary)
    return results


def get_evidence(store: Dict, ev_id: str) -> Optional[Dict]:
    """Get full evidence by ID."""
    return store["evidence"].get(ev_id)


def verify_evidence(store: Dict, ev_id: str) -> bool:
    """Verify content hash matches stored content."""
    ev = store["evidence"].get(ev_id)
    if not ev:
        return False
    computed = compute_hash(ev["content"])
    return computed == ev["content_sha256"]


def verify_all(store: Dict) -> Dict[str, bool]:
    """Verify all evidence. Returns dict of ev_id -> verified."""
    return {ev_id: verify_evidence(store, ev_id) for ev_id in store["evidence"]}


def main():
    parser = argparse.ArgumentParser(description="OSS Forensics Evidence Store")
    parser.add_argument("--store", default="evidence.json", help="Path to evidence store file")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # add command
    add_parser = subparsers.add_parser("add", help="Add evidence")
    add_parser.add_argument("--source", required=True, choices=["git", "github-api", "wayback", "gh-archive", "ioc-enrichment"])
    add_parser.add_argument("--type", required=True, choices=["force_push", "deleted_content", "suspicious_commit", "credential_leak", "malicious_code", "dependency_confusion", "workflow_injection", "maintainer_anomaly", "branch_deletion", "other"])
    add_parser.add_argument("--content", required=True, help="Evidence content (JSON string or raw text)")
    add_parser.add_argument("--ioc-ref", help="Associated IOC ID")
    add_parser.add_argument("--verification", default="UNVERIFIED", choices=["UNVERIFIED", "VERIFIED", "DISPUTED"])
    add_parser.add_argument("--notes", default="")

    # list command
    list_parser = subparsers.add_parser("list", help="List evidence")
    list_parser.add_argument("--source", help="Filter by source")
    list_parser.add_argument("--type", help="Filter by type")
    list_parser.add_argument("--verification", help="Filter by verification status")
    list_parser.add_argument("--full", action="store_true", help="Show full content")

    # show command
    show_parser = subparsers.add_parser("show", help="Show single evidence")
    show_parser.add_argument("ev_id", help="Evidence ID")

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify evidence integrity")
    verify_parser.add_argument("ev_id", nargs="?", help="Specific evidence ID (omit for all)")

    # stats command
    subparsers.add_parser("stats", help="Show store statistics")

    args = parser.parse_args()

    store = load_store(args.store)

    if args.command == "add":
        ev_id = add_evidence(store, args.source, args.type, args.content,
                            args.ioc_ref, args.verification, args.notes)
        save_store(store, args.store)
        print(f"Added evidence: {ev_id}")

    elif args.command == "list":
        results = list_evidence(store, args.source, args.type, args.verification)
        if not results:
            print("No evidence found")
            return
        for ev in results:
            content_preview = ""
            if args.full:
                content_preview = f" | {ev.get('content', '')[:80]}"
            print(f"{ev['id']} | {ev['timestamp']} | {ev['source']} | {ev['type']} | {ev['verification']}{content_preview}")

    elif args.command == "show":
        ev = get_evidence(store, args.ev_id)
        if not ev:
            print(f"Evidence {args.ev_id} not found", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(ev, indent=2))

    elif args.command == "verify":
        if args.ev_id:
            ok = verify_evidence(store, args.ev_id)
            print(f"{args.ev_id}: {'VERIFIED' if ok else 'CORRUPTED'}")
        else:
            results = verify_all(store)
            all_ok = all(results.values())
            for ev_id, ok in results.items():
                print(f"{ev_id}: {'VERIFIED' if ok else 'CORRUPTED'}")
            print(f"\nAll verified: {all_ok}")
            if not all_ok:
                sys.exit(1)

    elif args.command == "stats":
        total = len(store["evidence"])
        by_source = {}
        by_type = {}
        by_verification = {}
        for ev in store["evidence"].values():
            by_source[ev["source"]] = by_source.get(ev["source"], 0) + 1
            by_type[ev["type"]] = by_type.get(ev["type"], 0) + 1
            by_verification[ev["verification"]] = by_verification.get(ev["verification"], 0) + 1

        print(f"Total evidence: {total}")
        print(f"\nBy source: {by_source}")
        print(f"By type: {by_type}")
        print(f"By verification: {by_verification}")
        print(f"\nStore created: {store.get('created', 'unknown')}")
        print(f"Store updated: {store.get('updated', 'unknown')}")


if __name__ == "__main__":
    main()