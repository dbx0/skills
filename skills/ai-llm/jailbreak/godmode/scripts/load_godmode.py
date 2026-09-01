#!/usr/bin/env python3
"""
GODMODE Loader - Safe loader for jailbreak scripts.
Handles argparse/__main__ conflicts when loading via exec() in execute_code.
"""

import os
import sys
from pathlib import Path


def load_godmode():
    """
    Load GODMODE scripts into current namespace.
    Returns dict with auto_jailbreak, undo_jailbreak, and other functions.
    """
    hermes_home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
    scripts_dir = hermes_home / "skills/red-teaming/godmode/scripts"

    namespace = {"__name__": "godmode_loaded"}

    # Load parseltongue
    parseltongue_path = scripts_dir / "parseltongue.py"
    if parseltongue_path.exists():
        exec(parseltongue_path.read_text(), namespace)

    # Load auto_jailbreak
    auto_jailbreak_path = scripts_dir / "auto_jailbreak.py"
    if auto_jailbreak_path.exists():
        exec(auto_jailbreak_path.read_text(), namespace)

    # Load godmode_race
    godmode_race_path = scripts_dir / "godmode_race.py"
    if godmode_race_path.exists():
        exec(godmode_race_path.read_text(), namespace)

    # Load ultraplinian
    ultraplinian_path = scripts_dir / "ultraplinian.py"
    if ultraplinian_path.exists():
        exec(ultraplinian_path.read_text(), namespace)

    # Ensure key functions are available
    def auto_jailbreak(model: str = None, dry_run: bool = False):
        """Run auto-jailbreak detection and config update."""
        import asyncio
        if "auto_jailbreak" in namespace:
            return asyncio.run(namespace["auto_jailbreak"](model=model, dry_run=dry_run))
        else:
            # Inline fallback
            print("⚠️ auto_jailbreak not loaded, using inline version")
            return {"error": "not_loaded"}

    def undo_jailbreak():
        """Remove jailbreak from config."""
        if "undo_jailbreak" in namespace:
            return namespace["undo_jailbreak"]()
        else:
            print("⚠️ undo_jailbreak not loaded")

    namespace["auto_jailbreak"] = auto_jailbreak
    namespace["undo_jailbreak"] = undo_jailbreak

    return namespace

# Convenience: when imported, auto-load
if __name__ != "__main__":
    GODMODE = load_godmode()
    auto_jailbreak = GODMODE["auto_jailbreak"]
    undo_jailbreak = GODMODE["undo_jailbreak"]
    generate_variants = GODMODE.get("generate_variants")
    escalation_chain = GODMODE.get("escalation_chain")
    race_models = GODMODE.get("race_models")
    ultraplinian = GODMODE.get("ultraplinian")

# CLI entry point for direct execution
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="GODMODE Loader")
    parser.add_argument("--auto", action="store_true", help="Run auto_jailbreak")
    parser.add_argument("--model", help="Model to test")
    parser.add_argument("--dry-run", action="store_true", help="Test without applying")
    parser.add_argument("--undo", action="store_true", help="Remove jailbreak")
    args = parser.parse_args()

    import asyncio

    if args.undo:
        undo_jailbreak()
    elif args.auto:
        result = asyncio.run(auto_jailbreak(model=args.model, dry_run=args.dry_run))
        print(json.dumps(result, indent=2))
    else:
        print("GODMODE loaded. Use GODMODE.auto_jailbreak() or GODMODE.undo_jailbreak()")