#!/usr/bin/env bash
# refresh-tool-index.sh — Kali Linux tool-index refresh
# equivalent to the Windows version, refresh-tool-index.ps1
# Output: skills/tool-index.md + skills/tool-index.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/tool-discovery.sh"

OUTPUT_MD="${1:-${SKILL_ROOT}/tool-index.md}"
OUTPUT_JSON="${2:-${SKILL_ROOT}/tool-index.json}"

GENERATED_AT=$(date '+%Y-%m-%d %H:%M:%S %z')

# ─── Generate Markdown ────────────────────────────────────────────────────────────────

{
    echo "# Reverse-engineering tool index"
    echo ""
    echo "- Scanned at: $GENERATED_AT"
    echo "- Platform:   Kali Linux ($(uname -r))"
    echo "- Routing entry: \`SKILL.md\` → \`routing.md\` → the matching sub-skill"
    echo "- Note: this table is generated automatically by \`kali/scripts/refresh-tool-index.sh\`."
    echo "- Caution: for MCP servers such as jshookmcp, \`yes\` only means this machine can launch it via node/npx, not that it is registered and enabled in the MCP config."
    echo ""
    echo "| Tool | Owning skill | Purpose | Available | Path | Version | Source | Script refs |"
    echo "|---|---|---|---|---|---|---|---|"

    for entry in "${TOOL_CATALOG[@]}"; do
        result=$(resolve_tool "$entry")
        IFS='|' read -r name skill purpose available resolved_path version source <<< "$result"

        # Get script references
        refs="${SCRIPT_REFS[$name]:-—}"
        refs_display="${refs//,/<br>}"

        path_display="${resolved_path:-—}"
        version_display="${version:-—}"

        echo "| $name | $skill | $purpose | $available | $path_display | $version_display | $source | $refs_display |"
    done
} > "$OUTPUT_MD"

# ─── Capability status view ──────────────────────────────────────────────────────────────────

{
    echo ""
    echo "---"
    echo ""
    echo "## Capability Status"
    echo ""
    echo "| Capability | Tool available | MCP registered | Service online | Auto-installable | Install method |"
    echo "|------|---------|-----------|---------|-----------|---------|"

    CAPABILITY_NAMES=("jadx" "apktool" "frida" "idalib-mcp" "jshookmcp" "anything-analyzer" "idapro" "r2" "adb" "agent-browser" "ghidra-mcp" "seclists" "proxycat" "burpsuite-mcp" "nmap" "sqlmap" "hashcat" "hydra" "gobuster" "ffuf" "msfconsole" "nuclei")

    for cap_name in "${CAPABILITY_NAMES[@]}"; do
        # Check whether the tool is available
        tool_available="✗"
        if command -v "$cap_name" &>/dev/null; then
            tool_available="✓"
        fi

        # Check MCP registration status
        mcp_registered="—"
        mcp_check=$(check_mcp_registered "$cap_name")
        if [[ "$mcp_check" == "true" ]]; then
            mcp_registered="✓"
        fi

        # Check whether the service is online
        service_online="—"
        case "$cap_name" in
            idapro)
                if test_tcp_port 13337 2>/dev/null; then service_online="✓"; fi
                ;;
            anything-analyzer)
                if test_tcp_port 23816 2>/dev/null; then service_online="✓"; fi
                ;;
            ghidra-mcp)
                if test_tcp_port 8765 2>/dev/null; then service_online="✓"; fi
                ;;
            burpsuite-mcp)
                if test_tcp_port 9876 2>/dev/null; then service_online="✓"; fi
                ;;
        esac

        # Get the install method
        can_auto="✓"
        bootstrap_kind="apt-package"
        case "$cap_name" in
            jadx|ghidra-mcp|seclists)
                bootstrap_kind="github-release"
                ;;
            frida|idalib-mcp|proxycat)
                bootstrap_kind="pip-package"
                ;;
            jshookmcp|agent-browser)
                bootstrap_kind="npm-mcp"
                ;;
            anything-analyzer|idapro)
                bootstrap_kind="local-http-mcp"
                ;;
            burpsuite-mcp)
                bootstrap_kind="manual"
                can_auto="✗"
                ;;
        esac

        echo "| $cap_name | $tool_available | $mcp_registered | $service_online | $can_auto | $bootstrap_kind |"
    done

    echo ""
    echo "> ✓ = yes | ✗ = no | — = not applicable or not checked"
    echo ""
} >> "$OUTPUT_MD"

# ─── Generate JSON ─────────────────────────────────────────────────────────────────────

if command -v jq &>/dev/null; then
    # Use jq to generate structured JSON
    json_tools="[]"
    for entry in "${TOOL_CATALOG[@]}"; do
        result=$(resolve_tool "$entry")
        IFS='|' read -r name skill purpose available resolved_path version source <<< "$result"
        refs="${SCRIPT_REFS[$name]:-}"

        avail_bool="false"
        [[ "$available" == "yes" ]] && avail_bool="true"

        json_tools=$(echo "$json_tools" | jq \
            --arg name "$name" \
            --arg skill "$skill" \
            --arg purpose "$purpose" \
            --argjson available "$avail_bool" \
            --arg resolved_path "$resolved_path" \
            --arg version "$version" \
            --arg source "$source" \
            --arg script_refs "$refs" \
            '. + [{
                name: $name,
                skill: $skill,
                purpose: $purpose,
                available: $available,
                resolved_path: $resolved_path,
                version: $version,
                source: $source,
                script_refs: ($script_refs | split(","))
            }]')
    done

    jq -n \
        --arg generated_at "$GENERATED_AT" \
        --arg platform "kali-linux" \
        --argjson tools "$json_tools" \
        '{
            generated_at: $generated_at,
            platform: $platform,
            routing_entry: ["SKILL.md", "routing.md"],
            tools: $tools
        }' > "$OUTPUT_JSON"
else
    # Fall back to simple JSON when jq is unavailable
    echo "{\"generated_at\": \"$GENERATED_AT\", \"platform\": \"kali-linux\", \"note\": \"install jq for full JSON output\"}" > "$OUTPUT_JSON"
fi

echo "✅ Tool index refreshed"
echo "  markdown=$OUTPUT_MD"
echo "  json=$OUTPUT_JSON"
echo "  tools=${#TOOL_CATALOG[@]}"
