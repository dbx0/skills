#!/usr/bin/env bash
# quick-setup.sh — one-shot Kali 2026.1 initialization
# Run this on a fresh Kali system; it automatically does the following:
#   1. Update the system
#   2. Install the new Kali 2026.1 tools
#   3. Configure Kali's native MCP
#   4. Install reverse-engineering tools that are not preinstalled
#   5. Refresh the tool index
#   6. Print a configuration report
#
# Usage:
#   sudo bash kali/scripts/quick-setup.sh [--skip-update] [--minimal]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Arguments ──────────────────────────────────────────────────────────────────────────

SKIP_UPDATE=false
MINIMAL=false

for arg in "$@"; do
    case "$arg" in
        --skip-update) SKIP_UPDATE=true ;;
        --minimal) MINIMAL=true ;;
    esac
done

# ─── Colors ──────────────────────────────────────────────────────────────────────────

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
BOLD='\033[1m'
RESET='\033[0m'

banner() { echo -e "\n${BOLD}${CYAN}═══ $* ═══${RESET}\n"; }
ok() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
info() { echo -e "${CYAN}[i]${RESET} $*"; }

# ─── Permission check ──────────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "Run this as root: sudo bash $0"
    exit 1
fi

# ─── Check the Kali version ────────────────────────────────────────────────────────────────

banner "Checking system version"

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    info "System:  $PRETTY_NAME"
    info "Version: ${VERSION:-unknown}"
    info "Kernel:  $(uname -r)"
else
    warn "Could not detect the system version, continuing..."
fi

# ─── System update ──────────────────────────────────────────────────────────────────────

if [[ "$SKIP_UPDATE" != "true" ]]; then
    banner "System update"
    apt-get update -qq
    apt-get upgrade -y -qq
    ok "System updated"
else
    info "Skipping system update (--skip-update)"
fi

# ─── Install the new Kali 2026.1 tools ──────────────────────────────────────────────────────

banner "Installing the new Kali 2026.1 tools"

NEW_TOOLS_2026_1=(
    "adaptixc2"
    "atomic-operator"
    "fluxion"
    "gef"
    "metasploitmcp"
    "sstimap"
    "wpprobe"
    "xsstrike"
)

NEW_TOOLS_2025_4=(
    "evil-winrm-py"
    "hexstrike-ai"
)

for tool in "${NEW_TOOLS_2026_1[@]}" "${NEW_TOOLS_2025_4[@]}"; do
    if dpkg -l "$tool" &>/dev/null 2>&1; then
        ok "$tool already installed"
    else
        info "Installing $tool ..."
        apt-get install -y -qq "$tool" 2>/dev/null && ok "$tool installed" || warn "$tool install failed (it may not be in your repositories yet)"
    fi
done

# ─── Install Kali's native MCP ──────────────────────────────────────────────────────────

banner "Configuring Kali native MCP"

MCP_TOOLS=("mcp-kali-server" "metasploitmcp" "hexstrike-ai")

for tool in "${MCP_TOOLS[@]}"; do
    if dpkg -l "$tool" &>/dev/null 2>&1; then
        ok "$tool already installed"
    else
        info "Installing $tool ..."
        apt-get install -y -qq "$tool" 2>/dev/null && ok "$tool installed" || warn "$tool install failed"
    fi
done

# ─── Install AD / internal-network pentest tools ─────────────────────────────────────────────────────────

if [[ "$MINIMAL" != "true" ]]; then
    banner "Installing AD / internal-network pentest tools"

    AD_TOOLS=("coercer" "netexec" "responder" "bloodhound" "certipy-ad")

    for tool in "${AD_TOOLS[@]}"; do
        if dpkg -l "$tool" &>/dev/null 2>&1; then
            ok "$tool already installed"
        else
            info "Installing $tool ..."
            apt-get install -y -qq "$tool" 2>/dev/null && ok "$tool installed" || warn "$tool install failed"
        fi
    done
fi

# ─── Install non-preinstalled reverse-engineering tools ───────────────────────────────────────────────────────────

banner "Installing reverse-engineering tools"

# jadx (not preinstalled on Kali, downloaded from GitHub)
if ! command -v jadx &>/dev/null; then
    info "Installing jadx (from the GitHub release)..."
    bash "$SCRIPT_DIR/bootstrap-reverse.sh" jadx --skip-refresh 2>/dev/null && ok "jadx installed" || warn "jadx install failed"
else
    ok "jadx is available"
fi

# Node.js (required by some MCP servers)
if ! command -v node &>/dev/null; then
    info "Installing Node.js ..."
    apt-get install -y -qq nodejs npm && ok "Node.js installed" || warn "Node.js install failed"
else
    ok "Node.js is available: $(node -v)"
fi

# frida-tools
if ! command -v frida &>/dev/null; then
    info "Installing frida-tools ..."
    pip3 install --break-system-packages frida-tools 2>/dev/null && ok "frida-tools installed" || warn "frida-tools install failed"
else
    ok "frida is available"
fi

# ─── Configure the MCP client ──────────────────────────────────────────────────────────────

banner "Configuring the MCP client"

# Detect the real user ($HOME may be /root under sudo)
REAL_USER="${SUDO_USER:-root}"
REAL_HOME=$(eval echo "~$REAL_USER")

MCP_CONFIG_DIR="$REAL_HOME/.claude"
MCP_CONFIG="$MCP_CONFIG_DIR/mcp.json"

if command -v jq &>/dev/null; then
    mkdir -p "$MCP_CONFIG_DIR"

    if [[ ! -f "$MCP_CONFIG" ]]; then
        echo '{"mcpServers":{}}' > "$MCP_CONFIG"
    fi

    # Register kali-server
    jq '.mcpServers["kali-server"] = {"command": "kali-server-mcp", "args": ["--port", "5000"]}' "$MCP_CONFIG" > /tmp/mcp-tmp.json && mv /tmp/mcp-tmp.json "$MCP_CONFIG"

    # Register metasploit-mcp
    jq '.mcpServers["metasploit-mcp"] = {"command": "metasploitmcp", "args": ["--transport", "stdio"]}' "$MCP_CONFIG" > /tmp/mcp-tmp.json && mv /tmp/mcp-tmp.json "$MCP_CONFIG"

    # Register hexstrike
    jq '.mcpServers["hexstrike"] = {"command": "hexstrike-ai", "args": []}' "$MCP_CONFIG" > /tmp/mcp-tmp.json && mv /tmp/mcp-tmp.json "$MCP_CONFIG"

    # Register jshook
    jq '.mcpServers["jshook"] = {"command": "npx", "args": ["-y", "@jshookmcp/jshook@latest"], "env": {"JSHOOK_BASE_PROFILE": "search"}}' "$MCP_CONFIG" > /tmp/mcp-tmp.json && mv /tmp/mcp-tmp.json "$MCP_CONFIG"

    chown "$REAL_USER:$REAL_USER" "$MCP_CONFIG" "$MCP_CONFIG_DIR"
    ok "MCP config written to: $MCP_CONFIG"
else
    warn "jq is not installed, so MCP cannot be configured automatically. Copy kali/mcp-kali-example.json manually."
    info "Install jq with: apt install jq"
fi

# ─── Refresh the tool index ──────────────────────────────────────────────────────────────────

banner "Refreshing the tool index"

chmod +x "$SCRIPT_DIR"/*.sh "$SCRIPT_DIR"/lib/*.sh
sudo -u "$REAL_USER" bash "$SCRIPT_DIR/refresh-tool-index.sh" 2>/dev/null || bash "$SCRIPT_DIR/refresh-tool-index.sh"
ok "Tool index refreshed"

# ─── Print the report ──────────────────────────────────────────────────────────────────────

banner "Setup complete"

echo -e "${BOLD}✅ The Kali 2026.1 reverse-engineering skill routing pack is configured${RESET}"
echo ""
echo "  Install path: $(cd "$SCRIPT_DIR/../.." && pwd)"
echo "  MCP config:   $MCP_CONFIG"
echo "  Tool index:   $(cd "$SCRIPT_DIR/../.." && pwd)/skills/tool-index.md"
echo ""
echo "  Kali native MCP:"
command -v kali-server-mcp &>/dev/null && echo "    ✓ mcp-kali-server" || echo "    ✗ mcp-kali-server"
command -v metasploitmcp &>/dev/null && echo "    ✓ metasploitmcp" || echo "    ✗ metasploitmcp"
command -v hexstrike-ai &>/dev/null && echo "    ✓ hexstrike-ai" || echo "    ✗ hexstrike-ai"
echo ""
echo "  New 2026.1 tools:"
for tool in "${NEW_TOOLS_2026_1[@]}"; do
    if dpkg -l "$tool" &>/dev/null 2>&1; then
        echo "    ✓ $tool"
    else
        echo "    ✗ $tool"
    fi
done
echo ""
echo "  Next steps:"
echo "    1. Tell your AI client to read kali/RULES-kali.md"
echo "    2. Or just ask the AI: 'read kali/RULES-kali.md and run the setup'"
echo "    3. From then on, security and reverse-engineering tasks route automatically"
echo ""
