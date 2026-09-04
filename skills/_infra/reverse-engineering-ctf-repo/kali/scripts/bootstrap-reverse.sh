#!/usr/bin/env bash
# bootstrap-reverse.sh — Kali Linux automatic tool install/top-up
# equivalent to the Windows version, bootstrap-reverse.ps1
#
# Usage:
#   bash bootstrap-reverse.sh <capability1> [capability2] ... [--start-services] [--skip-refresh]
#
# Examples:
#   bash bootstrap-reverse.sh jadx apktool frida
#   bash bootstrap-reverse.sh idapro --start-services
#   bash bootstrap-reverse.sh jshookmcp anything-analyzer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/tool-discovery.sh"

# ─── Argument parsing ──────────────────────────────────────────────────────────────────────

CAPABILITIES=()
START_SERVICES=false
SKIP_REFRESH=false

for arg in "$@"; do
    case "$arg" in
        --start-services) START_SERVICES=true ;;
        --skip-refresh) SKIP_REFRESH=true ;;
        --list|-l)
            echo "jadx apktool frida frida-ps idalib-mcp jshookmcp anything-analyzer idapro r2 rabin2 adb agent-browser ghidra-mcp seclists proxycat burpsuite-mcp nmap pentestswarm"
            echo "mcp-kali-server metasploitmcp hexstrike-ai adaptixc2 atomic-operator sstimap xsstrike wpprobe fluxion gef coercer evil-winrm-py netexec responder bloodhound certipy"
            exit 0
            ;;
        -*) echo "Unknown option: $arg"; exit 1 ;;
        *) CAPABILITIES+=("$arg") ;;
    esac
done

if [[ ${#CAPABILITIES[@]} -eq 0 ]]; then
    echo "Usage: $0 <capability1> [capability2] ... [--start-services] [--skip-refresh]"
    echo ""
    echo "Available capabilities:"
    echo ""
    echo "  [Reverse engineering]"
    echo "    jadx apktool frida frida-ps idalib-mcp r2 rabin2 adb gef"
    echo ""
    echo "  [Penetration testing - classic tools]"
    echo "    nmap sqlmap hashcat hydra gobuster ffuf msfconsole nuclei"
    echo "    netexec responder crackmapexec bloodhound certipy wfuzz"
    echo "    aircrack-ng coercer evil-winrm-py"
    echo ""
    echo "  [Penetration testing - new in Kali 2026.1]"
    echo "    adaptixc2 atomic-operator sstimap xsstrike wpprobe fluxion"
    echo ""
    echo "  [MCP services]"
    echo "    jshookmcp anything-analyzer idapro agent-browser"
    echo "    mcp-kali-server metasploitmcp hexstrike-ai pentestswarm"
    echo ""
    echo "  [Other]"
    echo "    ghidra-mcp seclists proxycat burpsuite-mcp"
    echo ""
    echo "Examples:"
    echo "  $0 mcp-kali-server metasploitmcp hexstrike-ai pentestswarm  # every pentest MCP"
    echo "  $0 adaptixc2 sstimap xsstrike wpprobe          # install the new 2026.1 tools"
    echo "  $0 pentestswarm --start-services               # install Swarm AI"
    echo "  $0 idapro --start-services                     # install and start IDA MCP"
    exit 1
fi

# ─── Helper functions ──────────────────────────────────────────────────────────────────────

log_info() { echo -e "\033[36m[INFO]\033[0m $*"; }
log_ok() { echo -e "\033[32m[OK]\033[0m $*"; }
log_warn() { echo -e "\033[33m[WARN]\033[0m $*"; }
log_err() { echo -e "\033[31m[ERR]\033[0m $*"; }

# Check for sudo privileges
check_sudo() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    fi
    if sudo -n true 2>/dev/null; then
        return 0
    fi
    log_warn "Some operations require sudo privileges"
    return 1
}

# apt install
install_apt_package() {
    local package="$1"
    log_info "apt install $package ..."
    if [[ $EUID -eq 0 ]]; then
        apt-get update -qq && apt-get install -y -qq "$package"
    else
        sudo apt-get update -qq && sudo apt-get install -y -qq "$package"
    fi
}

# pip install
install_pip_package() {
    local package="$1"
    local source="${2:-}"
    local target="${source:-$package}"
    log_info "pip3 install $target ..."
    pip3 install --upgrade "$target" --break-system-packages 2>/dev/null \
        || pip3 install --upgrade "$target"
}

# npm global install
install_npm_global() {
    local package="$1"
    log_info "npm install -g $package ..."
    if [[ $EUID -eq 0 ]]; then
        npm install -g "$package"
    else
        sudo npm install -g "$package" 2>/dev/null || npm install -g "$package"
    fi
}

# Download and extract a GitHub release
install_github_release() {
    local repo="$1"
    local asset_regex="$2"
    local install_dir="$3"

    log_info "Downloading from the GitHub release: $repo ..."

    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local release_json
    release_json=$(curl -sL "$api_url")

    local download_url
    download_url=$(echo "$release_json" | jq -r ".assets[] | select(.name | test(\"${asset_regex}\")) | .browser_download_url" | head -n1)

    if [[ -z "$download_url" || "$download_url" == "null" ]]; then
        log_err "No release asset matching $asset_regex"
        return 1
    fi

    local filename
    filename=$(basename "$download_url")
    local tmp_file="/tmp/bootstrap-$$-${filename}"

    log_info "Downloading: $download_url"
    curl -sL -o "$tmp_file" "$download_url"

    # Create the install directory
    mkdir -p "$install_dir"

    # Extract according to file type
    case "$filename" in
        *.tar.gz|*.tgz)
            tar -xzf "$tmp_file" -C "$install_dir" --strip-components=1 2>/dev/null \
                || tar -xzf "$tmp_file" -C "$install_dir"
            ;;
        *.zip)
            local tmp_extract="/tmp/bootstrap-extract-$$"
            mkdir -p "$tmp_extract"
            unzip -qo "$tmp_file" -d "$tmp_extract"
            # If there is a single top-level directory, strip it
            local top_dirs
            top_dirs=$(find "$tmp_extract" -maxdepth 1 -mindepth 1 -type d)
            if [[ $(echo "$top_dirs" | wc -l) -eq 1 ]]; then
                cp -a "$top_dirs"/* "$install_dir/" 2>/dev/null || mv "$top_dirs"/* "$install_dir/"
            else
                cp -a "$tmp_extract"/* "$install_dir/"
            fi
            rm -rf "$tmp_extract"
            ;;
        *.deb)
            if [[ $EUID -eq 0 ]]; then
                dpkg -i "$tmp_file" || apt-get install -f -y
            else
                sudo dpkg -i "$tmp_file" || sudo apt-get install -f -y
            fi
            ;;
        *)
            cp "$tmp_file" "$install_dir/"
            ;;
    esac

    rm -f "$tmp_file"

    # Add the bin directory to PATH (current session only)
    if [[ -d "$install_dir/bin" ]]; then
        export PATH="$install_dir/bin:$PATH"
    else
        export PATH="$install_dir:$PATH"
    fi

    log_ok "Installed to $install_dir"
}

# Register an MCP server in the Claude config
register_mcp_server() {
    local server_name="$1"
    local config_json="$2"  # server config in JSON form

    local config_path
    config_path=$(get_claude_mcp_config_path)
    local config_dir
    config_dir=$(dirname "$config_path")

    mkdir -p "$config_dir"

    if [[ ! -f "$config_path" ]]; then
        echo '{"mcpServers":{}}' > "$config_path"
    fi

    if command -v jq &>/dev/null; then
        local tmp_file="/tmp/mcp-config-$$.json"
        jq ".mcpServers.\"${server_name}\" = ${config_json}" "$config_path" > "$tmp_file"
        mv "$tmp_file" "$config_path"
        log_ok "MCP server '$server_name' registered in $config_path"
    else
        log_warn "jq is not installed, so the MCP server cannot be registered automatically. Edit $config_path manually."
    fi
}

# Wait for a port to become ready
wait_for_port() {
    local port="$1"
    local timeout="${2:-90}"
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if test_tcp_port "$port" 2>/dev/null; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

# ─── Capability install logic ──────────────────────────────────────────────────────────────────

ensure_capability() {
    local name="$1"

    # First check whether it is already available
    if command -v "$name" &>/dev/null; then
        log_ok "$name is already available: $(command -v "$name")"
        return 0
    fi

    log_info "Installing: $name"

    case "$name" in
        # ─── Tools preinstalled or installable via apt ───
        nmap|sqlmap|hashcat|hydra|gobuster|ffuf|adb)
            install_apt_package "$name"
            ;;
        msfconsole)
            install_apt_package "metasploit-framework"
            ;;
        r2|rabin2|rasm2|radiff2|rahash2|rax2)
            if ! command -v r2 &>/dev/null; then
                install_apt_package "radare2"
            fi
            ;;
        apktool)
            install_apt_package "apktool"
            ;;
        seclists)
            install_apt_package "seclists"
            ;;
        # ─── Tools new in Kali 2026.1 (all installable directly via apt) ───
        adaptixc2)
            install_apt_package "adaptixc2"
            ;;
        atomic-operator)
            install_apt_package "atomic-operator"
            ;;
        fluxion)
            install_apt_package "fluxion"
            ;;
        gef)
            install_apt_package "gef"
            log_info "GEF installed. Its enhancements load automatically when gdb starts."
            ;;
        sstimap)
            install_apt_package "sstimap"
            ;;
        xsstrike)
            install_apt_package "xsstrike"
            ;;
        wpprobe)
            install_apt_package "wpprobe"
            ;;
        evil-winrm-py)
            install_apt_package "evil-winrm-py"
            ;;
        coercer)
            install_apt_package "coercer"
            ;;
        netexec)
            install_apt_package "netexec"
            ;;
        responder)
            install_apt_package "responder"
            ;;
        crackmapexec)
            install_apt_package "crackmapexec"
            ;;
        bloodhound)
            install_apt_package "bloodhound"
            ;;
        certipy)
            install_apt_package "certipy-ad"
            ;;
        wfuzz)
            install_apt_package "wfuzz"
            ;;
        aircrack-ng)
            install_apt_package "aircrack-ng"
            ;;
        # ─── Kali native MCP tools (apt install + MCP registration) ───
        mcp-kali-server)
            install_apt_package "mcp-kali-server"
            register_mcp_server "kali-server" '{
                "command": "kali-server-mcp",
                "args": ["--port", "5000"]
            }'
            log_info "To start it: kali-server-mcp --port 5000"
            log_info "Then connect AI clients to the API server with mcp-server"
            ;;
        metasploitmcp)
            install_apt_package "metasploitmcp"
            register_mcp_server "metasploit-mcp" '{
                "command": "metasploitmcp",
                "args": ["--transport", "stdio"]
            }'
            log_info "MetasploitMCP supports both stdio and HTTP modes"
            log_info "  stdio: metasploitmcp --transport stdio"
            log_info "  HTTP:  metasploitmcp --transport http --port 8085"
            ;;
        hexstrike-ai)
            install_apt_package "hexstrike-ai"
            register_mcp_server "hexstrike" '{
                "command": "hexstrike-ai",
                "args": []
            }'
            log_info "HexStrike AI installed. It exposes 150+ security tools to AI agents over MCP."
            ;;
        # ─── Pentest Swarm AI (swarm-intelligence pentest framework) ───
        pentestswarm)
            if command -v pentestswarm &>/dev/null; then
                log_ok "pentestswarm is available"
            elif command -v go &>/dev/null; then
                log_info "go install pentestswarm ..."
                go install github.com/Armur-Ai/Pentest-Swarm-AI/cmd/pentestswarm@latest
            elif command -v docker &>/dev/null; then
                log_info "Pulling the pentestswarm Docker image ..."
                docker pull ghcr.io/armur-ai/pentestswarm:latest
                log_info "Usage: docker run --rm ghcr.io/armur-ai/pentestswarm:latest scan <target> --scope <scope>"
            else
                log_warn "Installing pentestswarm requires Go 1.24+ or Docker"
                log_info "Install Go with: apt install golang-go"
                log_info "Then: go install github.com/Armur-Ai/Pentest-Swarm-AI/cmd/pentestswarm@latest"
                return 1
            fi
            register_mcp_server "pentestswarm" '{
                "command": "pentestswarm",
                "args": ["mcp", "serve"]
            }'
            log_info "Pentest Swarm AI configured"
            log_info "  MCP mode:  pentestswarm mcp serve"
            log_info "  Scan mode: pentestswarm scan <target> --scope <scope> --swarm"
            log_info "  Must be set: export PENTESTSWARM_ORCHESTRATOR_API_KEY=<your-claude-key>"
            ;;

        # ─── pip install ───
        frida|frida-ps)
            install_pip_package "frida-tools"
            ;;
        idalib-mcp)
            install_pip_package "ida-pro-mcp" "git+https://github.com/mrexodia/ida-pro-mcp.git"
            log_info "Run ida-pro-mcp --install to finish installing the IDA plugin"
            ;;
        proxycat)
            install_pip_package "proxycat"
            ;;

        # ─── GitHub Release ───
        jadx)
            install_github_release "skylot/jadx" "^jadx-[0-9].*\\.zip$" "$HOME/tools/jadx"
            chmod +x "$HOME/tools/jadx/bin/jadx" 2>/dev/null || true
            ;;
        ghidra-mcp)
            if command -v ghidra &>/dev/null; then
                log_ok "ghidra installed via apt"
            else
                install_apt_package "ghidra" 2>/dev/null \
                    || install_github_release "NationalSecurityAgency/ghidra" "^ghidra_.*_PUBLIC_.*\\.zip$" "$HOME/tools/ghidra"
            fi
            log_warn "The GhidraMCP plugin must be installed manually: https://github.com/LaurieWired/GhidraMCP/releases"
            ;;
        nuclei)
            if command -v go &>/dev/null; then
                log_info "go install nuclei ..."
                go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
            else
                install_github_release "projectdiscovery/nuclei" "^nuclei_.*_linux_amd64\\.zip$" "$HOME/tools/nuclei"
            fi
            ;;

        # ─── npm/MCP ───
        jshookmcp)
            if ! command -v node &>/dev/null; then
                install_apt_package "nodejs"
            fi
            if ! command -v npm &>/dev/null; then
                install_apt_package "npm"
            fi
            register_mcp_server "jshook" '{
                "command": "npx",
                "args": ["-y", "@jshookmcp/jshook@latest"],
                "env": {"JSHOOK_BASE_PROFILE": "search"}
            }'
            ;;
        agent-browser)
            if ! command -v node &>/dev/null; then
                install_apt_package "nodejs"
            fi
            install_npm_global "agent-browser"
            npx playwright install chromium 2>/dev/null || true
            ;;

        # ─── Local HTTP MCP services ───
        anything-analyzer)
            register_mcp_server "anything-analyzer" "{\"url\": \"http://localhost:23816/mcp\"}"
            if [[ "$START_SERVICES" == "true" ]]; then
                start_anything_analyzer
            fi
            ;;
        idapro)
            # Make sure idalib-mcp is installed first
            ensure_capability "idalib-mcp"
            register_mcp_server "idapro" "{\"url\": \"http://127.0.0.1:13337/mcp\"}"
            if [[ "$START_SERVICES" == "true" ]]; then
                start_idapro_service
            fi
            ;;

        # ─── Manual install ───
        burpsuite-mcp)
            log_warn "MANUAL_INSTALL_REQUIRED: burpsuite-mcp"
            log_warn "BurpSuite is preinstalled on Kali; search the extension marketplace for the MCP plugin"
            register_mcp_server "burpsuite" "{\"url\": \"http://localhost:9876/mcp\"}"
            ;;

        *)
            log_err "Unknown capability: $name"
            return 1
            ;;
    esac
}

# ─── Service startup ──────────────────────────────────────────────────────────────────────

start_anything_analyzer() {
    if test_tcp_port 23816 2>/dev/null; then
        log_ok "anything-analyzer is already running (port 23816)"
        return 0
    fi

    local repo_dir="$HOME/tools/anything-analyzer"

    if [[ ! -d "$repo_dir" ]]; then
        log_info "Cloning anything-analyzer ..."
        git clone https://github.com/Mouseww/anything-analyzer.git "$repo_dir"
    fi

    if ! command -v pnpm &>/dev/null; then
        npm install -g pnpm
    fi

    (cd "$repo_dir" && pnpm install && nohup pnpm dev > /tmp/anything-analyzer.log 2>&1 &)

    log_info "Waiting for anything-analyzer to start (port 23816) ..."
    if wait_for_port 23816 120; then
        log_ok "anything-analyzer started"
    else
        log_err "anything-analyzer timed out on startup; check the log: /tmp/anything-analyzer.log"
        return 1
    fi
}

start_idapro_service() {
    if test_tcp_port 13337 2>/dev/null; then
        log_ok "IDA Pro MCP is already running (port 13337)"
        return 0
    fi

    local ida_start_script="$SCRIPT_DIR/ida-start.sh"
    if [[ -x "$ida_start_script" ]]; then
        bash "$ida_start_script"
    else
        log_warn "The IDA start script does not exist: $ida_start_script"
        log_warn "Start IDA Pro manually; the plugin listens on port 13337 automatically"
        return 1
    fi
}

# ─── Main flow ────────────────────────────────────────────────────────────────────────

RESULTS=()

for cap in "${CAPABILITIES[@]}"; do
    if ensure_capability "$cap"; then
        RESULTS+=("{\"name\":\"$cap\",\"status\":\"ready\"}")
    else
        RESULTS+=("{\"name\":\"$cap\",\"status\":\"failed\"}")
    fi
done

# Refresh the tool index
if [[ "$SKIP_REFRESH" != "true" ]]; then
    log_info "Refreshing the tool index ..."
    bash "$SCRIPT_DIR/refresh-tool-index.sh" >/dev/null 2>&1 || true
fi

# Print the result
echo ""
echo "═══════════════════════════════════════════"
echo "  Bootstrap complete"
echo "═══════════════════════════════════════════"
for r in "${RESULTS[@]}"; do
    name=$(echo "$r" | jq -r '.name' 2>/dev/null || echo "$r")
    status=$(echo "$r" | jq -r '.status' 2>/dev/null || echo "unknown")
    if [[ "$status" == "ready" ]]; then
        echo "  ✓ $name"
    else
        echo "  ✗ $name (failed)"
    fi
done
echo ""
