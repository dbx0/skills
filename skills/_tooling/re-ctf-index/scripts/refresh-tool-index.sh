#!/usr/bin/env bash
# refresh-tool-index.sh — generic Linux/macOS tool index refresh
#
# This script is intentionally detection-only. It does not install tools.
# Output defaults:
#   skills/tool-index.md
#   skills/tool-index.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SKILL_ROOT/.." && pwd)"

OUTPUT_MD="${1:-${SKILL_ROOT}/tool-index.md}"
OUTPUT_JSON="${2:-${SKILL_ROOT}/tool-index.json}"
GENERATED_AT="$(date '+%Y-%m-%d %H:%M:%S %z')"
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
UNAME_R="$(uname -r 2>/dev/null || echo unknown)"

case "$UNAME_S" in
  Darwin) PLATFORM="macos" ;;
  Linux) PLATFORM="linux" ;;
  *) PLATFORM="unknown" ;;
esac

has_cmd() { command -v "$1" >/dev/null 2>&1; }
cmd_path() { command -v "$1" 2>/dev/null || true; }

run_version() {
  local cmd="$1"; shift
  if ! has_cmd "$cmd"; then
    echo ""
    return 0
  fi
  "$cmd" "$@" 2>&1 | head -n 1 | tr '\n' ' ' | sed 's/[[:space:]]*$//'
}

file_exists_any() {
  local p
  for p in "$@"; do
    if [[ -e "$p" ]]; then
      echo "$p"
      return 0
    fi
  done
  echo ""
}

brew_prefix() {
  if has_cmd brew; then
    brew --prefix 2>/dev/null || true
  fi
}

install_hint() {
  local name="$1"
  case "$PLATFORM:$name" in
    linux:java) echo "apt: sudo apt install openjdk-17-jdk" ;;
    linux:node) echo "apt/nvm: sudo apt install nodejs npm; prefer NodeSource or nvm for newer Node" ;;
    linux:python3) echo "apt: sudo apt install python3 python3-venv python3-pip pipx" ;;
    linux:jadx) echo "GitHub release: download jadx ZIP to ~/tools/jadx" ;;
    linux:apktool) echo "apt or jar: sudo apt install apktool; or official apktool.jar" ;;
    linux:adb) echo "apt or Android platform-tools: sudo apt install adb" ;;
    linux:frida) echo "pipx: pipx install frida-tools" ;;
    linux:r2|linux:radare2) echo "GitHub/source preferred; apt if available" ;;
    linux:ghidra) echo "GitHub release ZIP or Flatpak; Java required" ;;
    linux:burpsuite) echo "manual installer/jar; then load burp-mcp-full jar" ;;
    linux:jshookmcp) echo "npx: npx -y @jshookmcp/jshook@latest" ;;
    linux:anything-analyzer) echo "git clone + pnpm install + pnpm dev" ;;
    linux:nuclei) echo "GitHub release or go install; apt may be unavailable" ;;
    linux:seclists) echo "git clone https://github.com/danielmiessler/SecLists ~/tools/SecLists" ;;

    macos:java) echo "brew: brew install openjdk" ;;
    macos:node) echo "brew/nvm: brew install node; or nvm" ;;
    macos:python3) echo "brew: brew install python; then pipx/venv" ;;
    macos:jadx) echo "brew: brew install jadx" ;;
    macos:apktool) echo "brew: brew install apktool" ;;
    macos:adb) echo "brew: brew install android-platform-tools" ;;
    macos:frida) echo "pipx: pipx install frida-tools" ;;
    macos:r2|macos:radare2) echo "brew: brew install radare2" ;;
    macos:ghidra) echo "brew: brew install ghidra or brew install --cask ghidra" ;;
    macos:burpsuite) echo "brew cask/manual: brew install --cask burp-suite" ;;
    macos:jshookmcp) echo "npx: npx -y @jshookmcp/jshook@latest" ;;
    macos:anything-analyzer) echo "git clone + corepack enable + pnpm install + pnpm dev" ;;
    macos:nuclei) echo "brew: brew install nuclei" ;;
    macos:seclists) echo "git clone https://github.com/danielmiessler/SecLists ~/tools/SecLists" ;;
    *) echo "see PLATFORMS.md and docs/platforms/${PLATFORM}.md" ;;
  esac
}

# name|skill|purpose|commands|version command args|extra path probes
TOOLS=(
  "java|core-runtime|Java runtime for jadx/apktool/Burp/Ghidra|java|java -version|"
  "python3|core-runtime|Python runtime for helper scripts and pipx tools|python3|python3 --version|"
  "pipx|core-runtime|Isolated Python CLI installer|pipx|pipx --version|"
  "node|core-runtime|Node.js runtime for MCP bridges|node|node --version|"
  "npm|core-runtime|Node package manager|npm|npm --version|"
  "npx|core-runtime|Run npm MCP packages|npx|npx --version|"
  "jadx|apk-reverse|APK Java/Kotlin decompiler|jadx|jadx --version|$HOME/tools/jadx/bin/jadx"
  "apktool|apk-reverse|APK decode and rebuild|apktool|apktool --version|"
  "adb|apk-reverse|Android device bridge|adb|adb version|$HOME/tools/android-platform-tools/platform-tools/adb"
  "frida|reverse-engineering|Dynamic instrumentation CLI|frida|frida --version|$HOME/.local/bin/frida"
  "frida-ps|reverse-engineering|Frida process listing|frida-ps|frida-ps --version|$HOME/.local/bin/frida-ps"
  "r2|radare2|radare2 CLI analysis|r2|r2 -v|"
  "rabin2|radare2|Binary metadata extraction|rabin2|rabin2 -v|"
  "ghidra|reverse-engineering|Ghidra reverse-engineering suite|ghidraRun|ghidraRun --version|$HOME/tools/ghidra/ghidraRun;/Applications/Ghidra.app"
  "idapro|ida-reverse|IDA Pro commercial reverse-engineering suite|idat|idat -v|/opt/idapro/idat;/Applications/IDA Professional.app;/Applications/IDA Free.app"
  "burpsuite|burp-mcp|BurpSuite desktop application|burpsuite|burpsuite --version|/Applications/Burp Suite Professional.app;/Applications/Burp Suite Community Edition.app"
  "graphviz|diagram-generator|Graphviz diagram rendering|dot|dot -V|"
  "plantuml|diagram-generator|PlantUML diagram rendering|plantuml|plantuml -version|"
  "nmap|pentest-tools|Network scanner|nmap|nmap --version|"
  "sqlmap|pentest-tools|SQL injection testing tool|sqlmap|sqlmap --version|"
  "ffuf|pentest-tools|Web fuzzer|ffuf|ffuf -V|"
  "hashcat|pentest-tools|Password recovery|hashcat|hashcat --version|"
  "nuclei|pentest-tools|Template-based vulnerability scanner|nuclei|nuclei -version|"
  "binwalk|firmware-pentest|Firmware extraction and analysis|binwalk|binwalk --version|"
  "seclists|pentest-tools|Security wordlists|none|none|$HOME/tools/SecLists;/usr/share/seclists"
  "jshookmcp|js-reverse|JS/CDP/Hook MCP runtime via npx|npx|npx --version|"
  "anything-analyzer|browser-automation|Browser/HTTP analyzer MCP project|none|none|$HOME/tools/anything-analyzer;$REPO_ROOT/../anything-analyzer"
  "burp-mcp-full|burp-mcp|Local Burp MCP extension and stdio bridge|none|none|$REPO_ROOT/burp-mcp-full/mcp-bridge.js"
)

records_tmp="$(mktemp)"
trap 'rm -f "$records_tmp"' EXIT

{
  echo "# Tool Index"
  echo ""
  echo "- Generated at: $GENERATED_AT"
  echo "- Platform: $PLATFORM ($UNAME_S $UNAME_R)"
  echo "- Script: \`skills/scripts/refresh-tool-index.sh\`"
  echo "- Note: This script detects tools only. It does not install tools."
  echo ""
  echo "| Tool | Skill | Purpose | Available | Path | Version | Install hint |"
  echo "|---|---|---|---|---|---|---|"
} > "$OUTPUT_MD"

for entry in "${TOOLS[@]}"; do
  IFS='|' read -r name skill purpose commands version_spec probes <<< "$entry"

  available="no"
  path=""
  version=""

  if [[ "$commands" != "none" ]]; then
    IFS=',' read -ra cmd_list <<< "$commands"
    for cmd in "${cmd_list[@]}"; do
      if has_cmd "$cmd"; then
        available="yes"
        path="$(cmd_path "$cmd")"
        break
      fi
    done
  fi

  if [[ "$available" == "no" && -n "${probes:-}" ]]; then
    IFS=';' read -ra probe_list <<< "$probes"
    for probe in "${probe_list[@]}"; do
      if [[ -e "$probe" ]]; then
        available="yes"
        path="$probe"
        break
      fi
    done
  fi

  if [[ "$version_spec" != "none" ]]; then
    read -r ver_cmd ver_arg1 ver_arg2 <<< "$version_spec"
    if has_cmd "$ver_cmd"; then
      version="$(run_version "$ver_cmd" ${ver_arg1:-} ${ver_arg2:-})"
    fi
  fi

  [[ -z "$path" ]] && path="—"
  [[ -z "$version" ]] && version="—"
  hint="$(install_hint "$name")"

  echo "| $name | $skill | $purpose | $available | $path | $version | $hint |" >> "$OUTPUT_MD"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$skill" "$purpose" "$available" "$path" "$version" "$hint" >> "$records_tmp"
done

{
  echo ""
  echo "---"
  echo ""
  echo "## Next steps"
  echo ""
  case "$PLATFORM" in
    linux)
      echo "- Read \`docs/platforms/linux.md\` for ordinary Linux setup."
      echo "- If the host is Kali, read \`kali/README-kali.md\` instead."
      ;;
    macos)
      echo "- Read \`docs/platforms/macos.md\` for Homebrew and app-bundle setup."
      ;;
    *)
      echo "- Read \`PLATFORMS.md\` and choose the closest platform guide."
      ;;
  esac
  echo "- Register MCP servers in your Agent client; tool availability does not imply MCP registration."
} >> "$OUTPUT_MD"

python3 - "$records_tmp" "$OUTPUT_JSON" "$GENERATED_AT" "$PLATFORM" "$UNAME_S $UNAME_R" <<'PY'
import json, sys
records_path, output_json, generated_at, platform, uname = sys.argv[1:]
tools=[]
with open(records_path, encoding='utf-8') as f:
    for line in f:
        name, skill, purpose, available, path, version, hint = line.rstrip('\n').split('\t')
        tools.append({
            'name': name,
            'skill': skill,
            'purpose': purpose,
            'available': available == 'yes',
            'path': None if path == '—' else path,
            'version': None if version == '—' else version,
            'install_hint': hint,
        })
with open(output_json, 'w', encoding='utf-8') as f:
    json.dump({
        'generated_at': generated_at,
        'platform': platform,
        'uname': uname,
        'script': 'skills/scripts/refresh-tool-index.sh',
        'tools': tools,
    }, f, ensure_ascii=False, indent=2)
PY

echo "✅ Tool index refreshed"
echo "  markdown=$OUTPUT_MD"
echo "  json=$OUTPUT_JSON"
echo "  platform=$PLATFORM"
echo "  tools=${#TOOLS[@]}"
