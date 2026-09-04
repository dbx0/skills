# Cybersecurity Skills Router — Kali Linux Dedicated Edition

> This directory is the optimization and adaptation layer for Kali Linux 2026.1. It is specifically tuned for Kali 2026.1 (kernel 6.18), released in March 2026.
> The core knowledge base (skills/, CTF-Sandbox-Orchestrator/) is shared with the Windows edition; the Kali-specific README and Bash entry points need to cover the Windows core capability names while additionally providing native Kali tool/MCP capabilities.

---

## 0. Relationship to the Windows Edition (capability name alignment)

```text
project root/
├── skills/                    # Shared: SKILL.md, routing.md, references, field-journal
├── CTF-Sandbox-Orchestrator/  # Shared: 40+ CTF sub-skills
├── kali/                      # ← you are here
│   ├── scripts/
│   │   ├── bootstrap-reverse.sh
│   │   ├── refresh-tool-index.sh
│   │   ├── bootstrap-manifest.json
│   │   └── lib/
│   │       └── tool-discovery.sh
│   ├── RULES-kali.md
│   └── README-kali.md
├── RULES.md                   # Windows edition rules
└── Readme.md                  # Windows edition documentation
```

### 0.1 Alignment Principle

The Kali-specific entry point is not a plain copy of the Windows README, it is **the same set of core capability names plus extra Kali capabilities**:

- Windows: `skills/scripts/bootstrap-reverse.ps1`
- Kali: `kali/scripts/bootstrap-reverse.sh`
- Plain Linux/macOS: `skills/scripts/bootstrap-reverse.sh`

The Kali script should cover the core capability names in the Windows manifest, for example `jadx`, `apktool`, `frida`, `jshookmcp`, `anything-analyzer`, `idapro`, `r2`, `adb`, `ghidra-mcp`, `seclists`, `burpsuite-mcp`, `nmap`, `pentestswarm`, and it may additionally support native Kali tools such as `mcp-kali-server`, `metasploitmcp`, `hexstrike-ai`, `sstimap`, `xsstrike`, `netexec` and others.

**Shared parts** (no changes needed):
- All `SKILL.md` and `routing.md` files
- The whole `references/` knowledge base
- The `field-journal/` self-evolution mechanism
- All of `CTF-Sandbox-Orchestrator/`
- `docs-generator/` and `diagram-generator/`

**Kali-specific parts**:
- All scripts are bash (`.sh`)
- Package management goes through `apt`
- Path conventions follow Linux style (`/opt/`, `~/tools/`, `/usr/bin/`)
- Many tools are preinstalled on Kali, so the bootstrap logic is much simpler

---

## 1. Kali's Built-in Advantages

The following tools work **out of the box** on Kali 2026.1 (no bootstrap needed):

### Classic preinstalled tools

| Tool | Kali package | Status |
|------|----------|------|
| nmap | nmap | Preinstalled |
| sqlmap | sqlmap | Preinstalled |
| hashcat | hashcat | Preinstalled |
| john | john | Preinstalled |
| hydra | hydra | Preinstalled |
| metasploit | metasploit-framework | Preinstalled |
| gobuster | gobuster | Preinstalled |
| ffuf | ffuf | Preinstalled |
| radare2 | radare2 | Preinstalled |
| binwalk | binwalk | Preinstalled |
| frida | python3-frida-tools | Preinstalled or via pip |
| burpsuite | burpsuite | Preinstalled |
| wireshark | wireshark | Preinstalled |
| nikto | nikto | Preinstalled |
| wfuzz | wfuzz | Preinstalled |
| impacket | impacket-scripts | Preinstalled |
| netexec | netexec | Preinstalled |
| responder | responder | Preinstalled |
| aircrack-ng | aircrack-ng | Preinstalled |
| bloodhound | bloodhound | Installable with apt |
| ghidra | ghidra | Installable with apt |

### New tools in Kali 2026.1 (March 2026)

| Tool | Package | Purpose |
|------|------|------|
| AdaptixC2 | adaptixc2 | Post-exploitation and adversary simulation framework |
| Atomic-Operator | atomic-operator | Cross-platform Atomic Red Team test execution |
| Fluxion | fluxion | WiFi security auditing and social engineering |
| GEF | gef | Modern enhanced debugging framework for GDB |
| MetasploitMCP | metasploitmcp | MCP server interface for Metasploit |
| SSTImap | sstimap | Automated detection and exploitation of server-side template injection |
| WPProbe | wpprobe | Fast WordPress plugin enumeration |
| XSStrike | xsstrike | Advanced XSS scanner |

### New tools in Kali 2025.4 (December 2025)

| Tool | Package | Purpose |
|------|------|------|
| evil-winrm-py | evil-winrm-py | Python implementation of WinRM remote command execution |
| hexstrike-ai | hexstrike-ai | AI MCP security automation platform (150+ tools) |
| bpf-linker | bpf-linker | BPF static linker |

### Native Kali MCP tools (a key optimization)

| Tool | Package | Purpose | Installation |
|------|------|------|------|
| mcp-kali-server | mcp-kali-server | Official Kali MCP, lets the AI call terminal tools directly | `apt install mcp-kali-server` |
| MetasploitMCP | metasploitmcp | Metasploit MCP interface | `apt install metasploitmcp` |
| HexStrike AI | hexstrike-ai | MCP automation over 150+ security tools | `apt install hexstrike-ai` |

> **This is the biggest advantage of the Kali edition over the Windows edition**: all three MCP tools install straight from apt, with no manual GitHub/npm/Docker setup.

This means `bootstrap-reverse.sh` has far less work to do on Kali than on Windows.

---

## 2. Quick Start

### 2.0 One-shot initialization (recommended on a new system)

```bash
# One-shot configuration on a fresh Kali 2026.1 system (requires root)
sudo bash kali/scripts/quick-setup.sh

# Skip the system update (when the network is slow)
sudo bash kali/scripts/quick-setup.sh --skip-update

# Minimal installation (skips the AD/internal network tools)
sudo bash kali/scripts/quick-setup.sh --minimal
```

This script handles everything automatically: system update → install the new 2026.1 tools → configure the native MCPs → install the reversing tools → refresh the index → print a report.

### 2.1 First-time configuration

```bash
# 1. Go to the project root
cd /path/to/cybersecurity-skills-router

# 2. Make the scripts executable
chmod +x kali/scripts/*.sh kali/scripts/lib/*.sh

# 3. Refresh the tool index (detect local tool status)
bash kali/scripts/refresh-tool-index.sh

# 4. View the result
cat skills/tool-index.md
```

### 2.2 Set up the native Kali MCPs in one shot (strongly recommended)

```bash
# Install the three official Kali MCPs
bash kali/scripts/bootstrap-reverse.sh mcp-kali-server metasploitmcp hexstrike-ai

# After installation the MCP config is written to ~/.claude/mcp.json automatically
# If you use Kiro, copy it manually to ~/.kiro/settings/mcp.json
```

### 2.3 Install the new 2026.1 tools

```bash
# Install every new tool in one shot
bash kali/scripts/bootstrap-reverse.sh adaptixc2 atomic-operator sstimap xsstrike wpprobe fluxion gef

# AD / internal network pentest suite
bash kali/scripts/bootstrap-reverse.sh coercer evil-winrm-py netexec responder bloodhound certipy
```

### 2.4 Install missing tools

```bash
# Install a single tool
bash kali/scripts/bootstrap-reverse.sh jadx

# Install several tools
bash kali/scripts/bootstrap-reverse.sh jadx apktool frida jshookmcp

# Install and start the services
bash kali/scripts/bootstrap-reverse.sh idapro --start-services
```

### 2.5 Let the AI client route automatically

Tell your AI client to read `kali/RULES-kali.md` and it will handle the global injection on its own.

---

## 3. Path Conventions

| Purpose | Kali path |
|------|----------|
| Tool installation directory | `~/tools/` or `/opt/` |
| jadx | `/opt/jadx/` or `~/tools/jadx/` |
| apktool | `/usr/local/bin/apktool` (apt) or `~/tools/apktool/` |
| Ghidra | `/opt/ghidra/` or `~/tools/ghidra/` |
| IDA Pro | `/opt/idapro/` (if you have the Linux build) |
| Android SDK | `~/Android/Sdk/` |
| SecLists | `/usr/share/seclists/` (apt) or `~/tools/SecLists/` |
| Node.js | `/usr/bin/node` (apt/nvm) |
| Python | `/usr/bin/python3` (shipped with the system) |
| MCP config | `~/.claude/mcp.json` or `~/.kiro/settings/mcp.json` |

---

## 4. Summary of Differences from the Windows Edition

| Dimension | Windows edition | Kali edition |
|------|-----------|---------|
| Scripting language | PowerShell (.ps1) | Bash (.sh) |
| Package management | winget / GitHub Release ZIP | apt / pip / npm / GitHub Release tar.gz |
| Path separator | `\` | `/` |
| Environment variables | `%USERPROFILE%` | `$HOME` |
| Preinstalled tools | Almost none | Lots of security tools preinstalled |
| Starting IDA | `start.ps1` | Start the Linux build of IDA manually; the script only registers/checks the MCP unless you add your own launcher |
| MCP config path | `%USERPROFILE%\.claude\mcp.json` | `~/.claude/mcp.json` |
| Port checking | `TcpClient` | `nc -z` or `ss` |

---

## 5. Verification Checklist

```bash
# ─── Basic commands ───
java -version
python3 --version
pip3 --version
node -v
npx -v

# ─── Reversing tools ───
jadx --version
apktool --version
adb version
frida --version
r2 -v
gdb --version          # GEF loads automatically

# ─── Pentest tools (preinstalled on Kali) ───
nmap --version
sqlmap --version
hashcat --version
hydra -h | head -1
msfconsole --version
gobuster version
ffuf -V
nuclei -version

# ─── New Kali 2026.1 tools ───
sstimap -h 2>&1 | head -3
xsstrike -h 2>&1 | head -3
wpprobe --help 2>&1 | head -3
coercer -h 2>&1 | head -3
evil-winrm-py -h 2>&1 | head -3

# ─── AD / internal network tools ───
netexec --help 2>&1 | head -3
responder -h 2>&1 | head -3
certipy --version 2>&1 | head -1

# ─── Native Kali MCPs ───
which kali-server-mcp && echo "mcp-kali-server OK"
which metasploitmcp && echo "metasploitmcp OK"
which hexstrike-ai && echo "hexstrike-ai OK"

# ─── Refresh the tool index ───
bash kali/scripts/refresh-tool-index.sh

# ─── Check the MCP services (if already configured) ───
nc -z 127.0.0.1 5000 && echo "mcp-kali-server OK" || echo "mcp-kali-server offline"
nc -z 127.0.0.1 8085 && echo "metasploitmcp OK" || echo "metasploitmcp offline"
nc -z 127.0.0.1 13337 && echo "IDA MCP OK" || echo "IDA MCP offline"
nc -z 127.0.0.1 23816 && echo "anything-analyzer OK" || echo "anything-analyzer offline"
```

---

## 6. FAQ

### Q: What if the radare2 version shipped with Kali is too old?

```bash
# Install the latest version from the official source
bash kali/scripts/bootstrap-reverse.sh r2
# The Kali edition installs/fixes up radare2 through apt by default; if you need the latest version, switch to GitHub/source per the platform documentation
```

### Q: I use Parrot OS / BlackArch, will this work?

Yes. The scripts check whether a command exists, they are not tied to a specific distribution. The only catch is that `apt`-based automatic installation may need to be changed to `pacman` (BlackArch).

### Q: How do I set up the Linux build of IDA Pro?

Install IDA into `/opt/idapro/`, then change the `startScript` path for `idapro` in `kali/scripts/bootstrap-manifest.json`.

### Q: I want to use this system on both Windows and Kali

No problem. The `skills/` directory syncs through Git and the `field-journal/` experience is shared on both sides. The only difference is which scripts you run: `skills/scripts/*.ps1` on Windows, `kali/scripts/*.sh` on Kali.
