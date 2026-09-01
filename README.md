# skills

This is my personal collection of Offensive Security skills for my agentic workflows. It works with Claude Code, Claude Agent SDK, Hermes and any harness that reads `SKILL.md` files.

It has over **100 skills** covering web/API exploitation, identity and Active Directory, cloud and container abuse, mobile reverse engineering, binary RE/pwn, malware and C2 analysis, DFIR, supply chain, and LLM security. Each skill is a self-contained methodology: what to look for, how to prove it, and how to avoid the false positives that waste an engagement.

Most of them were stolen from other repos and a bunch of them I created to consolidate the knowledge I applied in assessments. Use as you will.

## Install

Claude Code will read the skills even if they're just symlinks, so this script will create a symlink for each one of the existing skills in here.

```bash
git clone https://github.com/dbx0/skills.git
cd skills
./install.sh
```
To take a single skill instead:

```bash
ln -s "$PWD/skills/web-appsec/server-side/signed-url-proxy-abuse" ~/.claude/skills/
```

---

## Layout

Skills are organized **domain-first**. The second level is a **MITRE ATT&CK Enterprise tactic** in domains that map onto the kill chain, and a descriptive grouping in domains organized
around a craft rather than an objective. `web-appsec` and `malware-c2` use both. You can check [SKILL_MAP.md](SKILL_MAP.md) for all the existing skills.

```
skills/<domain>/<tactic>/<skill-name>/SKILL.md
```

| Domain | Skills | Covers |
|---|---:|---|
| `methodology/` | 24 | Campaign orchestration, playbooks, decision trees, exploit chaining, triage |
| `web-appsec/` | 20 | Web + API exploitation, request smuggling, SSRF, SSTI, race conditions, bundle recovery |
| `identity-access/` | 13 | AD/Kerberos, Okta/Entra SSO, OAuth/OIDC/JWT, Windows/Linux credential material |
| `binary-re-pwn/` | 10 | Reverse engineering, pwn, firmware, patch-diff, binary diff |
| `mobile/` | 6 | Android/iOS RE, Frida hooking, APK pipelines, runtime analysis |
| `ai-llm/` | 5 | Prompt injection, jailbreak methodology, LLM/agent security |
| `cloud-container/` | 5 | Cloud IAM, instance metadata, Kubernetes, container/kernel escape |
| `_tooling/` | 5 | Non-attack utilities: toolchain drivers, browser automation, docs/diagrams |
| `infra-network/` | 4 | VPN/appliance attacks, vCenter, custom protocol replay, telecom core triage |
| `recon-osint/` | 4 | Attack-surface recon, scope attribution, OSINT |
| `malware-c2/` | 4 | Malware analysis, C2 panel analysis, EDR-bypass RE |
| `forensics-dfir/` | 3 | Timeline reconstruction, PCAP/protocol analysis, OSS forensics |
| `supply-chain/` | 3 | Dependency confusion, typosquatting, CI/CD and registry provenance |
| `crypto-stego/` | 2 | Crypto and steganography challenges |
| `blockchain-web3/` | 1 | Token / rug-pull / smart-contract audit |

`_infra/` holds non-skill repo material (Kali and Burp bridges, helper scripts, upstream docs).


Enjoy :) 
