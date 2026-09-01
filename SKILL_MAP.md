# Skill Map

Skills are organized **domain-first**. What the second level means depends on the domain — see the
table below.

- **Top level** = technique domain (web, identity, cloud, mobile, binary/RE, malware, ...).
- **Second level** = either an ATT&CK Enterprise tactic or a descriptive grouping, depending on the
  domain. Roughly half of each — attack domains that map onto the kill chain use tactics; domains
  organized around a craft rather than an objective use descriptive names.

| Second level | Domains |
|---|---|
| ATT&CK tactics | `recon-osint`, `identity-access`, `cloud-container`, `infra-network`, `forensics-dfir`, `supply-chain` |
| Descriptive | `methodology`, `ai-llm`, `binary-re-pwn`, `mobile`, `crypto-stego`, `blockchain-web3`, `_tooling` |
| Both | `web-appsec` (tactics + `server-side/`), `malware-c2` (tactics + `analysis/`) |

Tactics in use: `reconnaissance`, `initial-access`, `discovery`, `credential-access`,
`privilege-escalation`, `lateral-movement`, `defense-evasion`, `command-and-control`, `collection`.
Each domain section below is annotated so you can tell which scheme applies without guessing.

`_infra/` holds non-skill repo material (Kali/Burp bridges, docs, helper scripts).

---

## 📁 Domain Overview

| # | Domain | Skills | Description |
|---|--------|--------|-------------|
| 01 | `methodology/` | 24 | Campaign orchestration, playbooks, decision trees, mindset, exploit-chaining. |
| 02 | `recon-osint/` | 4 | Attack-surface recon and OSINT. |
| 03 | `web-appsec/` | 20 | Web + API exploitation, smuggling, SSRF, SSTI, race conditions, JS/bundle recovery. |
| 04 | `identity-access/` | 13 | AD/Kerberos, SSO (Okta/Entra), OAuth/OIDC/JWT, Windows/Linux credential material. |
| 05 | `cloud-container/` | 5 | Cloud IAM, metadata, Kubernetes, container/kernel escape. |
| 06 | `infra-network/` | 4 | VPN/appliance attacks, vCenter, custom protocol replay, telecom core triage. |
| 07 | `mobile/` | 6 | Android/iOS reverse engineering, hooking, runtime analysis. |
| 08 | `binary-re-pwn/` | 10 | Reverse engineering, pwn, firmware, patch-diff, binary diff, JS reverse. |
| 09 | `malware-c2/` | 4 | Malware RE, config extraction, C2 panel analysis, EDR bypass. |
| 10 | `forensics-dfir/` | 3 | OSS supply-chain forensics, DFIR timelines, PCAP analysis. |
| 11 | `crypto-stego/` | 2 | Cryptography, encoding, steganography. |
| 12 | `ai-llm/` | 5 | LLM jailbreak, prompt injection, agent/MCP abuse, LLM security. |
| 13 | `supply-chain/` | 3 | Dependency confusion, typosquatting, CI/CD, provenance. |
| 14 | `blockchain-web3/` | 1 | Token / smart-contract security audit. |
| — | `_tooling/` | 5 | Non-attack utilities: pentest toolchain, browser automation, diagram/docs generators, RE index. |
| — | `_infra/` | — | Repo infrastructure (not skills). |

---

## 01 · methodology/  (descriptive subfolders)

### orchestration/
- `offsec-campaign-orchestrator` — master offensive-campaign workflow
- `subagent-hunt-orchestration` — split campaigns across specialist subagents
- `ctf-sandbox-orchestrator` — CTF-sandbox master entrypoint/router
- `attack-chain-multistage` — multi-stage "A→B" attack-path orchestrator

### workflows/
- `pentest-playbook` — 7-phase pentest pipeline
- `deep-hunt` — deep single-workflow attack mode
- `manual-decision-trees` — manual testing decision trees
- `bug-bounty` — bug bounty lifecycle: validation → triage → report
- `bugbounty-hunt` — end-to-end BB/VDP engagement driver: scope → recon → hunt → `HUNT.md` + `vuln/` writeups
- `src-hunter` — 5-phase workflow for bug bounty and crowdsourced-testing programs
- `continuous-surface-monitoring` — continuous recon + campaign memory
- `mid-engagement-ir-detection` — detect client SOC/IR changes mid-engagement

### exploit-chaining/
- `attack-chain` — visible exploit-chain builder from primitives
- `exploit-chaining-engine` — score/prioritize/compose weak findings

### triage/
- `artifact-pivot-intelligence` — public-artifact-first methodology
- `archive-credential-recovery` — Wayback/CDX mining of dead deploys for live secrets
- `build-env-secret-triage` — does a matched `process.env` secret actually ship to the browser?
- `credential-verification` — prove a recovered key is live without abusing it (three-state method)
- `gateway-layer-attribution` — did the gateway or the upstream app answer? Read 401/403/404 correctly before concluding
- `client-runtime-intelligence` — front-end bundle → route/auth map
- `cloud-exposure-triage` — exposed cloud/identity/storage triage
- `protocol-surface-triage` — service/port/banner → attack meaning

### mindset/
- `offensive-security` — unified offensive methodology umbrella
- `redteam-mindset` — operator discipline / mindset corrections

---

## 02 · recon-osint/

### reconnaissance/
- `sherlock` — username OSINT across 400+ networks
- `web2-recon` — subdomain/host/URL/JS/API recon pipeline
- `egress-waf-evasion` — geo/WAF/bot-manager block diagnosis, IP-burn hygiene, edge/gateway stack fingerprint
- `scope-attribution` — prove the target actually operates a host before testing it (CNAME/SaaS/ISP/honeypot traps)

---

## 03 · web-appsec/  (ATT&CK tactics + descriptive `server-side/`)

### discovery/
- `vulnerability-hunting` — 27 web/cloud/auth/protocol hunting patterns
- `api-security` — GraphQL/REST/gRPC testing
- `competition-bundle-sourcemap-recovery` — sourcemap/bundle recovery
- `competition-graphql-rpc-drift` — GraphQL/RPC schema drift
- `graphql-schema-reconstruction` — enumerate schema when introspection is blocked (error oracles, `@skip(if:true)`)
- `postmessage-security` — `window.postMessage` listener sweeps, origin-check bypass, sink proof

### initial-access/
- `request-smuggling-specialist` — HTTP request smuggling/desync
- `flask-werkzeug-attack` — Flask/Werkzeug debugger RCE
- `competition-web-runtime` — CTF web/API/SSR runtime
- `competition-request-normalization-smuggling` — parser-differential smuggling
- `competition-ssrf-metadata-pivot` — SSRF → internal/metadata pivot
- `competition-template-render-path` — SSTI / render path
- `competition-file-parser-chain` — file upload/parser abuse
- `competition-race-condition-state-drift` — race windows / state drift
- `competition-queue-worker-drift` — queue/async worker drift
- `competition-runtime-routing` — host/forwarded-header/vhost routing
- `competition-websocket-runtime` — WebSocket/SSE runtime
- `waf-path-bypass` — edge 403 vs origin: trailing-slash / path-normalization bypass

### server-side/
- `signed-url-proxy-abuse` — HMAC-signed proxy URLs: signing oracles, signer/fetcher normalisation mismatch, real-SSRF test

### collection/
- `competition-browser-persistence` — browser cookie/storage/credential harvest

---

## 04 · identity-access/

### credential-access/
- `okta-attack` — Okta IdP: enum, MFA bypass
- `m365-entra-attack` — M365/Entra ID attack chain
- `competition-identity-windows` — AD/Kerberos/LDAP/OAuth identity
- `competition-jwt-claim-confusion` — JWT/JWS/JWE claim confusion
- `competition-oauth-oidc-chain` — OAuth/OIDC redirect/state/PKCE
- `competition-lsass-ticket-material` — LSASS secrets / ticket material
- `competition-dpapi-credential-chain` — DPAPI / vault / browser creds
- `competition-relay-coercion-chain` — forced-auth coercion / NTLM relay
- `competition-linux-credential-pivot` — Linux credential artifacts / SSH

### privilege-escalation/
- `competition-kerberos-delegation` — delegation / S4U / RBCD abuse
- `competition-ad-certificate-abuse` — AD CS certificate abuse

### lateral-movement/
- `competition-windows-pivot` — Kerberos/WinRM/SMB/RDP pivot

### collection/
- `competition-mailbox-abuse` — enterprise mail / OAuth consent abuse

---

## 05 · cloud-container/

### credential-access/
- `competition-cloud-metadata-path` — cloud metadata / workload identity
- `competition-container-runtime` — container runtime / mounted secrets

### privilege-escalation/
- `cloud-iam-deep` — AWS/Azure/GCP IAM attack chain
- `competition-k8s-control-plane` — Kubernetes API / RBAC edges
- `competition-kernel-container-escape` — kernel / namespace / container escape

---

## 06 · infra-network/

### initial-access/
- `enterprise-vpn-attack` — SSL VPN / remote-access appliance matrix
- `vmware-vcenter-attack` — vSphere/vCenter external attack matrix
- `competition-custom-protocol-replay` — custom binary/text protocol replay
- `telecom-surface-triage` — exposed 3GPP/GBA/BSF/SIP/IMS carrier-core recognition + subscriber-safe proof

---

## 07 · mobile/  (descriptive subfolders)

### reverse-engineering/
- `apk-redteam-pipeline` — end-to-end Android APK red-team pipeline
- `apk-reverse` — APK unpack/decompile/smali/repack/Frida
- `applink-declaration-analysis` — `assetlinks.json` / AASA mining → app ids, staging builds, claimed paths
- `mobile-reverse` — iOS/Android runtime analysis & hooking
- `competition-android-hooking` — Android Frida hooking / signing recovery
- `competition-ios-runtime` — IPA runtime / Frida / ObjC-Swift

---

## 08 · binary-re-pwn/  (descriptive subfolders)

### reverse-engineering/
- `reverse-engineering` — core static/dynamic RE
- `ida-reverse` — IDA Pro analysis
- `radare2` — radare2 CLI analysis
- `binary-diff` — cross-version symbol migration / diffing
- `js-reverse` — JS/TS reverse (bundlers, obfuscation)
- `firmware-pentest` — firmware image → reverse → emulate → exploit
- `competition-firmware-layout` — firmware partition/boot layout

### exploitation/
- `pwn-chain` — reverse → vuln → working exploit
- `patch-diff-exploit` — N-day patch diff → PoC
- `competition-reverse-pwn` — CTF reverse/pwn workflow

---

## 09 · malware-c2/  (ATT&CK tactics + descriptive `analysis/`)

### analysis/
- `malware-analysis` — malware RE, unpacking, C2 extraction
- `competition-malware-config` — malware config recovery

### defense-evasion/
- `edr-bypass-re` — reverse EDR/AV hooks → bypass

### command-and-control/
- `c2-panel-analysis` — threat-actor C2 panel analysis

---

## 10 · forensics-dfir/

### collection/
- `oss-forensics` — 7-phase OSS supply-chain forensic investigation
- `competition-forensic-timeline` — DFIR chronology / cross-artifact correlation
- `competition-pcap-protocol` — PCAP analysis / session reconstruction

---

## 11 · crypto-stego/  (descriptive subfolders)

### steganography/
- `competition-stego-media` — image/audio/video/document/container stego

### crypto/
- `competition-crypto-mobile` — crypto/encoding/stego + mobile trust

---

## 12 · ai-llm/  (descriptive subfolders)

### jailbreak/
- `godmode` — GODMODE / Parseltongue / ULTRAPLINIAN
- `red-teaming-ops` — LLM jailbreak + IR opsec
- `llm-security` — prompt injection, jailbreak, model extraction

### prompt-injection/
- `competition-prompt-injection` — prompt injection / retrieval poisoning
- `competition-agent-cloud` — AI-agent / MCP / toolchain + cloud abuse

---

## 13 · supply-chain/

### reconnaissance/
- `supply-chain-attack-recon` — external supply-chain recon

### initial-access/
- `supply-chain-security` — dependency confusion / typosquatting / CI-CD
- `competition-supply-chain` — CI/CD / registry / provenance drift

---

## 14 · blockchain-web3/  (descriptive subfolders)

### audit/
- `meme-coin-audit` — token / rug-pull / smart-contract audit

---

## _tooling/  (non-attack utilities)

- `pentest-tools` — active pentest toolchain (recon/scan/SQLi/dirbust/cracking)
- `browser-automation` — headless/CDP browser automation for RE
- `diagram-generator` — diagrams from natural language
- `docs-generator` — documentation generation
- `re-ctf-index` — router/index for the RE-CTF skill collection

## _infra/  (repo material, not skills)

- `kali/`, `burp-mcp-full/`, `docs/`, `scripts/`, `claude-bughunter-scripts/`, top-level README/RULES/ARCHITECTURE docs.
