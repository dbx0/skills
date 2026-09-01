---
name: src-hunter
description: Practical SRC / crowd-testing / bug bounty vulnerability-hunting workflow skill. Includes a 5-phase methodology (intake → recon → enum → hunt → report), 19 attack-class playbooks (SQLi/XSS/RCE/SSRF/IDOR/CSRF/Path Traversal/File Upload/SSTI/XXE/Race/HTTP Smuggling/OAuth/JWT/SAML/GraphQL/Mobile/LLM/DoS), 305 structured payloads, 263 WAF/EDR bypass variants, 2887 real disclosed High/Critical HackerOne cases, 77,000+ WooYun case statistics, a fingerprint library for Chinese-stack OA / middleware, and vertical playbooks for the banking and telecom industries. Triggers when the user mentions "SRC hunting / SRC vulnerability hunting / bug bounty / crowd testing / hackerone / bug bounty / SRC / arbitrary-X vulnerabilities / penetration testing" or asks "how to hunt a given target / how to test a given API / how to bypass a WAF".
argument-hint: "<target-or-program-or-phase>"
level: 2
---

# SRC Hunter — Practical Vulnerability-Hunting Workflow

A practical Security Response Center / crowd-testing / bug bounty hunting skill. It translates white-box methodology into black-box probing, layered with real case statistics and a payload library.

---

## When to use this skill

**Keyword matches**:
- "SRC hunting" / "SRC vulnerability" / "SRC testing" / "Security Response Center"
- "bug bounty" / "bug bounty rewards" / "crowd testing"
- "hackerone" / "h1" / "bugcrowd" / "intigriti" / "yeswehack"
- "how to hunt / how to test / how to attack + a given target / endpoint / parameter"
- "WAF bypass" / "bypass the WAF" / "WAF bypass"
- Authorization abuse such as "arbitrary account / arbitrary modify / arbitrary delete / arbitrary operation"
- Logic flows such as "password reset" / "password recovery"
- "unauthenticated access" / "default credentials" / "Actuator" / "Spring exposure" / "unauthenticated Redis"
- The user gives you a URL or API endpoint to test

**When NOT to use this skill**:
- Pure white-box source code audit (use the `code-audit` skill)
- Fix / defense Q&A for known vulnerabilities (use general conversation)
- Standalone CTF challenges (this is a real-environment workflow)

---

## Workflow — 5 phases

### Phase 1 · Intake

Input: program name / SRC entry URL / subdomain.

Things to do:
- Capture the Scope (in-scope domains / IPs / mobile apps / API endpoints)
- Capture Out-of-scope (prohibited content, third-party services, cloud assets exclusions)
- Capture the rules (payout tiers, disclosure window, retest policy, safe-harbor)
- Capture test accounts / test headers (e.g. `X-Bug-Bounty: <handle>`)

**Priority assessment** (estimate hit rate based on match type; see `references/methodology/05-srctimebox-priority.md`):
- 6-hour window → run high-hit-rate types (password reset 88% / arbitrary account 86.4% / withdrawal 83.1%)
- Single-day window → add information disclosure + asset exposure + Actuator
- Cyber-drill / peak periods → the full spectrum

→ See [`references/methodology/00-index.md`](references/methodology/00-index.md)

### Phase 2 · Recon (passive reconnaissance)

Intelligence gathering that sends no packets to the target:

- **CT logs**: crt.sh / Censys (find subdomains)
- **Historical snapshots**: Wayback / CommonCrawl
- **GitHub search**: `org:target` + keywords (password / api_key / SECRET)
- **Search-engine dorks**: `site:target.com inurl:/admin`, `filetype:env`, `intitle:Index of`
- **ASN / IP ranges**: bgp.he.net to find IP blocks
- **Favicon hash**: FOFA / Shodan to find assets sharing the same favicon
- **DNS history**: SecurityTrails / Whoisxmlapi

### Phase 3 · Enum (active probing)

**Asset enumeration**:
- Subdomains: amass / subfinder / puredns / dnsx
- Liveness: httpx / naabu
- Screenshots: gowitness / aquatone
- Content discovery: ffuf / feroxbuster / dirsearch
- Tech fingerprinting: wappalyzer / webanalyze (also check `references/dictionaries/chinese-srcfingerprints.md` for Chinese-stack component hits)
- JS extraction: linkfinder / subjs / gau / katana
- Subdomain-takeover fingerprints: subjack / subzy

### Phase 4 · Hunt (vulnerability probing)

Follow the corresponding playbook by attack type. **Every playbook contains**: methodology + parameter-frequency table + real H1 cases + structured payloads + WAF bypass variants.

**Priority path** (sorted by hit rate + value):

| Playbook | Entry hint | File |
|---|---|---|
| **Unauthenticated access** | Actuator/Swagger/default ports/weak passwords | `references/playbooks/unauth-access.md` |
| **Information disclosure** | .git/.svn/.env/heapdump/path listing | `references/playbooks/info-disclosure.md` |
| **Arbitrary-X authz** | User-tier ID is enumerable/modifiable | `references/playbooks/arbitrary-x-authz.md` |
| **Business logic** | password reset/payment/orders/verification codes | `references/playbooks/logic-flaws.md` |
| **OAuth/SAML/JWT** | auth flows/redirect_uri/token | `references/playbooks/oauth-saml-jwt.md` |
| **API REST** | BOLA/Mass Assignment/rate | `references/playbooks/api-rest.md` |
| **SQLi** | any user input reaching the DB | `references/playbooks/sqli.md` |
| **RCE** | deserialization/SSTI/XXE/prototype chain/framework | `references/playbooks/rce.md` |
| **SSRF** | URL parameters/cache/Host injection | `references/playbooks/ssrf-cache-host.md` |
| **Path traversal** | file-path parameters/LFI/RFI | `references/playbooks/path-traversal.md` |
| **File upload** | upload points + parsing flaws | `references/playbooks/file-upload.md` |
| **XSS** | any user input reaching HTML/JS | `references/playbooks/xss.md` |
| **HTTP smuggling** | reverse proxy + Content-Length | `references/playbooks/http-smuggling.md` |
| **GraphQL** | introspection/nesting | `references/playbooks/graphql.md` |
| **Race conditions** | concurrent requests / TOCTOU | `references/playbooks/race-conditions.md` |
| **DoS** | ReDoS / unthrottled resources / algorithmic blowup | `references/playbooks/dos.md` |
| **Mobile** | Android / iOS APK | `references/playbooks/mobile.md` |
| **LLM Agent** | prompt injection / tool calls | `references/playbooks/llm-prompt-injection.md` |
| **Intranet post-exploitation** | credentials / lateral movement / domain | `references/playbooks/intranet-postexp.md` |

**General methodology** (attack-type agnostic):

| Document | Key content |
|---|---|
| [`methodology/01-attack-priority.md`](references/methodology/01-attack-priority.md) | RCE > file write > auth bypass > injection > info disclosure value ranking |
| [`methodology/02-bypass-toolkit.md`](references/methodology/02-bypass-toolkit.md) | General bypass decision tree + encoding / obfuscation / WAF |
| [`methodology/03-evidence-discipline.md`](references/methodology/03-evidence-discipline.md) | Black-box evidence rules + anti-hallucination + compliance |
| [`methodology/04-control-gap-hunting.md`](references/methodology/04-control-gap-hunting.md) | 9 classes of sensitive operations → expected controls → probing for gaps |
| [`methodology/05-srctimebox-priority.md`](references/methodology/05-srctimebox-priority.md) | 6h / single-day / cyber-drill / monthly time-box templates |

**Industry-vertical playbooks** (check first when asset-relevant):

| Industry | Document | When to use |
|---|---|---|
| Banking / payment / finance | [`industry/banking-finance.md`](references/industry/banking-finance.md) | Target involves payment / online banking / third-party payment aggregation |
| Telecom / ISP | [`industry/telecom-isp.md`](references/industry/telecom-isp.md) | Target is a carrier / BOSS / NMS / IoT SIM platform |

**Dictionaries / credentials**:

| Document | Purpose |
|---|---|
| [`dictionaries/default-credentials-cn.md`](references/dictionaries/default-credentials-cn.md) | Chinese-vendor credentials for Seeyon / Tongda / Wanhu / Weaver / Yonyou / Kingdee / Huawei / ZTE / Hikvision, etc. |
| [`dictionaries/chinese-srcfingerprints.md`](references/dictionaries/chinese-srcfingerprints.md) | Chinese-stack OA / middleware fingerprints + high-frequency parameters + one-click detection commands |

### Phase 5 · Report (submission)

→ Use the template [`templates/report-submission.md`](references/templates/report-submission.md)

**Three-part skeleton**:
1. **Title**: precise to endpoint + vulnerability type, no more than 80 characters
2. **Reproduction steps**: each step executable / screenshot / HAR
3. **Impact + remediation advice**: CVSS 4.0 vector + business impact section

---

## MCP tool integration

This skill supports calling a local MCP server as a tool layer. **Primary choice: jshookmcp** (134 curated tools / 386 full set / 36 domains, with a built-in Burp Suite bridge / Frida / WASM / anti-debug / Android adb / sourcemap reconstruction). Full index and scenario mapping:

→ [`references/tools/mcp-jshook.md`](references/tools/mcp-jshook.md)

The default recommendation is the `search` profile (context cost ~3K tokens), activating tools on demand via `mcp__jshook__search_tools` + `mcp__jshook__activate_tools`, to avoid the `full` profile loading 40K+ tokens all at once.

---

## Data asset scale

| Category | Volume |
|---|---|
| Attack-class playbooks | 19 |
| General methodology documents | 6 |
| Industry-vertical playbooks | 2 (banking / telecom) |
| Dictionaries / credentials | 3 |
| Report templates | 1 |
| Structured payloads | **305** (177 web + 128 intranet) |
| WAF / EDR bypass variants | **263 steps**, covering 23 classes of web attacks |
| Tool command cheat sheet | 114 entries (Nmap/SQLMap/Burp/MSF/...) |
| Real HackerOne cases (disclosed High/Critical) | **2887**, sorted by weakness into 141 category MDs |
| WooYun historical case statistics (non-regenerable) | 88,636 |

The real H1 cases are **embedded directly at the end of each corresponding playbook** (each playbook ends with a "H1 Real Cases" Top 12 table + summaries).

---

## Compliance and legal red lines

Every playbook ends with a "things not to do" section. General red lines (observe on any SRC):

- ❌ Out-of-scope assets / domains → stop immediately and report
- ❌ Actually taking someone's PII → only prove access, then destroy immediately
- ❌ Sustained load / DoS / high traffic → only 1–3 PoC packets, then stop immediately
- ❌ Modifying someone else's data (even with write access) → only validate on objects you control
- ❌ Phishing or social engineering in production → don't
- ❌ Submitting unverified guesses → you must have HTTP packet / screenshot / video evidence
- ✅ Tag yourself with a test header (e.g. `X-Bug-Bounty: <handle>`)
- ✅ Use two of your own accounts to self-demonstrate authorization-bypass scenarios
- ✅ Use an OOB domain for SSRF probing; don't use someone else's DNSLog
- ✅ Self-check against `references/templates/report-submission.md` before submitting

---

## CLI mnemonic prefix

`srchunter` (e.g. `srchunter scope set <program>`, `srchunter recon run`, `srchunter findings new <type>`). The CLI is not currently implemented; this is only a naming convention.

---

## Reference / cross-link structure

```
src-hunter/
├── SKILL.md                    # this file — skill entry point
├── README.md                   # project description
└── references/
    ├── methodology/   6 docs   # general tactics
    ├── playbooks/    19 docs   # attack-class playbooks (each with H1 cases + payload library)
    ├── industry/      3 docs   # industry verticals
    ├── dictionaries/  3 docs   # dictionaries / credentials
    ├── templates/     1 doc    # report template
    ├── h1-reports/             # raw data for 2887 H1 reports + 141-category MD
    │   ├── raw/                # raw JSON (for resume / secondary analysis)
    │   └── by-weakness/        # Markdown grouped by CWE
    └── payloader/              # 305 structured payload records
        ├── raw/                # JSON (machine-readable)
        ├── by-category/        # MD grouped by category
        ├── tools/              # tool commands
        └── waf-bypass.md       # 263-step WAF bypass collection
```
