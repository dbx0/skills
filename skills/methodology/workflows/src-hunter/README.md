**Main** · [English](README.en.md)

# src-hunter

This is a Claude Code skill for SRC, crowd-testing, and bug bounty work.

Put simply: you give it a target, and it drives vulnerability hunting through a fixed pipeline: first confirm the target scope, then do intelligence gathering and asset enumeration, then move into vulnerability testing, and finally compile the report.

```text
intake → recon → enum → hunt → report
```

The project bundles a knowledge base compiled from public sources, including:

- 19 classes of attack playbooks
- 305 structured payloads
- WAF / EDR bypass variants
- HackerOne disclosed High / Critical hacktivity data
- WooYun historical case statistics residue
- Common Chinese-stack component fingerprints and default credentials

## Install

Marketplace:

```bash
/plugin marketplace add MyuriKanao/src-hunter-skill
/plugin install src-hunter@src-hunter
```

Git:

```bash
git clone https://github.com/MyuriKanao/src-hunter-skill.git ~/.claude/skills/src-hunter
```

## Directory structure

```text
references/
  methodology/    five-phase workflow, attack priority, bypass toolkit, evidence rules
  playbooks/      one file per vulnerability class, with real H1 cases and payloads
  industry/       banking/finance and telecom/ISP vertical playbooks
  dictionaries/   Chinese-stack component fingerprints and default credentials
  templates/      CVSS 4.0 report template
  h1-reports/     raw data for 2887 disclosed reports, grouped by weakness
  payloader/      305 structured payloads, 263 WAF/EDR bypass steps, 114 tool commands
```

The playbooks are the main entry point. All playbooks are written from a black-box perspective, assuming you only have a URL and no source code.

Every playbook is organized around the same set of questions:

- Where to find entry points
- Which payloads to test with
- Which response characteristics to observe
- How to judge impact
- How to raise the vulnerability's value
- Which actions are off-limits

The overall philosophy is not to pile up payloads, but to string together the testing actions, evidence retention, and report output.

## MCP tool integration

This skill integrates a local MCP server as a tool layer, letting Claude directly invoke browser automation, CDP debugging, network interception, JS hooks, AST deobfuscation, Frida memory verification, WASM reversing, source-map reconstruction, Android adb bridging, SSL-pinning bypass, and more during the hunt phase.

**Current primary choice**: [jshookmcp](https://github.com/vmoranv/jshookmcp) 0.3.0 (134 curated tools / 386 full set / 36 domains). See [`references/tools/mcp-jshook.md`](references/tools/mcp-jshook.md) for the full index and scenario mapping.

Seven high-affinity playbooks (`xss` / `rce` / `ssrf-cache-host` / `mobile` / `oauth-saml-jwt` / `api-rest` / `file-upload`) each carry a `## Related MCP tools` reverse-anchor at the end, indicating which jshook tools to reach for on that attack surface and when.

## TODO

- Support integrating more tools
- Multi-agent execution workflow

## Trigger keywords

The skill's built-in trigger terms include:

- bug bounty, HackerOne, SRC hunting, bug bounty rewards, crowd testing
- WAF bypass, bypass the WAF
- how to test a given endpoint / API / parameter
- arbitrary account, arbitrary modify, arbitrary delete
- password reset, password recovery
- default credentials, Actuator, exposed admin console

It can also be invoked explicitly:

```text
/src-hunter <target>
```

## Playbook list

| Playbook | Embedded H1 cases |
|---|---:|
| arbitrary-x-authz (IDOR / account takeover / privesc) | 465 |
| rce (deserialization / SSTI / XXE / framework) | 385 |
| xss | 335 |
| info-disclosure | 319 |
| oauth-saml-jwt | 240 |
| logic-flaws (CSRF / clickjacking / payment) | 234 |
| path-traversal / LFI / RFI | 163 |
| sqli | 147 |
| dos | 138 |
| ssrf-cache-host | 108 |
| unauth-access (default credentials / Actuator / exposed services) | 46 |
| http-smuggling / CRLF | 38 |
| api-rest / WebSocket | 15 |
| file-upload | 8 |
| mobile (Android / iOS) | 8 |
| race-conditions | 5 |
| llm-prompt-injection | 1 |
| graphql | 1 |
| intranet-postexp (intranet / post-exploitation cheat sheet) | — |

## Data sources

- HackerOne hacktivity feed: 2887 disclosed High / Critical reports, sourced from public data.
- WooYun historical archive: covers 88,636 cases, retaining only statistical residue such as parameter frequency, case IDs, and bypass patterns.
- Payloader: 305 structured payloads + 263 WAF / EDR bypass steps + 114 tool commands, original repo `3516634930/Payloader`.

This project only organizes, translates, and recombines public material; it contains no proprietary data and does not scrape content that requires authentication.

## Red lines

Every playbook writes out its specific boundaries at the end. Below are a few of the most commonly crossed:

- **Sample control**: for SQLi, proving the database name / version is enough — don't dump data; for IDOR, Mongo / ES data pulls, 1–3 sample records is enough, not the full set.
- **Test-account self-demonstration**: authorization bypass, password reset, JWT forgery, redirect_uri, blind XSS — all tested between two accounts you registered yourself. **Never touch a stranger's account** — even if you can.
- **Read, don't write**: with RCE, only run `id` / `whoami` / `uname -a`; with unauthenticated Redis / Mongo, only `info` / `ping` / `db.version()`; with arbitrary file read, stop at the `root:x:` line — don't read `/etc/shadow`.
- **Don't actually trigger side effects**: don't actually send SMS, don't actually charge, don't actually send email, don't actually refund, don't actually overwrite files, don't actually modify announcements / mail templates. Prove the endpoint is reachable + returns 200, then stop.
- **DoS / concurrency**: a single reproduction ≤ 60s, run serially 5 times. Race-condition concurrency 50–100, never 1000+. For unthrottled SMS / email, send to your own phone 5–10 times at most.
- **Leave nothing behind**: webshells, heapdumps, backups, dumped source — save locally, delete immediately after reporting, don't push to GitHub / third-party cloud storage.
- **Credentials: obtained but not used**: leaked AWS / Stripe / database credentials — only validate with `sts get-caller-identity` / a banner check, never use them to charge / send email / connect to production databases.
- **Redact all PII in reports**: phone numbers, emails, usernames, tokens, cookies — keep first 2 + last 2, and if necessary attach a sha256 fingerprint to prove you had the original.
- **OOB validation**: don't use public DNSLog platforms; use the vendor-provided SSRF testing platform, or self-host interactsh / your own DNSLog.
- **No capture, no finding**: every assertion needs an HTTP packet / screenshot / video — don't submit based on "it should."

Each vulnerability class has finer-grained limits (DoS is the most sensitive, uploads leave no webshell, read-class takes only 1 sample record, etc.); see the last section of the corresponding playbook.

## Friendship links
[linuxdo](https://linux.do/)
## License

MIT.

Data sources are all public material. This project mainly organizes, translates, and categorizes the material, packaging it into a Claude Code skill suited for black-box vulnerability hunting.
