# src-hunter Methodology Entry Point

> Perspective: black-box SRC / crowd-testing / bug bounty (H1, Bugcrowd, Butian, CNVD)
> Assumption: the attacker only has a URL, parameters, and HTTP-capture ability, **no source code**

---

## How to use this methodology

The hunter's workflow is cut into 4 segments, each corresponding to one file in this directory:

```
[01] Target selection — decide where to hit first (attack priority)
        │
        ▼
[02] Opening move — craft the payload, with a bypass matrix (bypass toolkit)
        │
        ▼
[04] Control-gap hunting — translate "sensitive operation ↔ expected control" into black-box probing strategy
        │
        ▼
[03] Wrap-up — evidence discipline: captures, echoes, out-of-band, reproduction rate; never write "guessed" vulnerabilities
```

| File | Role | When to read it |
|------|------|-----------------|
| `01-attack-priority.md` | Decide the report order RCE > file write > auth bypass > injection > info disclosure, with quantified P0–P3 scoring | When selecting targets / ordering report priority |
| `02-bypass-toolkit.md` | General bypass decision trees for SQLi, XSS, command, path, SSRF, WAF + encoding dictionaries | Whenever a payload is blocked |
| `03-evidence-discipline.md` | Black-box evidence discipline: HTTP packets, echoes, DNSLog, diff, reproduction rate; how to avoid "I assumed" vulnerabilities | Before writing the report |
| `04-control-gap-hunting.md` | Translate 9 classes of sensitive operations (data modification/bulk/permission/funds/SSRF/file/command/auth/authz) into "which controls should exist, and how to probe for their absence" | When you get a new feature and don't know where to start |

---

## Alignment with SRC platforms

Different platforms have different preferences for "scoring factors":

| Platform | Preferred vulnerability types | Must have |
|------|---------------|--------|
| **HackerOne** | RCE, Auth Bypass, IDOR, SQLi, SSRF | CVSS 3.1 or 4.0 + executable PoC + impact scope |
| **Bugcrowd** | VRT grading (P1–P5), prefers chainable attack chains | Reproducible steps + screenshots/video |
| **Butian / CNVD** | General-purpose RCE, SQLi, unauthenticated access, sensitive info disclosure | Vulnerability proof (screenshots, reproduction packets) |
| **Crowd-testing / cyber-drill** | Intranet entry, control, lateral movement | Impacted-asset inventory + post-exploitation evidence |

**Unified rules**:
1. Only test authorized assets, no spillover
2. No deletion / no modification / no bulk data dumping — prove and stop
3. Redact data (mask usernames, phone numbers)
4. No uploading / no leaving webshells; command execution only runs read-only commands (`id`, `whoami`, `uname -a`)

---

## Value ranking (condensed)

| Tier | Vulnerability type | Average bounty range (reference: H1 / Bugcrowd) |
|------|---------|---------------------------------|
| Top | Unauthenticated RCE / SSRF→RCE / deserialization | $5k – $50k |
| High | Auth bypass / broad public-IDOR data / arbitrary file read | $1k – $10k |
| Medium | SQLi / authorization abuse / file upload (restricted) | $300 – $3k |
| Low | XSS / info disclosure (no sensitive data) | $50 – $500 |

> This order is the cash embodiment of the "shortest attack path principle" in `01-attack-priority.md`.

---

## Companion playbook directory

See `../playbooks/00-index.md` for the vulnerability-type classification.
