# Shortest Attack Path Principle — Black-box Hunter Edition

> Perspective: black-box SRC, focused on **bounty value / reproduction cost / platform review priority**, not the CVSS textbook

---

## 1. One-sentence principle

**Attackers always take the path of least resistance — SRC reports should be queued by "resistance" too.**

Resistance = authentication barrier + reproduction steps + exploit tooling barrier + social-engineering dependency.
The lower the resistance, the higher the bounty and the faster the platform review.

---

## 2. Four-dimension scoring (0–3 per dimension, total 0–12)

| Dimension | 3 (best) | 2 | 1 | 0 |
|------|-------------|------|------|------|
| **Auth barrier** | No login required at all | Ordinary registered user | Privileged user (VIP / merchant) | Admin only |
| **Request complexity** | Single HTTP request | 2–3 steps | Requires race condition | Requires precise timing / multi-day |
| **Social-eng dependency** | No user interaction needed | Requires clicking a link | Requires user input | Requires admin action |
| **Exploit barrier** | curl / browser | Common tools (Burp, sqlmap) | Requires writing your own exploit | Requires a 0day |

**Grading**:
- **P0 (10–12)**: report immediately, platform handles as Critical
- **P1 (7–9)**: High, follow up in 48–72h
- **P2 (4–6)**: Medium
- **P3 (0–3)**: Low / Info (most platforms don't accept)

---

## 3. Vulnerability type × default value matrix

Baseline scores assume the best case of "single request + no auth". **Actual reports must deduct points for real conditions.**

| Vulnerability type | Baseline P tier | SRC value (H1 median) | Notes |
|---------|------------|---------------------|------|
| **Unauthenticated RCE** | P0 | $5k–$50k | Direct server control |
| **Unauthenticated SSRF→cloud metadata** | P0 | $3k–$20k | AWS/Alibaba Cloud metadata |
| **Arbitrary file write** | P0 | $3k–$15k | Equivalent to RCE |
| **Arbitrary file read (incl. `/etc/passwd` / config)** | P0/P1 | $1k–$8k | Depends on what you read |
| **Unauthenticated database / Redis / Mongo** | P0 | $1k–$10k | See `playbooks/unauth-access.md` |
| **Auth bypass / privesc (normal→admin)** | P0/P1 | $2k–$15k | |
| **Critical-function IDOR (orders / PII / payment)** | P1 | $500–$5k | Depends on leak volume |
| **SQLi (dumpable)** | P1 | $1k–$8k | +50% more with DBA privileges |
| **Stored XSS (admin console)** | P1 | $300–$3k | Chain with CSRF / IDOR to raise score |
| **Unauthenticated info disclosure (.git/.svn/backups)** | P1 | $500–$3k | Raise to P0 if it contains DB passwords |
| **Logic flaws (password reset / payment tampering)** | P1 | $500–$5k | |
| **CSRF (sensitive operations)** | P2 | $100–$1k | Often merged when submitted alone |
| **Reflected XSS** | P2 | $50–$500 | Increasingly rejected by platforms |
| **Open redirect** | P3 | $0–$200 | Marked N/A by most platforms |

> Data combines public H1 reports + Bugcrowd VRT; specific platform standards are governed by the target's policy.

---

## 4. Value escalation chains (Chain to escalate)

Rather than reporting a P2, chain it up to P0. Common escalation chains:

```
Open redirect         → chain with OAuth   → account takeover (P1)
Reflected XSS         → chain with admin console → console compromise (P1)
SSRF (arbitrary URL)  → probe intranet 6379 → Redis write SSH public key (P0)
Arbitrary file read   → read /proc/self/environ / config → grab DB password (P0)
SQLi ordinary user    → read admin hash → offline crack / change password (P0/P1)
IDOR                  → change role=admin → authz privesc (P0)
Default creds admin/admin → console upload → Webshell (P0)
.git leak             → read source → find hardcoded secret / intranet (P0)
```

Report the version with the **longest chain / highest endpoint** to maximize the bounty.

---

## 5. 9 classes of sensitive operations × black-box priority

The table below translates the "white-box controls" of `sensitive_operations_matrix.md` into "the first black-box probes to run."
For each operation type, open with a shot at "is a key control missing?".

| Operation type | Identifying features (URL / parameters) | Control gaps to probe | If missing |
|---------|----------------------|--------------|--------|
| **Data modification** | POST/PUT/DELETE, contains `id`/`uid`/`oid` | Auth / resource ownership | IDOR / authz abuse (P1) |
| **Data access (GET single)** | `/user/{id}`, `/order/{id}` | Resource ownership | Horizontal IDOR (P1) |
| **Bulk / export** | `/export`, `/download`, `/batch` | Auth + scope limits + count limits | Mass data leak (P1) |
| **Permission change** | `/role`, `/grant`, `/permission` | Elevated authorization + boundary checks | Privesc to admin (P0) |
| **Fund operations** | `/transfer`, `/pay`, `/refund` | Amount validation + idempotency + concurrency | Amount tampering / double-spend (P0) |
| **External HTTP** | `/fetch`, `/preview`, `/import?url=` | URL allowlist + protocol restriction + intranet blocking | SSRF (P0/P1) |
| **File upload** | multipart/form-data | Type + content + path validation | Upload webshell (P0) |
| **File read / download** | contains `path`/`file`/`filename` | Path normalization + permissions | Arbitrary read (P0) |
| **File deletion (easily missed!)** | DELETE / `?action=del` | Path + permissions + audit | Arbitrary file deletion (P0) |
| **Command execution / Ping / diagnostics** | `/ping`, `/nslookup`, `/exec`, `/util` | Command allowlist + parameter filtering | RCE (P0) |
| **Authentication operations** | `/login`, `/reset`, `/sms` | Captcha + rate + binding | Credential stuffing / reset (P1) |

**Procedure**:
1. Grab the feature list → assign each endpoint to a class in the table above
2. Fire probes one by one for the "controls to probe" corresponding to that type (see `04-control-gap-hunting.md`)
3. Find a gap → move into the corresponding `playbooks/<type>.md` to complete exploitation → score → report

---

## 6. When to downgrade / when not to report

Downgrade conditions (-1 each, drop to P3 = abandon):

- Intranet-isolated asset, unreachable from the internet
- WAF/IPS deployed and 5+ bypasses all fail
- Extremely short exploit window (< 100ms race condition, cannot reproduce stably)
- Data redacted to the point of no business value (can only obtain a user_id sequence number)
- Platform explicitly marks OOS (Out of Scope)

Do-not-report conditions:

- Relies solely on physical access / an already-rooted device
- Reproducible only under a custom client (private SDK)
- Self-signed cert / user voluntarily installs a malicious CA
- A known CVE but the target is clearly patched, only "looks old" by version number

---

## 7. Report title templates

```
[P0][Unauthenticated][RCE] /api/v1/import accepts ${jndi:} - single-packet pwn
[P1][Authenticated][SQLi] /api/search?q= UNION injection, can read admin hash
[P1][Authz][IDOR] /api/orders/{id} horizontal traversal of others' orders (100 redacted records)
[P2][CSRF] sensitive operation /api/email/change lacks token + SameSite=None
```

Format: `[tier][condition][type] endpoint - one-sentence description`.

---

## 8. Report ordering mnemonic

> **Unauthenticated > Authenticated > Admin**
> **Single-packet > Multi-packet > Race condition**
> **Direct exploit > Chained exploit**
> **New-type > Old-type**
> **Real data > Self-generated data**

Sort all findings for the same target by this mnemonic before submitting, so the platform reviewer isn't overwhelmed.
