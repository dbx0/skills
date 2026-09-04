# SRC time-box priority — high-severity-share ranking from 22,132 cases

> Perspective: within a fixed time budget (one crowd test, one SRC scoring sprint, one HVV exercise), what order should a black-box SRC hunter invest time in.
> Companion reading: `01-attack-priority.md` (how much each vulnerability type is worth) + this file (the probability that finding one in a class == high severity).

---

## 1. The one-line principle

`01-attack-priority.md` gives **"how much it's worth if you find it"**;
this file gives **"the probability that finding one == high severity"**.
Combine the two → attack whatever has the highest return on time invested first.

```
Time-box return = baseline bounty (table 01)  ×  probability of high severity on a find (this table)  /  average probe cost
```

---

## 2. High-severity-share ranking across 16 vulnerability classes

> 22,132 real samples; "high severity" = rated high or critical by the platform/committee.

| Rank | Vulnerability class | Cases | High-severity share | Domain | Black-box probe difficulty |
|------|---------|-------|---------|------|------------|
| 1 | **Password reset** | 777 | **88.0%** | Auth | Medium (must run the whole flow and compare responses) |
| 2 | **Arbitrary account / arbitrary login** | 220 | **86.4%** | Authz | Low (check whether the login endpoint requires a password) |
| 3 | **Withdrawal** | 59 | **83.1%** | Finance | High (needs a test account + risk-control edge cases) |
| 4 | **Amount tampering** | 176 | **83.0%** | Finance | Low (set `amount=0.01` and you know) |
| 5 | **Balance tampering** | 113 | **77.9%** | Finance | Medium (needs an understanding of the ledger/points model) |
| 6 | **Arbitrary user registration** | 24 | **75.0%** | Authz | Low (bypass the invite code / change the email suffix) |
| 7 | **Logic flaws (general)** | 266 | **74.8%** | Logic | Medium (flow + state machine) |
| 8 | **Order tampering** | 1,227 | **74.2%** | Finance | Medium (change status / skip steps) |
| 9 | **Price tampering** | 70 | **74.3%** | Finance | Low (change `price`) |
| 10 | **Misconfiguration** | 1,796 | **72.6%** | Config | Low (port scan + default credentials) |
| 11 | **Arbitrary operation** | 40 | **72.5%** | Authz | Medium (must recognize "approve/review" endpoints) |
| 12 | **Payment bypass** | 1,056 | **68.7%** | Finance | Medium (replay the callback / skip payment) |
| 13 | **Design flaws** | 1,391 | **65.3%** | Logic | High (must understand the business) |
| 14 | **Information disclosure** | 4,858 | **64.7%** | Information | Low (path wordlist + Wayback) |
| 15 | **Broken access control (IDOR / horizontal-vertical)** | 1,705 | **62.3%** | Authz | Low (two-account comparison) |
| 16 | **Weak passwords** | 7,513 | **58.2%** | Auth | Low (brute force, mind the rate limit) |

> Three counterintuitive figures worth noting:
> 1. **Password reset 88%** — many people test only "SMS-code brute force" and ignore the 4 patterns: response echo, missing binding, and flow-step skipping.
> 2. **Misconfiguration 72.6%** — port scanning + default credentials is the lowest-cost "sure-hit" effort.
> 3. **Arbitrary account 86.4%** — 24 points higher than general IDOR (62.3%); specifically target endpoints with "passwordless login, forgeable token".

---

## 3. SRC time-box playbooks (4 templates)

### Template A: 6-hour sprint — find one reportable high-severity bug

```
0:00-0:30  Scan ports + scan admin paths + run default credentials    (hit → misconfiguration 72.6% / weak password 58.2%)
0:30-1:30  Capture the main business flows (register/login/recover/order/return)  → record all parameters as you go
1:30-2:30  Run through the 4 password-reset patterns one by one         (88% high severity)
2:30-4:00  Two-account IDOR, horizontal and vertical                    (62.3% high severity, but bulk-friendly)
4:00-5:00  Payment/order: change amount/price/quantity                  (74-83% high severity)
5:00-6:00  Organize evidence + write the report + redact
```

### Template B: single-day depth — go deep on one target

```
1. First run one pass with "Template A" over the surface
2. Nothing shipped → go into SP/CP/partner subdomains and obscure sub-products (event pages, marketing pages, points malls)
3. Search GitHub for the company's code leaks (high-frequency params known; search `siteId`, `out_trade_no`, etc.)
4. Search the Wayback Machine for decommissioned endpoints (many old ones are still live)
5. Capture the app's traffic: compare with the web for differing endpoints (app endpoints often have weaker authz)
6. Third-party SDKs: support IM / payment SDK / push SDK, check for a hardcoded secret
```

### Template C: HVV exercise — prioritize gaining access

```
P0 focus (first 30%):
  - Scan 6379/27017/2375/9200/2181 on all IPs → hit means data/RCE
  - Scan 7001/8080/8088 + WebLogic / JBoss / Tomcat default credentials
  - Scan Spring Actuator /heapdump, /env

P1 focus (30-60%):
  - .git / .svn / wwwroot.rar / *.bak (see dictionaries/)
  - Shiro rememberMe default key, Fastjson 1.2.x, Log4Shell

P2 focus (60-100%):
  - Business bugs (password reset / broken access / arbitrary account)
  - GitHub code search
```

### Template D: SRC monthly scoring — harvest the long tail

```
Two mines with a lower high-severity share but large case counts:
  - Information disclosure (64.7% × 4,858 cases = huge volume)
  - Weak passwords (58.2% × 7,513 cases = huge volume)

Strategy:
  1. Maintain private path wordlists + weak-password lists (see dictionaries/)
  2. Automatically scan a batch of newly launched subdomains / new business lines
  3. Spend 30 minutes a day reading SRC announcements/updates, and scan new assets the moment they appear
```

---

## 4. Combined matrix with `01-attack-priority.md`

Rows: baseline bounty tier (table 01). Columns: high-severity-share band.
Cells: the actual investment order.

| Baseline \ High-severity share | 88% band (password reset / arbitrary account) | 72-83% band (payment/order/config/arbitrary op) | 58-65% band (IDOR/weak pw/info disclosure) |
|---|---|---|---|
| **P0 (RCE / arbitrary write)** | — | **🔴 top priority** (misconfig includes RCE, Actuator leaking secrets) | 🟠 info disclosure rises to P0 when it holds a DB password |
| **P0/P1 (auth bypass / admin escalation)** | 🔴 arbitrary account = report immediately | 🟠 arbitrary operation / arbitrary modification | 🟡 ordinary IDOR |
| **P1 (IDOR / logic / SQLi)** | 🟠 password reset → single-user takeover = P1 | 🟡 price 0.01 / order-status skip | 🟡 horizontal IDOR, single record |
| **P2 (XSS / CSRF / redirect)** | — | — | 🟢 chain it (XSS + IDOR) |

🔴 report now / 🟠 high priority / 🟡 medium / 🟢 filler / — combination does not exist

---

## 5. Probe decision tree (by time-box budget)

```
Got the target → how much time is left?

  ≤ 1h  → run only: default credentials + Actuator + .git + weak passwords + a single IDOR
  ≤ 6h  → add: the 4 password-reset patterns + price tampering + two-account IDOR
  ≤ 1d  → add: order state machine + verification-code brute force + arbitrary operation (approve/publish)
  ≤ 1w  → add: app reverse engineering + sub-product lines + third-party SDKs + deep business digging
```

At the end of each time-box segment, you must:
1. Confirm whether the findings so far can close the evidence loop → if not, don't leave them for later
2. Assess whether there are still "short-chain, high-share" combinations to dig
3. Don't fall into the "one more day and I'll chain RCE" obsession — call it per the time box

---

## 6. Counterintuitive reminders

> **The three most easily overlooked things with the highest high-severity share:**

1. **Intercept the response to look for the verification code** — many people only care about intercepting the request, but among password-reset bugs (88% high severity), the most common case is the response handing you `verifyCode` directly.
2. **Check whether the login endpoint actually needs a password** — arbitrary account is 86.4% high severity. Look at the body: can you swap for a token by sending only `username`? Can the `password` field be empty?
3. **Approve / review / publish endpoints** — arbitrary operation is 72.5% high severity. These are often "admin paths" but with authz enforced only in the frontend.

---

## 7. Mapping to the playbooks

| Rank band | Main playbook |
|--------|--------------|
| 1 (password reset) | `playbooks/logic-flaws.md` §3.1 + `oauth-saml-jwt.md` |
| 2/6/11 (arbitrary X) | `playbooks/arbitrary-x-authz.md` |
| 3/4/5/8/9/12 (finance) | `playbooks/logic-flaws.md` §3.4 + `industry/banking-finance.md` |
| 7/13 (logic/design) | `playbooks/logic-flaws.md` |
| 10 (config) | `playbooks/unauth-access.md` + `dictionaries/default-credentials-cn.md` |
| 14 (info disclosure) | `playbooks/info-disclosure.md` + `dictionaries/chinese-srcfingerprints.md` |
| 15 (IDOR) | `playbooks/logic-flaws.md` §3.2 + `playbooks/api-rest.md` |
| 16 (weak passwords) | `playbooks/unauth-access.md` + `dictionaries/default-credentials-cn.md` |
