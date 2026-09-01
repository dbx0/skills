---
name: api-security
description: API security testing across REST, GraphQL, WebSocket and SOAP. 10-phase methodology from endpoint discovery through authz testing, injection, rate-limit abuse and CI/CD integration. Use when testing an API surface in a bug bounty or pentest.
---

# API Security Testing

> Covers all protocols: REST / GraphQL / WebSocket / SOAP
> A 10-phase methodology, from discovery to CI/CD integration

## Applicable Scenarios

- REST API security testing (OpenAPI/Swagger-driven or blind testing)
- GraphQL security audit (introspection, batch queries, alias overloading)
- WebSocket security testing
- JWT / OAuth 2.0 authentication testing
- BOLA/IDOR/BFLA authorization vulnerability detection
- API rate-limit bypass and DoS testing

## 10-Phase Testing Process

### Phase 1: API Discovery and Reconnaissance

```text
Active discovery:
□ Vespasian: headless browser crawl → auto-generate OpenAPI 3.0 / GraphQL SDL spec
□ Entropy --discover: extract endpoints from robots.txt + JS files
□ Kiterunner / ffuf: brute-force undocumented endpoint paths
□ Check common paths: /swagger.json, /openapi.json, /graphql, /api-docs

GraphQL introspection (three-tier attempt):
  1. Standard introspection query
  2. Slimmed-down query (bypass full WAF blocking)
  3. Query only __schema { types { name } } (minimal probe)
```

### Phase 2: Authentication Testing

```text
JWT analysis (jwt_tool / Burp):
□ alg:none attack: change the header to "alg":"none", empty the signature
□ Key confusion: RS256 public key → HS256 symmetric key
□ Weak HMAC key brute-force: jwt_tool -C -d wordlist.txt
□ Expiry/claim tampering: modify the exp/iat/sub/role claims
□ kid injection: ../../etc/passwd → HMAC signature bypass

OAuth 2.0:
□ redirect_uri manipulation → authorization code leakage
□ CSRF via missing state parameter
□ Token leakage in the Referer header
□ PKCE absence detection

GraphQL authentication:
□ mutation bypassing authentication via GET request (CSRF)
□ Batch-query authentication bypass
```

### Phase 3: Authorization Testing (BOLA/IDOR/BFLA)

```text
BOLA (broken object-level authorization):
□ Iterate numeric IDs: /user/1 → /user/2 → /user/3
□ Iterate UUIDs
□ Iterate usernames/emails
□ Burp Autorize: dual-session replay comparison

BFLA (broken function-level authorization):
□ Regular user executing an admin API
□ HTTP method switching: GET → PUT → PATCH → DELETE
□ API version downgrade: /v2/admin → /v1/admin
□ Bulk operation injection: {"users": [1,2,3]} → {"users": [1,2,3,admin_id]}

Tools: Burp Autorize, AuthMatrix, Entropy (malicious_insider persona)
```

### Phase 4: GraphQL-Specific

```text
Introspection leakage → information exposure detection
Alias overloading → 100+ alias DoS
Batch queries → 10+ simultaneous query DoS
Field duplication → __typename × 500
Directive overloading → recursive @skip/@include
Circular queries → deeply nested introspection recursion
Field suggestion → information leakage in error messages
GraphiQL/Playground exposure → IDE public exposure risk
GET mutation → CSRF risk
Tracing/debug mode → metadata leakage

Tools: FireTail, Escape DAST, api.sh (Phases 1-3)
```

### Phase 5: REST Input Validation

```text
□ HTTP method switching: GET→POST→PUT→DELETE→OPTIONS→PATCH
□ Content-Type tampering: JSON→XML→multipart
□ NoSQL injection: {"username": {"$gt": ""}}
□ SSRF via URL parameter: webhook URL / avatar URL / import URL
□ XXE in XML endpoints
□ Parameter pollution: /api?role=user&role=admin
□ Mass assignment: add is_admin: true to the request body
```

### Phase 6: Business Logic and Differential Testing

```text
□ Entropy compare: diff v1 vs v2 API → status code changes / field removal / latency regression
□ Multi-role workflow testing: admin/user/readonly permission matrix
□ Coupon/points/price manipulation
□ Race conditions: concurrent request testing for TOCTOU
```

### Phase 7: WebSocket Testing

```text
□ Endpoint discovery
□ Message injection (payload injection, prototype pollution)
□ Oversized message handling
□ Type confusion
□ Cross-Site WebSocket Hijacking (CSWH)
```

### Phase 8: Rate Limiting and DoS

```text
□ Rate-limit bypass via headers: X-Forwarded-For, X-Real-IP
□ Path variants: /api/ → /api → /Api/ → /API/
□ Slowloris low-bandwidth exhaustion
□ GraphQL batch-query deep-nesting DoS
□ IP rotation testing (ProxyCat proxy pool)
```

### Phase 9: Data Exposure

```text
□ Response over-exposure: compare API return vs UI display
□ Pagination enumeration: ?page=1&limit=10000
□ Information leakage in error messages: stack traces / internal paths / SQL errors
□ GraphQL nested traversal accessing unauthorized data
□ OpenAPI spec exposing sensitive endpoints
```

### Phase 10: CI/CD Integration

```text
□ Entropy --ci --watch: auto re-run on spec change
□ Escape DAST: auto-block the build by severity threshold
□ Persist findings as regression tests
□ StackHawk (developer-first, ZAP core)
```

## Product-Specific: Keycloak version fingerprint + CVE-safe detection

Find Keycloak via the OIDC well-known (both distro path layouts):
```
/realms/master/.well-known/openid-configuration          (Quarkus distro, KC 17+)
/auth/realms/master/.well-known/openid-configuration     (legacy WildFly distro)
# a JSON body containing "protocol/openid-connect" confirms Keycloak; grep hosts for "keycloak" too.
```
Get the **exact version** from the login page's static-resource path (needed for CVE matching):
```
GET /realms/master/protocol/openid-connect/auth?client_id=account&response_type=code&redirect_uri=<self>
# -> HTML references /resources/<VERSION>/login/keycloak/...   <- that <VERSION> is the build.
```
If `master` 500s/404s, the realm is restricted/renamed — enumerate real realms from an app that
uses it (its login redirect carries `realms/<name>`).

**CVE-safe boundary (critical):** many Keycloak nuclei templates (e.g. the CVE-2026-18963
reset-credentials account-takeover chain) **actually set a new password on a target account** in
their final step. That is a real account takeover — prohibited under "only interact with your own
account". **Fingerprint the version and confirm the vulnerable flow is *reachable* (read-only first
steps), then STOP and report on version + reachability.** Never run the state-changing steps of an
exploit chain to "prove" it.

## Product-Specific: ServiceNow unauthenticated data exposure

A `*.service-now.com` instance (or `Server: snow_adc`) has a well-known unauth data-exposure class
(the "Simple List" / widget ACL bypass). Test it — table APIs being locked does NOT mean the portal is:

```
/api/now/table/incident?sysparm_limit=1   -> expect 401 (ACL-enforced; good)
/sp  /csm  /esc  /kb                       -> Service Portal, usually 200 UNAUTHENTICATED
```
1. Fetch a public portal page (`/sp?id=index`), capture cookies + the CSRF token `g_ck`
   (`window.g_ck` in the HTML, ~72 chars).
2. Call the SP data API with the token: `POST /api/now/sp/widget/<widget>` with
   `{"options":{"table":"sys_user","fields":"user_name,email","maximum_entries":"1"}}`, or read a
   page's server-rendered widgets: `GET /api/now/sp/page?id=<id>` (kb_home, incident_list, csm_index_full...).
3. Parse `result.containers[].rows[].columns[].widget.data` for **non-empty record lists**. If a
   widget returns real records unauthenticated, that is the finding — stop at 1 record, do not bulk
   pull PII.
4. Confirm the guest context: `result.user` = `{"user_name":"guest","roles":null}` means the portal
   is public; records leaking to that context = ACL misconfig. If every widget is empty and the
   guest has no roles, the instance is correctly configured (clean negative).

## Toolchain

| Tool | Purpose | Obtain |
|------|------|------|
| Vespasian | Traffic → OpenAPI/GraphQL spec | GitHub: praetorian-inc/vespasian |
| Entropy | LLM-generated attack scenarios, 5 personas | GitHub: arjinexe/entropy-chaos |
| Escape DAST | Business logic security testing | escape.tech |
| api.sh | 8-phase all-protocol attack pipeline | GitHub: Sharon-Needles/api |
| FireTail | GraphQL 12-item specialized testing | firetail.ai |
| jwt_tool | Comprehensive JWT testing | GitHub: ticarpi/jwt_tool |
| Burp Autorize | Dual-session authorization comparison | Burp BApp Store |

## References

- `references/rest-graphql-testing.md` — In-depth REST + GraphQL testing
- `references/jwt-oauth-testing.md` — JWT + OAuth security testing
