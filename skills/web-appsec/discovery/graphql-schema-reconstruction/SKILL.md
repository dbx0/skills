---
name: graphql-schema-reconstruction
description: Use when a GraphQL endpoint blocks standard introspection (__schema, __type) but you still need to enumerate fields, mutations, and types — covers validation-vs-execution error oracles, the @skip(if:true) technique, and empty-input-object dumps. Trigger on "introspection disabled", "GraphQL schema recovery", "blind GraphQL enumeration", or after api-security's standard introspection attempts fail.
version: 1.0.0
author: field-derived (iFood engagement, shop.ifood.com.br schema recovery)
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [graphql, introspection, schema-recovery, api-security, error-oracle]
    related_skills: [api-security, client-runtime-intelligence, bug-bounty]
---

# GraphQL Schema Reconstruction Without Introspection

Standard introspection (`__schema`, `__type` queries) is often disabled and returns a generic
"Invalid input" style error for everything. That does not mean the schema is unrecoverable — most
GraphQL servers still distinguish validation-stage errors from execution-stage errors internally,
and that differential leaks the schema one field/type at a time.

Use this after `api-security`'s standard three-tier introspection attempt has been tried and blocked.

## When to Use

- `__schema`/`__type` introspection returns a generic, uniform error regardless of query shape
- You have a recovered client bundle (via `client-runtime-intelligence`) with a partial/declared
  GraphQL contract and want to check for undeclared fields/mutations the handler still accepts
- You need to determine the real blast radius of a GraphQL surface before it can be assessed for
  authz/injection issues

## Method

### 1. Wrong-typed variable oracle

Send a variable of the wrong scalar type for a guessed field/argument name:

```graphql
query { someGuessedField(id: "not-an-int") }
```

- A **detailed type-mismatch error** (naming the field, argument, and expected type) confirms the
  field, its argument, and that argument's type all exist.
- A **generic/uniform error** means at least one of field/argument/type doesn't exist as guessed.

Run this systematically across a wordlist of plausible field names (derived from the object model,
REST API naming if a parallel REST surface exists, or the recovered client's declared contract as a
starting seed).

### 2. `@skip(if: true)` oracle

Wrap a guessed field in `@skip(if: true)`:

```graphql
query { guessedField @skip(if: true) }
```

This validates that the field exists (the query parses and passes validation) **without ever
invoking its resolver** — the field is skipped at execution time. This makes it safe to probe
mutations this way too, since the resolver — and any side effect it would have — never runs.

### 3. Empty input object oracle

For custom input object types (common on mutations), send an empty object:

```graphql
mutation { createSomething(input: {}) }
```

The validation error frequently lists every required field and its type in one response, dumping
the input object's full shape without needing to guess field names individually.

### 4. Distinguish disclosure from exposure

Recovered field/mutation/type **names** are attack-surface disclosure, not data exposure — file this
as informational/low on its own. It only escalates if:
- A recovered field is then called and returns real data to an unauthenticated/under-privileged
  caller (that's a separate authz finding on that specific field)
- A recovered mutation can be executed to cause a state change with no proper auth (do not execute
  state-changing mutations without authorization — report the mutation's existence and let the
  program authorize execution testing)

### 5. Design-intent review — separate dead surface from deliberate pre-auth checks

Cross-reference every recovered operation against the client bundle's actual call sites (use
`client-runtime-intelligence` to map calls). Three outcomes:

- **Deliberate, unauthenticated by design** (e.g. an email-exists check on a signup form, called
  from a real UI flow) — not a vulnerability, this is expected product behavior; consider whether the
  *response* leaks more than intended even if the *access* is fine
- **Correctly gated** — call sites all pass through an `isAuthenticated`/`skip:` guard and the
  server independently returns `null`/an auth error without a token
- **Dead legacy surface** — the operation is declared/reachable but has zero call sites anywhere in
  the current client. This is the strongest, cheapest fix argument: recommend removal rather than
  "add auth," since nothing legitimate depends on it.

## Common Mistakes

- Treating every recovered field name as a data-exposure finding rather than checking what it
  actually returns when called
- Executing state-changing mutations to "confirm" they work, without program authorization
- Reporting "unauthenticated GraphQL operation" as a blanket authz bug when the operation is a
  deliberate pre-auth check (signup existence check) — the real issue, if any, is response content,
  not access
- Giving up after standard introspection fails instead of trying the error-oracle differentials
  above

## Cross-References

- `api-security` for the broader REST/GraphQL/WebSocket testing methodology this slots into
- `client-runtime-intelligence` for recovering the declared client contract and call-site mapping
  used in the design-intent review step
