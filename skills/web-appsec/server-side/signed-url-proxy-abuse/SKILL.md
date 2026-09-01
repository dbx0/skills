---
name: signed-url-proxy-abuse
description: Attack architectures where a client reaches backends through a proxy that fetches an HMAC-signed, base64-encoded target URL (/api/proxy/<sig>.<b64url>). Covers finding signing oracles that mint signatures for attacker input, signer-vs-fetcher normalisation mismatch, server-side placeholder expansion, and how to tell a real SSRF from a path change that reaches nothing. Use when discovery/config data shows signed proxy URLs, or any URL-fetching indirection with an integrity tag.
sources: field_recon (fintech engagement — signing oracle found, normalisation asymmetry proven, no impact reached)
report_count: 0
---

# Signed-URL Proxy Abuse

Pattern: the client never calls backends directly. It calls

```
https://proxy.target.com/api/proxy/<SIGNATURE>.<base64url(TARGET_URL)>
```

The signature is an HMAC the client cannot forge, so the naive conclusion — "the target is
integrity-protected, move on" — is usually where people stop. The interesting bugs are in **who
else will sign for you** and **whether the signer and the fetcher agree on what the URL says**.

## Step 1 — Harvest and decode the corpus

Discovery/config endpoints hand you dozens of pre-signed URLs. Decode them all:

```python
import base64, re, json
def decode(u):
    m = re.search(r'/api/proxy/([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)', u)
    if not m: return None
    b = m.group(2); b += '=' * (-len(b) % 4)
    return m.group(1), base64.urlsafe_b64decode(b).decode()
```

Decoding the signature itself is worth a minute. A typical layout:

```
25 bytes = 0x00 version | 4-byte key id | 20-byte MAC   (HMAC-SHA1 shape)
```

Stable per-region key ids confirm one signing key per environment. **Not forgeable offline** —
so stop trying, and go find an oracle.

## Step 2 — Find signing oracles (the actual attack)

A signing oracle is any endpoint that takes your input and returns a **freshly signed** proxy URL.
They exist because some flows are dynamic (invite slugs, share links, per-customer resources).

Hunt by response content, not by name:

```bash
# any unauthenticated endpoint whose RESPONSE contains /api/proxy/
grep -rl '/api/proxy/' <harvested-js> <recovered-source> <mobile-binary-strings>
```

Confirmed shape from the field:

```
GET /api/inviter/<slug>   →  200
{"redirect":"https://proxy.target.com/api/proxy/AJxL5L....<b64>"}
   b64 → https://prod-global-customs.target.com/api/inviter/<slug>
```

The server just signed a URL containing your input. **Now the question is how much of that URL
you control.** Path segment only is common. Anything touching the *host* is the prize.

## Step 3 — Try to escape the host at signing time

```
..%2F..%2Fadmin              %252F..%252Fadmin        %c0%af..%c0%afadmin
test%5C..%5C..%5Cadmin       test%40evil.tld          %2F%2F%2Fevil.tld
test%00https%3A%2F%2Fevil    test%0d%0aHost%3A+evil   fullwidth ／ ．
```

A correctly built signer **re-encodes** and everything stays a path segment. Watch for the oracle
*refusing* certain inputs (404, no signature) — that refusal set tells you where its validation is,
and a null byte making it refuse while `%c0%af` signs happily is a hint about the parser.

## Step 4 — Signer vs fetcher normalisation mismatch

The real bug class. The **signer** computes the MAC over one byte sequence; the **fetcher** may
decode further before issuing the request. If they disagree, the fetched URL is not the signed URL.

Call each signed URL and compare status against a clean baseline:

| Payload | Fetch | Reading |
|---|---|---|
| baseline slug | `500` | reached the intended upstream unchanged |
| `..%2F` | `401` | path altered — fetcher decoded `%2F` |
| `%252F` double-encoded | `401` | fetcher **double**-decodes |
| `%c0%af` overlong UTF-8 | `401` | fetcher accepts overlong forms |
| `%40` at-sign | `500` | stayed in path — **no userinfo host escape** |

A status *difference* proves the mismatch is real. It does **not** prove impact.

## Step 5 — Server-side placeholder expansion

Signed targets often embed placeholders **inside** the signed blob:

```
/api/user/:user-id/credential      /api/admin/users/:id/revoke/all
/api/customers/:id/rollout-map     /api/locale/:locale/localizations
```

The client cannot substitute these without breaking the MAC, so the **proxy must expand them
server-side from client-supplied input after verifying the signature**. That is an injection point
by construction — if reachable.

Test by supplying the value as path suffix, query param, and `?%3Aname=`. In the field engagement
all forms returned `403`: **the proxy authenticated before substituting**, closing the hypothesis.
Check auth ordering first — it decides whether this whole branch is testable.

## The discipline that stops a false positive

Every "success" here must be compared against **direct access to the same target**:

```
via signed proxy + traversal  → 401
direct request to that host   → 401     ← identical: you gained NOTHING
```

Path manipulation that lands on hosts you can already reach is not SSRF. Report it only when the
proxy reaches something you demonstrably cannot: a link-local address, an internal-only name, or
an endpoint that answers *differently* through the proxy because the proxy supplies credentials.

Check whether the proxy injects auth at all — if traversal yields `401` everywhere, it does not,
and the ceiling on this whole avenue is low.

## Reporting

- Signing oracle + host escape + internal reach → SSRF, high severity.
- Signing oracle + path-only control, everything reachable anyway → **no impact**, do not file.
- Normalisation mismatch with no reach → a real bug class with no demonstrated effect; mention it
  as supporting detail on another finding, not as its own report.
