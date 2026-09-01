---
name: attack-chain
description: "Visible exploit-chain builder. Use when a primitive appears and the operator needs to convert it into a reportable high-impact chain."
sources: field_recon, hackerone_public
report_count: 50
---

# Attack Chain Mode

Use this mode when the operator invokes `/attack-chain <primitive or finding>`.

This is the visible, operator-facing wrapper around the exploit chaining engine. It turns scattered observations into a chain card.

## Output Contract

Produce a chain card:

```text
Primitive:
Boundary broken:
Carrier object:
Authority upgrade:
Victim / asset:
Impact target:
Current proof:
Missing proof:
Next 5 pivots:
Reportability score:
Chainability score:
Recommended next action:
```

## Chainability Rubric

Score from 0 to 5:
- `0`: informational only
- `1`: unrealistic preconditions
- `2`: low-value data or weak state
- `3`: sensitive object, privileged workflow precondition, or token-adjacent state
- `4`: session, role, export, secret, internal service, or financial state
- `5`: ATO, privilege escalation, cross-tenant data access, cloud/control-plane access, RCE, or material financial loss

## Primitive Ladders

### IDOR / object read

Pivot:
- same object family write/delete
- export/preview/attachment child object
- GraphQL helper mutation
- mobile/legacy API sibling
- support/admin rendering of the same object

### Token / secret / signed URL

Pivot:
- validate scope with minimal non-destructive request
- identify service and permissions
- test expiry/revocation
- find where it is generated or logged
- chain to repo, CI, cloud, storage, webhook, or API access

### SSRF / backend fetch

Pivot:
- full-response reflection before blind-only claims
- redirect and parser second stage
- cloud metadata/service discovery
- internal admin/control plane
- log/export/error-body side channel

### XSS / rendering sink

Pivot:
- privileged render context
- stored/admin/support path
- session/action impact
- cache poisoning and clean-client validation
- CSP/cookie reality check before severity claim

### Race / business logic

Pivot:
- duplicate value
- entitlement without payment
- refund without revocation
- role after removal
- worker completes after permission change

### Import / parser

Pivot:
- file read via symlink/path confusion
- SSRF through import-from-URL
- metadata/renderer sink
- imported object ACL drift
- parser-to-execution path

## Decision Rule

If the chain card cannot name a concrete victim, asset, and harm, do not report yet. Keep hunting or downgrade to a lead.

