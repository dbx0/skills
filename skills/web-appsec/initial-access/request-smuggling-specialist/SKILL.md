---
name: request-smuggling-specialist
description: "HTTP Request Smuggling / Desync Specialist — deep triage and assessment of request smuggling, HTTP desync, parser discrepancies, protocol downgrade boundaries, queue poisoning. 32 technique cards covering CL.TE, TE.CL, TE.TE, CL.0, 0.CL, H2.CL, H2.TE, H2.0, HTTP/2 splitting, request tunnelling, response queue poisoning, connection-locked smuggling, client-side desync, browser-powered desync, pause-based desync, hop-by-hop confusion, expect-100-continue, protocol transition, HTTP/1.0+TE, HTTP/3-to-HTTP/1, cache poisoning chains, WAF bypass, host routing, trailer boundaries, h2c upgrade, HTTP/3 connection contamination, TRACE-assisted desync, opportunistic TLS/RFC 2817. Trigger on 'request smuggling', 'http desync', 'cl.te', 'te.cl', 'request tunnelling', 'queue poisoning', 'client-side desync', 'browser-powered desync'. Use for any HTTP parser discrepancy or desync assessment."
version: 2.0.0
author: 0xPira (SSKills), integrated by bx0
---

# HTTP Request Smuggling / Desync Specialist

A specialist skill for triaging request smuggling and HTTP desync signals. Not an exploit pack — does not generate malformed framing automatically, does not use victim traffic, does not perform shared cache or queue poisoning.

## How to Use

1. Start with `router.md` — first-pass triage and card selection
2. Apply `safety.md` — hard gates and manual-only boundaries
3. Load at most 3 relevant files from `techniques/` based on router output
4. Return structured output using `output-schema.json`

## Quick Reference: Technique Index

| Signal | Load This Card |
|---|---|
| Conflicting Content-Length + Transfer-Encoding | `techniques/cl-te.md`, `techniques/te-cl.md`, `techniques/te-te.md` |
| Duplicate/invalid Content-Length | `techniques/duplicate-content-length.md`, `techniques/invalid-content-length.md` |
| Early response before body consumed | `techniques/cl-0.md`, `techniques/0-cl.md`, `techniques/client-side-desync.md` |
| HTTP/2 edge or downgrade | `techniques/h2-cl.md`, `techniques/h2-te.md`, `techniques/h2-0.md`, `techniques/http2-request-splitting.md` |
| Dechunking, chunk extensions, trailers | `techniques/te-0-dechunking.md`, `techniques/chunked-parser-differentials.md`, `techniques/trailers.md` |
| Upgrade, CONNECT, h2c, opportunistic TLS | `techniques/protocol-transition.md`, `techniques/h2c-smuggling.md`, `techniques/rfc2817-opportunistic-tls.md` |
| HTTP/3, connection coalescing | `techniques/http3-to-http1.md`, `techniques/http3-connection-contamination.md` |
| Hidden second response, TRACE reflection | `techniques/request-tunnelling.md`, `techniques/trace-assisted-desync.md`, `techniques/response-queue-poisoning.md` |
| Host, cache, WAF, ACL impact | `techniques/host-routing.md`, `techniques/cache-chain.md`, `techniques/waf-parser-gap.md` |
| Hop-by-hop header issues | `techniques/hop-by-hop.md` |
| Expect: 100-continue | `techniques/expect-100-continue.md` |
| HTTP/1.0 + Transfer-Encoding | `techniques/http1-te.md` |

## Router Summary

1. Confirm scope, host, scheme, route, evidence IDs
2. Identify signal type: architecture, protocol translation, parser behavior, connection state, cache behavior, or scanner-only
3. If scanner-only → return `needs_more_evidence`
4. Load ≤3 technique cards from `techniques/` based on routing hints
5. Produce structured output matching `output-schema.json`

## Output Schema

Required fields: `status`, `variant_hypotheses`, `architecture_hypothesis`, `parser_boundary`, `required_evidence`, `false_positive_controls`, `safe_next_step`, `manual_gate_required`

Status values: `needs_more_evidence`, `hypothesis_ready`, `manual_proof_contract_required`, `discarded_false_positive`, `needs_specialized_review`

## Safety Gates

- Authorized testing only
- No automatic malformed HTTP framing
- No automatic conflicting Content-Length or Transfer-Encoding
- No automatic pause mid-request
- No shared cache/queue/connection poisoning
- No victim traffic
- No sensitive body/token/credential persistence

**Automatic lane:** GET/HEAD inventory, static review, protocol support observation, cache header observation, hypothesis generation.

**Manual-gated lane:** malformed framing, body ambiguity, HTTP/2 downgrade, h2c upgrade, TRACE-assisted checks, HTTP/3 contamination, timing probes, queue/cache poisoning, callbacks, sensitive data access, cross-user impact validation.

## Key Variants

### CL.TE
Front-end uses Content-Length, origin uses Transfer-Encoding. Conflicting headers cause the front-end to forward more than the origin expects.

### TE.CL
Front-end uses Transfer-Encoding (chunked), origin uses Content-Length. Origin reads fixed length, leftover bytes become prefix of next request.

### TE.TE
Both front and back support TE, but one rejects/normalizes obfuscated or duplicate Transfer-Encoding. Parser differential in TE handling.

### CL.0 / 0.CL
Server responds before consuming promised body (CL.0) or interprets body on methods that shouldn't have one (0.CL). Body suffix affects next request parsing.

### H2.CL / H2.TE / H2.0
HTTP/2 edge downgrading to HTTP/1 origin. Content-Length retained after downgrade (H2.CL), illegal TE accepted and forwarded (H2.TE), or stream behaves like zero-length body (H2.0).

### HTTP/2 Request Splitting
CRLF or pseudo-header ambiguity during HTTP/2 to HTTP/1 downgrade. Downstream request line differs from HTTP/2 semantics.

### Request Tunnelling
Two responses behind one front-end request. Hidden inner request without cross-user queue poisoning.

### Response Queue Poisoned
Shifted response order — attacker's request gets victim's response. Requires connection reuse or shared queue.

### Connection-Locked Smuggling
Attack only succeeds on same client connection. Disabled when client reuse is disabled.

### Client-Side Desync / Browser-Powered Desync
Browser-compatible request triggers early response. Victim browser reuses HTTP/1.1 connection and receives poisoned response.

### Pause-Based Desync
Headers sent then delayed body. Front-end streams partial request to origin, late body affects later parsing.

### TE.0 / Dechunking Smuggling
Proxy dechunks Transfer-Encoding before forwarding to origin. Origin receives different framing than edge parsed.

### Chunked Parser Differentials
Chunk extensions, terminators, or trailer handling differs between front-end and origin parsers.

### h2c Cleartext Upgrade Smuggling
h2c accepted on proxy-facing route but not over HTTP/1.1. Upgrade reaches unintended hop.

### HTTP/3 Connection Contamination
HTTP/3 connection coalescing causes sibling authorities to share connection state. One host's request affects another's routing.

### TRACE-Assisted Desync
TRACE method enabled through proxy chain reveals smuggled request reflection or hidden second response.

### Opportunistic TLS / RFC 2817
Upgrade path between proxy and origin. One hop switches protocol, another continues HTTP/1.1 parsing.

## Related Skills

- `offensive-security` — main web app bug bounty methodology (Section A)
- `bug-bounty-triage` — 7-Question Gate for validating before reporting
- `bug-bounty-reporting` — report templates for H1/Bugcrowd/Intigriti/Immunefi

## Sources

See `sources.json` for 40+ authoritative references including PortSwigger research, Akamai advisories, Cloudflare Pingora analyses, AWS ALB docs, Fastly guides, and relevant RFCs (9110-9114, 9204, 7541, 8441, 9298, 9931).
