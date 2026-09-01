# Request Smuggling Router

Start here after another system has routed a signal to the request-smuggling specialist. The incoming context may only say that request smuggling is plausible; do not assume a specific variant yet.

## First Pass

1. Confirm scope, host, scheme, route, and evidence IDs.
2. Identify whether the signal is architecture, protocol translation, parser behavior, connection state, cache behavior, or only scanner text.
3. If the context is scanner-only, return `needs_more_evidence` and ask for raw request/response metadata and architecture evidence.
4. Load at most three technique cards from `techniques/` based on the routing hints below.
5. Produce output matching `output-schema.json`.

## Routing Hints

- Conflicting Content-Length and Transfer-Encoding: load `cl-te.md`, `te-cl.md`, or `te-te.md`.
- Duplicate, malformed, or surprising Content-Length: load `duplicate-content-length.md` or `invalid-content-length.md`.
- Early response before body consumption: load `cl-0.md`, `0-cl.md`, `client-side-desync.md`, or `browser-powered-desync.md`.
- HTTP/2 edge or downgrade: load `h2-cl.md`, `h2-te.md`, `h2-0.md`, or `http2-request-splitting.md`.
- Dechunking, chunk extensions, chunk terminators, or trailers: load `te-0-dechunking.md`, `chunked-parser-differentials.md`, or `trailers.md`.
- Upgrade, CONNECT, h2c, or opportunistic TLS: load `protocol-transition.md`, `h2c-smuggling.md`, or `rfc2817-opportunistic-tls.md`.
- HTTP/3, connection coalescing, or sibling authority state: load `http3-to-http1.md` or `http3-connection-contamination.md`.
- Hidden second response, TRACE reflection, or response concatenation: load `request-tunnelling.md`, `trace-assisted-desync.md`, or `response-queue-poisoning.md`.
- Host, cache, WAF, or ACL impact: load `host-routing.md`, `cache-chain.md`, or `waf-parser-gap.md` only after naming the root parser or connection-state boundary.

## Decision Rules

- Technique names are hypotheses, not findings.
- A gadget is not the root cause unless it creates impact without another parser boundary.
- If active validation would require malformed framing, pauses, connection poisoning, queue poisoning, cache poisoning, or victim simulation, mark it manual-gated.
- Prefer one precise missing-evidence request over a broad checklist.
