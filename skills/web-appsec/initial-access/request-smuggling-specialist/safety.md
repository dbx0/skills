# Request Smuggling Safety

## Hard Gates

- Authorized testing only.
- Do not automatically generate malformed HTTP framing.
- Do not automatically send conflicting Content-Length or Transfer-Encoding.
- Do not automatically pause mid-request to test timeout behavior.
- Do not poison shared cache, shared queue, shared connection, or victim traffic.
- Do not persist sensitive bodies, cookies, tokens, credentials, or tenant data.

## Automatic Lane

Automatic work is limited to ordinary GET/HEAD inventory, static review, protocol support observation, cache header observation, and hypothesis generation.

## Manual-Gated Lane

Manual approval is required for malformed framing, body ambiguity, HTTP/2 downgrade probes, h2c upgrade probes, TRACE-assisted checks, HTTP/3 contamination checks, timing probes, queue poisoning, cache poisoning, callbacks, sensitive data access, and any cross-user impact validation.

## Stop Conditions

Stop on out-of-scope infrastructure, unexpected private data, repeated 5xx, elevated latency, third-party backend involvement, missing cleanup path, or need for real victim traffic.
