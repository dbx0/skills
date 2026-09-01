# HTTP/3 Connection Contamination

## When To Consider

- HTTP/3 edge with connection coalescing
- sibling authorities share connection state

## Evidence To Collect

- same connection routes authorities differently than fresh connections
- authority state survives independent H3 streams

## False Positive Controls

- normal wildcard coalescing
- cache or redirect variance

## Safe Validation Boundary

- Owned-domain inventory first; no out-of-scope sibling tests.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [http3-to-http1](./http3-to-http1.md)
- [connection-state](./connection-state.md)
