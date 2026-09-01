# Client-Side Desync

## When To Consider

- browser-compatible request can trigger early response
- victim browser would reuse HTTP/1.1 connection

## Evidence To Collect

- approved browser PoC in test profile
- endpoint early-response behavior

## False Positive Controls

- HTTP/2 used by browser
- CORS-only issue

## Safe Validation Boundary

- Manual gate; no real victim.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [cl-0](./cl-0.md)
- [browser-powered-desync](./browser-powered-desync.md)
