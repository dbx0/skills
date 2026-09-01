# HTTP/2 Request Splitting

## When To Consider

- CRLF or pseudo-header ambiguity during downgrade
- ambiguous :path or :authority

## Evidence To Collect

- downstream request line differs from HTTP/2 semantics
- proxy rewrite observable

## False Positive Controls

- frontend rejects malformed pseudo-headers
- display-only escaping

## Safe Validation Boundary

- Manual only; no full smuggled request automation.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [h2-cl](./h2-cl.md)
- [host-routing](./host-routing.md)
