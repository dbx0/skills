# HTTP/3 to HTTP/1 Boundary

## When To Consider

- HTTP/3 edge with HTTP/1 origin
- QUIC stream FIN translation

## Evidence To Collect

- edge supports H3 but origin receives H1
- translation preserves ambiguous field

## False Positive Controls

- H3 end-to-end
- client fallback misread

## Safe Validation Boundary

- Manual research-only; no automated H3 fuzzing.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [http3-connection-contamination](./http3-connection-contamination.md)
