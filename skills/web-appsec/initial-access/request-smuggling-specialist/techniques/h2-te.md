# H2.TE

## When To Consider

- HTTP/2 request carries illegal TE
- downgrade creates HTTP/1 Transfer-Encoding semantics

## Evidence To Collect

- edge accepts forbidden TE
- origin receives TE-like field

## False Positive Controls

- edge strips TE
- client display confusion

## Safe Validation Boundary

- Manual only; record actual wire protocol.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [h2-cl](./h2-cl.md)
- [te-te](./te-te.md)
