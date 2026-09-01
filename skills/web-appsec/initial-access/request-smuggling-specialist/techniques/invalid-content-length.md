# Invalid Content-Length

## When To Consider

- blank, signed, overflowed, or non-decimal CL
- leading whitespace or suffix

## Evidence To Collect

- reject/close policy differs
- connection reuse after invalid CL

## False Positive Controls

- normal timeout
- body too large protection

## Safe Validation Boundary

- Manual only with small benign bodies.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [duplicate-content-length](./duplicate-content-length.md)
