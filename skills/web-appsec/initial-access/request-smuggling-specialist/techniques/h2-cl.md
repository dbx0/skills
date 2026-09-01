# H2.CL

## When To Consider

- HTTP/2 edge with HTTP/1 origin
- Content-Length retained after downgrade

## Evidence To Collect

- downgraded request preserves attacker-controlled CL
- DATA length differs from generated HTTP/1 CL

## False Positive Controls

- HTTP/2 end-to-end
- edge validates CL against DATA

## Safe Validation Boundary

- Manual HTTP/2 tooling only.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [h2-te](./h2-te.md)
- [h2-0](./h2-0.md)
