# CL.TE

## When To Consider

- conflicting Content-Length and Transfer-Encoding
- front-end appears to honor CL

## Evidence To Collect

- edge/origin parser disagreement
- connection close or reuse behavior
- canonical control request

## False Positive Controls

- ordinary TE rejection
- WAF block before origin

## Safe Validation Boundary

- Manual malformed framing only; no victim traffic.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [te-cl](./te-cl.md)
- [te-te](./te-te.md)
