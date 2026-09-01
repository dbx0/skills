# 0.CL

## When To Consider

- implicit-zero interpretation
- GET or OPTIONS body discrepancy

## Evidence To Collect

- front-end forwards body despite zero-length policy
- back-end waits or consumes body

## False Positive Controls

- application ignores body safely
- normal 400 or 411

## Safe Validation Boundary

- Manual only; no body flood.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [cl-0](./cl-0.md)
