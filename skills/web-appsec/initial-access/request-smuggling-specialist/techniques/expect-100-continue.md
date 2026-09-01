# Expect: 100-Continue / Interim Response

## When To Consider

- Expect header
- interim response behavior differs
- response header removal dependency

## Evidence To Collect

- front-end and in-path server disagree before body
- connection state after reject is defined

## False Positive Controls

- ordinary 417
- body never forwarded

## Safe Validation Boundary

- Manual only; no large body.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [protocol-transition](./protocol-transition.md)
