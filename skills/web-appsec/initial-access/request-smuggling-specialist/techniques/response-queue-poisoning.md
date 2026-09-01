# Response Queue Poisoning

## When To Consider

- shifted response order
- unexpected response for baseline request

## Evidence To Collect

- queue shift persists for following request
- paired owned-account proof

## False Positive Controls

- cache variation
- backend pool change

## Safe Validation Boundary

- Manual only; owned accounts, no third-party data.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [request-tunnelling](./request-tunnelling.md)
