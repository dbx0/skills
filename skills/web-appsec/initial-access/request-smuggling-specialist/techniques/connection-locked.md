# Connection-Locked Request Smuggling

## When To Consider

- attack fails when client reuse disabled
- succeeds on same client connection

## Evidence To Collect

- nested response or connection-bound effect
- impact via cache or header leak

## False Positive Controls

- ordinary pipelining
- tool reuse artifact

## Safe Validation Boundary

- Manual only; label connection-locked clearly.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [connection-state](./connection-state.md)
