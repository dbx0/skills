# Host Routing / Virtual Host Desync

## When To Consider

- Host/:authority/SNI mismatch
- absolute-form target or forwarded host

## Evidence To Collect

- front-end and origin choose different virtual hosts
- cache key differs from origin host

## False Positive Controls

- normal multi-tenant routing
- redirect canonicalization

## Safe Validation Boundary

- Manual only; route primary host-header impact separately.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [cache-chain](./cache-chain.md)
- [connection-state](./connection-state.md)
