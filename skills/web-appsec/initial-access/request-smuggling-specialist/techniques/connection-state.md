# Connection State Attack

## When To Consider

- front-end connection remembers Host, auth, SNI, or routing
- prior request affects later request

## Evidence To Collect

- state mutation on same connection
- control request then probe request sequence

## False Positive Controls

- normal keep-alive
- session cookie state

## Safe Validation Boundary

- Manual only; route host/auth issues to the right owner.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [host-routing](./host-routing.md)
- [http3-connection-contamination](./http3-connection-contamination.md)
