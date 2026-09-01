# CL.0

## When To Consider

- server responds before consuming promised body
- endpoint ignores request body

## Evidence To Collect

- body suffix affects later parsing
- endpoint-specific early response

## False Positive Controls

- server closes connection
- self-visible client artifact

## Safe Validation Boundary

- Manual only; isolate connection.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [client-side-desync](./client-side-desync.md)
- [browser-powered-desync](./browser-powered-desync.md)
