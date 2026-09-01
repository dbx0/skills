# Browser-Powered Server-Side Desync

## When To Consider

- browser can trigger prefix
- front-end streams to origin

## Evidence To Collect

- browser constraints understood
- test account impact path

## False Positive Controls

- browser cannot send required headers
- preflight changes method

## Safe Validation Boundary

- Manual gate; browser lab first.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [client-side-desync](./client-side-desync.md)
