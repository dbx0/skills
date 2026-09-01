# TE.0 / Dechunking Smuggling

## When To Consider

- edge or proxy dechunking policy
- Transfer-Encoding removed before origin

## Evidence To Collect

- hop-specific metadata shows dechunking before forwarding
- origin behavior differs from canonical chunked control

## False Positive Controls

- ordinary TE rejection
- proxy rewrites clean Content-Length

## Safe Validation Boundary

- Manual malformed framing only; isolate route and connection.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [te-cl](./te-cl.md)
- [chunked-parser-differentials](./chunked-parser-differentials.md)
