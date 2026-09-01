# TE.CL

## When To Consider

- chunked body accepted at edge
- origin appears to consume fixed length

## Evidence To Collect

- edge and origin disagree about final chunk
- backend response timing differs from edge response

## False Positive Controls

- proxy dechunks safely
- origin rejects chunked bodies

## Safe Validation Boundary

- Manual malformed framing only; strict request budget.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [cl-te](./cl-te.md)
- [te-0-dechunking](./te-0-dechunking.md)
