# TE.TE

## When To Consider

- duplicate or obfuscated Transfer-Encoding
- case or whitespace tolerant parser

## Evidence To Collect

- front-end and back-end normalize TE differently
- canonical TE control

## False Positive Controls

- generic invalid header rejection
- legacy proxy removes unknown coding

## Safe Validation Boundary

- Manual only; no broad TE mutation.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [chunked-parser-differentials](./chunked-parser-differentials.md)
