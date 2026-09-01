# Trailer and TE: Trailers Boundary

## When To Consider

- Trailer header, chunked trailers, TE: trailers
- TRAIL.TERM or TERM.TRAIL boundary

## Evidence To Collect

- security decision ignores/accepts trailer differently
- request joining follows trailer termination

## False Positive Controls

- trailers ignored consistently
- client library never sends

## Safe Validation Boundary

- Manual only; metadata proof first.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [chunked-parser-differentials](./chunked-parser-differentials.md)
