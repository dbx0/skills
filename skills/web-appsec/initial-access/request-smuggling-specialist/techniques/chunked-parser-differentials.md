# Chunked Parser Differentials

## When To Consider

- chunk extension discrepancy
- TERM.EXT, EXT.TERM, TERM.SPILL, or SPILL.TERM behavior

## Evidence To Collect

- front-end and origin disagree where chunked body ends
- canonical chunked controls behave normally

## False Positive Controls

- generic invalid chunk rejection
- client normalized chunk syntax

## Safe Validation Boundary

- Manual research-only; no broad mutation campaigns.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [te-te](./te-te.md)
- [trailers](./trailers.md)
