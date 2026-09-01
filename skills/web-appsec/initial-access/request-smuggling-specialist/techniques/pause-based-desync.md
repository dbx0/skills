# Pause-Based Desync

## When To Consider

- headers sent then delayed body
- timeout asymmetry

## Evidence To Collect

- front-end streams partial request
- late body affects later parsing

## False Positive Controls

- slowloris behavior
- front-end timeout first

## Safe Validation Boundary

- Manual gate; strict timeout budget.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [cl-0](./cl-0.md)
