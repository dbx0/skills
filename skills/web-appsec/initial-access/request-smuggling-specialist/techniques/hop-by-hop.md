# Hop-By-Hop Header Confusion

## When To Consider

- Connection nominates TE, Host-like, or auth-like fields
- custom hop-by-hop stripping

## Evidence To Collect

- one hop removes field another depends on
- origin receives improper framing or loses security header

## False Positive Controls

- proxy strips all hop-by-hop safely
- application ignores header

## Safe Validation Boundary

- Manual metadata proof first.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [waf-parser-gap](./waf-parser-gap.md)
