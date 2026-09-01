# WAF / ACL Bypass via Parser Discrepancy

## When To Consider

- WAF blocks one parsed request but origin may parse another
- body or header parser mismatch

## Evidence To Collect

- blocked control path becomes reachable read-only
- origin action is safe

## False Positive Controls

- route is public
- WAF allowlist by design

## Safe Validation Boundary

- Manual only; read-only target route.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [hop-by-hop](./hop-by-hop.md)
- [host-routing](./host-routing.md)
