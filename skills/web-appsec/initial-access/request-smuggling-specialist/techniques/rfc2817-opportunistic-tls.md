# Opportunistic TLS / RFC 2817 Desync

## When To Consider

- RFC 2817 style Upgrade path
- opportunistic TLS between proxy and origin

## Evidence To Collect

- one hop switches protocol while another continues HTTP/1.1 parsing
- close-on-reject differs

## False Positive Controls

- TLS upgrade not enabled
- connection closes before follow-up interpretation

## Safe Validation Boundary

- Lab or owned proxy first; no third-party tunnel traffic.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [protocol-transition](./protocol-transition.md)
