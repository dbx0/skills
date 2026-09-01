# h2c Cleartext Upgrade Smuggling

## When To Consider

- h2c advertised or accepted on proxy-facing route
- Upgrade: h2c reaches unintended hop

## Evidence To Collect

- front-end policy differs from backend protocol acceptance
- h2c path reaches route blocked over HTTP/1.1

## False Positive Controls

- TLS ALPN h2 confused with h2c
- proxy fully terminates upgrade

## Safe Validation Boundary

- Inventory first; manual upgrade probes only.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [protocol-transition](./protocol-transition.md)
