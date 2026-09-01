# Upgrade / CONNECT Optimistic Transition

## When To Consider

- Upgrade, CONNECT, WebSocket, connect-udp, or HTTP/2 CONNECT
- bytes sent before transition confirmation

## Evidence To Collect

- server interprets optimistic bytes as HTTP/1.1 after reject
- close-on-reject behavior is defined

## False Positive Controls

- compliant wait for 101/200
- server closes on reject

## Safe Validation Boundary

- Manual only; lab or owned proxy first.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [h2c-smuggling](./h2c-smuggling.md)
- [rfc2817-opportunistic-tls](./rfc2817-opportunistic-tls.md)
