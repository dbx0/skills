# HTTP/1.0 + Transfer-Encoding

## When To Consider

- HTTP/1.0 request with TE
- close-delimited body

## Evidence To Collect

- proxy/origin disagree on body end
- strict parser rejects control

## False Positive Controls

- server upgrades internally to HTTP/1.1
- connection close prevents queue impact

## Safe Validation Boundary

- Manual only; record version line.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [te-cl](./te-cl.md)
