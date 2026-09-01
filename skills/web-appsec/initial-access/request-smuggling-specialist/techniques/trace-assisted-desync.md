# TRACE-Assisted Desync Gadget

## When To Consider

- TRACE enabled through proxy chain
- response concatenation or hidden second response visible

## Evidence To Collect

- root parser differential named separately
- response header removal explains visibility

## False Positive Controls

- TRACE only reflects visible request
- client-side pipelining output

## Safe Validation Boundary

- Manual only; stop on sensitive reflected headers.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [request-tunnelling](./request-tunnelling.md)
