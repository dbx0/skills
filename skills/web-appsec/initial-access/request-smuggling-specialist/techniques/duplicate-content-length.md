# Duplicate Content-Length

## When To Consider

- duplicate CL fields
- comma-joined or conflicting CL values

## Evidence To Collect

- one hop rejects while another forwards
- logs or responses map to parser choice

## False Positive Controls

- client library canonicalized values
- proxy rejects before origin

## Safe Validation Boundary

- Manual malformed framing only.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [invalid-content-length](./invalid-content-length.md)
