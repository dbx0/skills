# HTTP Request Tunnelling

## When To Consider

- two responses behind one front-end request
- hidden inner request without cross-user queue poisoning

## Evidence To Collect

- second response reveals metadata or front-end bypass
- works without victim traffic

## False Positive Controls

- HTTP/1 pipelining false positive
- debug server extra response

## Safe Validation Boundary

- Manual only; disable client reuse first.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [trace-assisted-desync](./trace-assisted-desync.md)
- [response-queue-poisoning](./response-queue-poisoning.md)
