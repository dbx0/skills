# Request Smuggling Overview

## When To Consider

- proxy/CDN/gateway to distinct origin parser
- connection reuse or protocol translation evidence

## Evidence To Collect

- architecture hypothesis
- normal baseline metadata
- parser boundary candidate

## False Positive Controls

- scanner-only label
- single-parser direct path

## Safe Validation Boundary

- Collect passive architecture and protocol evidence first.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [cl-te](./cl-te.md)
- [te-cl](./te-cl.md)
- [te-0-dechunking](./te-0-dechunking.md)
