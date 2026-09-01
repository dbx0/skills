# Cache Poisoning Desync Chain

## When To Consider

- cache layer and response queue anomaly
- unkeyed header or origin shield

## Evidence To Collect

- poison affects disposable cache key
- HIT/MISS/Age evidence

## False Positive Controls

- normal cache variance
- private/no-store response

## Safe Validation Boundary

- Manual gate; unguessable disposable path and purge plan.
- Do not generate payloads automatically.
- Store metadata, hashes, and response shapes only.

## Output Requirements

- Name the suspected parser boundary.
- State the weakest missing evidence.
- Choose one safe next step.
- Mark active validation as manual-gated unless it is ordinary GET/HEAD inventory.

## Related Techniques

- [host-routing](./host-routing.md)
- [response-queue-poisoning](./response-queue-poisoning.md)
