# HTTP Request Smuggling / Desync Specialist

A lightweight SSkills specialist for triaging request smuggling and HTTP desync signals.

This is not an exploit pack. It does not generate malformed framing automatically, does not use victim traffic, and does not perform shared cache or queue poisoning.

## How To Use

1. Start with [router.md](router.md).
2. Apply [safety.md](safety.md).
3. Load at most three relevant files from [techniques](techniques/index.md).
4. Return structured output using [output-schema.json](output-schema.json).

## Why This Shape

The specialist is intentionally small at the entrypoint. It expects another system to route a broad signal such as `request_smuggling`, then uses the router to choose precise technique cards. This keeps assimilation low while preserving specialist depth.

## Included Technique Cards

See [techniques/index.md](techniques/index.md).

## Sources

See [sources.json](sources.json).

## License

MIT. See the collection-level [LICENSE](../../LICENSE).
