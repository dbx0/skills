# Fallback Strategy

When the current path makes no progress, fall back in this order:

1. From breakpoints back to request observation
2. From source-code guessing back to runtime evidence
3. From Node environment-shimming back to page forensics
4. From deep deobfuscation back to a minimal reproducible chain
