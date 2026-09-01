#!/usr/bin/env python3
"""
Parseltongue Encoder for GODMODE jailbreak skill.
Obfuscates trigger words to bypass input-side safety classifiers.
"""

import sys
import argparse
import random
import base64
import json

# ===================== TIER 1: LIGHT (11 techniques) =====================


def leetspeak(text: str) -> str:
    """Classic leetspeak substitution."""
    mapping = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7',
               'A': '4', 'E': '3', 'I': '1', 'O': '0', 'S': '5', 'T': '7'}
    return ''.join(mapping.get(c, c) for c in text)


def unicode_cyrillic(text: str) -> str:
    """Replace Latin chars with Cyrillic lookalikes."""
    mapping = {'a': 'а', 'e': 'е', 'i': 'і', 'o': 'о', 'c': 'с', 'p': 'р',
               'x': 'х', 'y': 'у', 'A': 'А', 'E': 'Е', 'I': 'І', 'O': 'О',
               'C': 'С', 'P': 'Р', 'X': 'Х', 'Y': 'У'}
    return ''.join(mapping.get(c, c) for c in text)


def bubble_text(text: str) -> str:
    """Circled/bubble characters."""
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr(0x24D0 + ord(c) - ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr(0x24B6 + ord(c) - ord('A')))
        else:
            result.append(c)
    return ''.join(result)


def spaced(text: str) -> str:
    """Space between every character."""
    return ' '.join(text)


def underscored(text: str) -> str:
    """Underscore between every character."""
    return '_'.join(text)


def dotted(text: str) -> str:
    """Dot between every character."""
    return '.'.join(text)


def reversed_text(text: str) -> str:
    """Reverse the string."""
    return text[::-1]

MORSE_MAP = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', ' ': '/'
}


def morse(text: str) -> str:
    """Convert to Morse code."""
    return ' '.join(MORSE_MAP.get(c.upper(), c) for c in text)

SUPERSCRIPT_MAP = {c: chr(0x2070 + i) for i, c in enumerate('0123456789')}
SUPERSCRIPT_MAP.update({c: chr(0x1D43 + i) for i, c in enumerate('abcdefghijklmnopqrstuvwxyz')})
SUPERSCRIPT_MAP.update({c: chr(0x1D2C + i) for i, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ')})


def superscript(text: str) -> str:
    """Superscript characters."""
    return ''.join(SUPERSCRIPT_MAP.get(c, c) for c in text)

SUBSCRIPT_MAP = {c: chr(0x2080 + i) for i, c in enumerate('0123456789')}
SUBSCRIPT_MAP.update({c: chr(0x2090 + i) for i, c in enumerate('abcdefghijklmnopqrstuvwxyz')})


def subscript(text: str) -> str:
    """Subscript characters."""
    return ''.join(SUBSCRIPT_MAP.get(c, c) for c in text)


def pig_latin(text: str) -> str:
    """Convert to pig latin."""
    words = text.split()
    result = []
    for w in words:
        if len(w) > 1 and w.isalpha():
            result.append(w[1:] + w[0] + 'ay')
        else:
            result.append(w + 'ay')
    return ' '.join(result)

# ===================== TIER 2: STANDARD (22 techniques) =====================


def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def hex_encode(text: str) -> str:
    return text.encode().hex()


def rot13(text: str) -> str:
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))

BRAILLE_MAP = {
    'a': '⠁', 'b': '⠃', 'c': '⠉', 'd': '⠙', 'e': '⠑', 'f': '⠋',
    'g': '⠛', 'h': '⠓', 'i': '⠊', 'j': '⠚', 'k': '⠅', 'l': '⠇',
    'm': '⠍', 'n': '⠝', 'o': '⠕', 'p': '⠏', 'q': '⠟', 'r': '⠗',
    's': '⠎', 't': '⠞', 'u': '⠥', 'v': '⠧', 'w': '⠺', 'x': '⠭',
    'y': '⠽', 'z': '⠵', ' ': '⠀'
}


def braille(text: str) -> str:
    return ''.join(BRAILLE_MAP.get(c.lower(), c) for c in text)

MATH_BOLD_MAP = {c: chr(0x1D400 + i) for i, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}
MATH_BOLD_MAP.update({c: chr(0x1D41A + i) for i, c in enumerate('abcdefghijklmnopqrstuvwxyz')})


def math_bold(text: str) -> str:
    return ''.join(MATH_BOLD_MAP.get(c, c) for c in text)

MATH_ITALIC_MAP = {c: chr(0x1D434 + i) for i, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}
MATH_ITALIC_MAP.update({c: chr(0x1D44E + i) for i, c in enumerate('abcdefghijklmnopqrstuvwxyz')})


def math_italic(text: str) -> str:
    return ''.join(MATH_ITALIC_MAP.get(c, c) for c in text)


def bracketed(text: str) -> str:
    return ''.join(f'[{c}]' for c in text)


def parenthesized(text: str) -> str:
    return ''.join(f'({c})' for c in text)


def double_spaced(text: str) -> str:
    return '  '.join(text)


def comma_separated(text: str) -> str:
    return ','.join(text)

# ===================== TIER 3: HEAVY (33 techniques) =====================


def base64_leetspeak(text: str) -> str:
    return base64.b64encode(leetspeak(text).encode()).decode()


def hex_unicode(text: str) -> str:
    return ''.join(f'\\u{ord(c):04x}' for c in text)


def url_encoded(text: str) -> str:
    return ''.join(f'%{ord(c):02x}' for c in text)


def html_entities(text: str) -> str:
    return ''.join(f'&#x{ord(c):x};' for c in text)


def acrostic_first(text: str) -> str:
    return ' '.join(w[0] for w in text.split() if w)


def acrostic_last(text: str) -> str:
    return ' '.join(w[-1] for w in text.split() if w)


def triple_layer(text: str) -> str:
    return base64.b64encode(base64.b64encode(text.encode()).decode().encode()).decode()


def unicode_zwj(text: str) -> str:
    return '\u200d'.join(text)


def unicode_bom(text: str) -> str:
    return '\ufeff' + text


def null_injection(text: str) -> str:
    return '\x00'.join(text)

# ===================== ENCODER REGISTRY =====================

LIGHT_ENCODERS = {
    "leetspeak": leetspeak,
    "unicode_cyrillic": unicode_cyrillic,
    "bubble": bubble_text,
    "spaced": spaced,
    "underscored": underscored,
    "dotted": dotted,
    "reversed": reversed_text,
    "morse": morse,
    "superscript": superscript,
    "subscript": subscript,
    "pig_latin": pig_latin,
}

STANDARD_ENCODERS = {
    **LIGHT_ENCODERS,
    "base64": base64_encode,
    "hex": hex_encode,
    "rot13": rot13,
    "braille": braille,
    "math_bold": math_bold,
    "math_italic": math_italic,
    "bracketed": bracketed,
    "parenthesized": parenthesized,
    "double_spaced": double_spaced,
    "comma_separated": comma_separated,
}

HEAVY_ENCODERS = {
    **STANDARD_ENCODERS,
    "base64_leetspeak": base64_leetspeak,
    "hex_unicode": hex_unicode,
    "url_encoded": url_encoded,
    "html_entities": html_entities,
    "acrostic_first": acrostic_first,
    "acrostic_last": acrostic_last,
    "triple_layer": triple_layer,
    "unicode_zwj": unicode_zwj,
    "unicode_bom": unicode_bom,
    "null_injection": null_injection,
}

ALL_ENCODERS = {
    "light": LIGHT_ENCODERS,
    "standard": STANDARD_ENCODERS,
    "heavy": HEAVY_ENCODERS,
}

TIER_LABELS = {
    "light": "L0-Light",
    "standard": "L1-Standard",
    "heavy": "L2-Heavy",
}


def generate_variants(text: str, tier: str = "standard", max_variants: int = None) -> list:
    """Generate encoded variants of the input text."""
    encoders = ALL_ENCODERS.get(tier, STANDARD_ENCODERS)
    variants = []

    for name, encoder in encoders.items():
        try:
            encoded = encoder(text)
            if encoded != text:
                variants.append({
                    "label": f"[{TIER_LABELS[tier]}:{name}]",
                    "encoder": name,
                    "tier": tier,
                    "text": encoded
                })
        except Exception as e:
            variants.append({
                "label": f"[{TIER_LABELS[tier]}:{name}:ERROR]",
                "encoder": name,
                "tier": tier,
                "text": f"Error: {e}"
            })

    if max_variants and len(variants) > max_variants:
        variants = variants[:max_variants]

    return variants


def main():
    parser = argparse.ArgumentParser(description="Parseltongue Encoder for GODMODE")
    parser.add_argument("text", nargs="?", help="Text to encode (stdin if omitted)")
    parser.add_argument("--tier", choices=["light", "standard", "heavy"], default="standard",
                        help="Encoding tier (default: standard)")
    parser.add_argument("--encoder", help="Specific encoder to use")
    parser.add_argument("--list", action="store_true", help="List available encoders")
    parser.add_argument("--max", type=int, default=10, help="Max variants to show")
    parser.add_argument("--json", action="store_true", help="Output JSON")

    args = parser.parse_args()

    if args.list:
        for tier, encoders in ALL_ENCODERS.items():
            print(f"\n=== {tier.upper()} ({len(encoders)} encoders) ===")
            for name in sorted(encoders.keys()):
                print(f"  {name}")
        return

    # Read input
    if args.text:
        text = args.text
    else:
        text = sys.stdin.read().strip()

    if not text:
        print("No input text provided", file=sys.stderr)
        sys.exit(1)

    if args.encoder:
        # Single encoder
        encoders = {**LIGHT_ENCODERS, **STANDARD_ENCODERS, **HEAVY_ENCODERS}
        if args.encoder not in encoders:
            print(f"Unknown encoder: {args.encoder}", file=sys.stderr)
            sys.exit(1)
        result = encoders[args.encoder](text)
        if args.json:
            print(json.dumps({"encoder": args.encoder, "text": result}))
        else:
            print(result)
    else:
        # All variants for tier
        variants = generate_variants(text, args.tier, args.max)
        if args.json:
            print(json.dumps(variants, indent=2))
        else:
            for v in variants:
                print(f"{v['label']:30} {v['text']}")


if __name__ == "__main__":
    main()