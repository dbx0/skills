#!/usr/bin/env python3
"""Parse SSRF error messages from Ollama to extract leaked characters.
Usage: echo '<json_error>' | python3 parse_ssrf_error.py

Handles all JSON parser error patterns:
- "invalid character 'X' looking for beginning of value" -> X
- "invalid character 'X' in literal false/true/null (expecting 'Y')" -> maps back to f/t/n
- "unexpected end of JSON input" -> '{'
"""
import sys
import re
import json

line = sys.stdin.read().strip()

try:
    data = json.loads(line)
    err = data.get('error', '')
except (json.JSONDecodeError, AttributeError):
    m = re.search(r'"error":"([^"]*)"', line)
    err = m.group(1).replace('\\"', '"') if m else ''

# Pattern 1: direct character leak
m = re.search(r"invalid character '([^']+)' looking for beginning of value", err)
if m:
    print(m.group(1))
    sys.exit(0)

# Pattern 2: JSON literal confusion (f, t, n)
m = re.search(r"invalid character '([^']+)' in literal (\w+) \(expecting '([^']+)'\)", err)
if m:
    literal_map = {('false', 'a'): 'f', ('true', 'r'): 't', ('null', 'u'): 'n'}
    key = (m.group(2), m.group(3))
    print(literal_map.get(key, m.group(1)))
    sys.exit(0)

# Pattern 3: '{' starts JSON object, fails with unexpected end
if 'unexpected end of JSON input' in err:
    print('{')
    sys.exit(0)

# Pattern 4: catch-all
m = re.search(r"invalid character '([^']+)'", err)
if m:
    print(m.group(1))
    sys.exit(0)

print('?')
