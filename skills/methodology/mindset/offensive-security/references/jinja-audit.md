# llama.cpp Jinja2 Chat Template Engine — Security Audit

**Date:** July 2025
**Target:** llama.cpp commit b9840 / b9888 (`common/jinja/`)
**Component:** Custom C++ Jinja2 interpreter for `tokenizer.chat_template` rendering

---

## Executive Summary

**No RCE possible.** The engine is a clean-room C++ implementation of a Jinja2 **subset** with:
- No filesystem access (`include`, `import`, `extends` not implemented)
- No code execution (`eval`, `exec` not implemented)
- No network access
- No reflection/attribute access on C++ objects

**Only DoS vectors exist** — resource exhaustion via unbounded allocations in filters/builtins.

---

## Architecture

```
GGUF tokenizer.chat_template (string)
         │
         ▼
common_chat_templates_apply_jinja()  (chat.cpp:2629)
         │
         ▼
jinja::context + jinja::runtime      (runtime.cpp)
         │
         ▼
AST Execution → String Output
```

### Key Files

| File | Lines | Purpose |
|------|-------|---------|
| `common/jinja/runtime.h/cpp` | ~1000 | AST nodes, context, execution engine |
| `common/jinja/value.h/cpp` | ~1500 | Value types, ALL builtins/filters/tests |
| `common/jinja/parser.h/cpp` | ~300 | PEG-like parser |
| `common/jinja/lexer.h/cpp` | ~200 | Tokenizer |

---

## Complete Builtin Catalog

### Global Functions (`value.cpp:351-530`)

| Function | Args | Risk |
|----------|------|------|
| `raise_exception(msg)` | string | DoS — throws C++ exception (caught) |
| `namespace(**kwargs)` | kwargs | Low — creates object |
| `strftime_now(format)` | string | Low — `std::strftime` |
| `range(start?, stop, step?)` | ints | **DoS** — `range(1e9)` allocates 8GB |
| `tojson(value, ...)` | any | Low — JSON serialize |

### String Filters (`value.cpp:597-879`)

| Filter | Risk | Notes |
|--------|------|-------|
| `upper`, `lower`, `title`, `capitalize` | Low | |
| `strip`, `lstrip`, `rstrip` | Low | |
| `replace(old, new, count?)` | **DoS** | `replace("", "x")` → **infinite loop** (find("") returns 0) |
| `split(delim?, maxsplit?)` | **DoS** | `split("")` → splits every char; huge array |
| `rsplit` | **DoS** | Same as split |
| `slice(start, stop, step)` | Low | Bounds checked |
| `indent(width, first?, blank?)` | **DoS** | `indent(1e9)` → 1GB string |
| `truncate(length, killwords?, end?)` | Low | |
| `wordcount` | Low | |
| `int(default?, base?)`, `float(default?)`, `string` | Low | Parse |
| `default(default, boolean?)`, `safe`, `tojson` | Low | |
| `join(d?)` | **DoS** | Not implemented → throws |

### Array/Sequence Filters (`value.cpp:912-1157`)

| Filter | Risk |
|--------|------|
| `first`, `last`, `length` | Low |
| `slice` | Low |
| `selectattr(attr, test?, *args)` | **DoS** — iterates entire array, calls test per item |
| `rejectattr` | **DoS** — same |
| `map(attr, *args)` | **DoS** — same |
| `select(test, *args)`, `reject` | **DoS** — same |
| `list`, `sort(reverse?, case_sensitive?, attribute?)`, `reverse` | **DoS** on huge arrays |
| `min`, `max` | **DoS** — iterates all |
| `sum(start?, attribute?)` | **DoS** |
| `unique(case_sensitive?, attribute?)` | **DoS** — builds set |
| `batch(count, fill?)`, `groupby(attribute)` | **DoS** — builds nested structures |
| `join(d?, attribute?)` | Low (if implemented) |

### Object Filters (`value.cpp:1164-1257`)

| Filter | Risk |
|--------|------|
| `get(key, default?)`, `keys`, `values`, `items` | Low |
| `tojson`, `string`, `length` | Low |
| `dictsort(case_sensitive?, by?, reverse?)` | Low |
| `join` | Not implemented |

### Tests (`value.cpp:423-528`)

All tests are **low risk** — type checks, comparisons, membership. No side effects.

---

## Vulnerability Details

### VULN-JINJA-01: `replace("", "x")` Infinite Loop

**File:** `value.cpp:722-752`

```cpp
while ((pos = str.find(old_str, pos)) != std::string::npos) {
    result += str.substr(last, pos - last);
    result += new_str;
    pos += old_str.length();  // BUG: if old_str=="", pos doesn't advance!
    last = pos;
}
```

**Exploit:** `{{ "hello" | replace("", "X") }}` → CPU 100% until killed.

**Fix:** Reject empty `old_str` or advance by 1 when empty.

---

### VULN-JINJA-02: `split("")` / `rsplit("")` OOM

**File:** `value.cpp:667-721`

```cpp
std::string delim = (args.count() > 1) ? args.get_pos(1)->as_string().str() : " ";
if (delim.empty()) {
    throw raised_exception("empty separator");  // MISSING!
}
```

**Exploit:** `{{ "A" * 1000000 | split("") }}` → 1M element array.

**Fix:** Reject empty delimiter.

---

### VULN-JINJA-03: `range(0, 1_000_000_000)` OOM

**File:** `value.cpp:382-419`

```cpp
for (int64_t i = start; step > 0 ? i < stop : i > stop; i += step) {
    out->push_back(mk_val<value_int>(i));  // No upper bound check
}
```

**Exploit:** `{{ range(0, 1000000000) | list | length }}` → allocates ~8GB.

**Fix:** Cap at 10,000 elements.

---

### VULN-JINJA-04: `indent(1_000_000_000)` OOM

**File:** `value.cpp:835-876`

```cpp
indent.assign(val_width->as_int(), ' ');  // No bounds check
```

**Fix:** Cap width at 10,000.

---

### VULN-JINJA-05: `tojson` Self-Reference Stack Overflow

**File:** `value.cpp:235-262`

```cpp
static std::string json_ensure_ascii_preserving_format(...) {
    // Recursive, no cycle detection
}
```

**Exploit:**
```jinja2
{% set x = {"self": x} %}  {# self-referential #}
{{ x | tojson }}
```

**Fix:** Track visited objects during serialization.

---

### VULN-JINJA-06: `selectattr`/`map`/`select`/`reject` on Huge Arrays

**File:** `value.cpp:912-1050`

All iterate entire input array with no limit:

```cpp
for (const auto & item : arr) {
    // calls test/filter per item
}
```

**Exploit:** `{{ messages | selectattr("content", "length") | list | length }}` with 1M messages.

**Fix:** Add iteration limits.

---

## Attack Surface Analysis

### What an Attacker Controls

1. **`tokenizer.chat_template`** — Full template string from GGUF metadata
2. **`messages`** — Conversation history (user-controlled)
3. **`tools`** — Tool definitions (user/model-controlled)
4. **`chat_template_kwargs`** — Arbitrary JSON merged into context

### What the Template Receives (from `chat.cpp:2631-2698`)

```json
{
  "messages": [...],
  "tools": [...],
  "bos_token": "<s>",
  "eos_token": "