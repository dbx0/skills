# AI Assisted Reverse Engineering

> LLM driven decompilation / multi-agent verification / neural semantic recovery
> The biggest paradigm shift of 2025-2026

## Core Tools and Models

### LLM4Decompile
- The first open source framework applying LLMs to binary → source decompilation
- Supports multiple architectures: x86/ARM/MIPS
- Input: assembly code → output: C source
- Training data: millions of source-assembly pairs

### Decaf (2026)
- **Compiler feedback verification**: take the LLM generated source → compile it → compare against the original binary
- Result: decompilation rate 26% → 83.9% (ExeBench Real -O2)
- Key insight: the feedback loop is more effective than a bigger model

### Constraint-Guided Multi-Agent (2026)
- Three stage verification pipeline:
  1. Syntactic correctness (parsing)
  2. Compilability (GCC)
  3. Behavioral equivalence (LLM generated test cases)
- 84-97% re-executability rate, at only $0.03-0.05 per run

### REMEND (2026)
- Specialty: extracting mathematical equations from binaries
- 89.8-92.4% accuracy (across 3 ISAs × 3 optimization levels × 2 languages)
- Speed: 0.132s per function, only 12M parameters

### Glaurung
- Open source Ghidra alternative, Rust core plus Python bindings
- **AI native architecture**: an LLM agent embedded at every analysis layer
- Evidence artifacts: plain/rich/JSON/JSONL output formats for LLM consumption
- Supports: ELF/PE/Mach-O, x86/ARM/RISC-V, IOC detection, entropy analysis

## Workflow: AI Augmented Binary Analysis

### 1. LLM Assisted Fast Recon

```text
□ strings extraction → LLM semantic classification (URLs/keys/paths/protocols)
□ Import table analysis → LLM infers functionality (crypto=OpenSSL? network=libcurl?)
□ Disassembly snippets → LLM identifies patterns (crypto algorithms, anti-debugging, VM detection)
□ Error messages → LLM infers context ("Invalid license" → where the licensing logic lives)
```

### 2. Neural Decompilation

```bash
# LLM4Decompile
python llm4decompile.py --binary target.so --arch arm64 --output target.c

# Verify the result (recompile and compare)
gcc -O2 -o target_recompiled target.c -fPIC -shared
# → verify behavioral equivalence of the output
```

### 3. Multi-Agent Verification

```text
Agent 1 (syntax): check whether the generated C code parses
  ↓ fail → feed the error message back to the LLM and retry
Agent 2 (compile): compile with GCC → check warnings/errors
  ↓ fail → feed the compiler errors back to the LLM
Agent 3 (behavior): LLM generates inputs → run the original and the recompiled build → compare output
  ↓ mismatch → feed the difference back to the LLM → iterate on the fix
```

### 4. LLM Assisted Static Analysis

```text
□ Function renaming: feed in the decompiled pseudocode → LLM suggests meaningful names
□ Type recovery: analyze the context → LLM infers struct/class definitions
□ Algorithm identification: assembly snippets → LLM identifies the crypto algorithm (AES/TEA/RC4/custom)
□ Protocol reversing: packet sequences → LLM infers the protocol format
□ Comment generation: decompiled code → LLM generates comments in Chinese or English
```

### 5. macOS/iOS Private Framework Reversing (MOTIF)

```text
Problem: macOS private frameworks are undocumented and type information is missing
Approach: the LLM analyzes usage patterns → infers method signatures and parameter types
Result: ObjC signature recovery 15% → 86% (vs static analysis)
```

## LLM Prompt Templates

### Function Semantic Analysis

```
You are a reverse engineering expert. Analyze this decompiled function:

[pseudocode]

1. What does this function do? (one sentence)
2. Suggest a meaningful function name.
3. What are the input parameters and their likely types?
4. What is the return value?
5. What external APIs/functions does it depend on?
6. Any security-relevant operations (crypto, auth, network, file I/O)?
```

### Algorithm Identification

```
Analyze this assembly/disassembly for cryptographic operations:

[assembly code]

1. Is this a known cryptographic algorithm? (AES/DES/RC4/TEA/ChaCha20/custom?)
2. Identify the key schedule and round structure.
3. What is the key size?
4. Are there any hardcoded constants that identify the algorithm?
```

### Protocol Format Inference

```
Given this network packet sequence, infer the protocol structure:

[hex dump]

1. Identify magic bytes and length fields.
2. Propose a struct definition for the packet header.
3. What field(s) appear to be checksums/CRCs?
4. Is this a known protocol or custom?
```

## Choosing a Tool

| Scenario | Recommended Tool | Cost |
|------|---------|------|
| Fast decompilation | LLM4Decompile | Free (local GPU) |
| High accuracy decompilation | Constraint-Guided Multi-Agent | ~$0.05 per binary |
| Mathematical function extraction | REMEND | Free |
| Cross platform RE | Glaurung (Rust) | Free and open source |
| LLM interaction | Claude API / GPT-4 / DeepSeek | ~$0.01-0.10 per call |

## Limitations

- **Complex control flow**: virtualized/obfuscated code is still hard (control flow flattening, VMProtect)
- **Indirect calls**: vtables and function pointers are difficult to recover
- **Inlined functions**: boundaries blur once the compiler inlines
- **Floating point math**: semantic recovery of vectorized instructions still needs work
- **Context window**: large functions (>1000 lines) exceed the LLM's context limit

Source: Decaf (2026), REMEND (2026), Constraint-Guided Multi-Agent Decompilation (2026), LLM4Decompile, Glaurung
