---
name: docs-generator
description: |
  Creates task-oriented technical documentation with progressive disclosure. Use when writing READMEs, API docs, architecture docs, or markdown documentation.
  Also use this skill at the END of any completed reverse engineering, penetration testing, CTF, or security analysis task to generate a formal report in the user's project directory.
  Trigger keywords: write report, write documentation, produce report, writeup, technical documentation, report, documentation.
---

# Technical Documentation

For writing style, tone, and voice guidance, use `Skill(ce:writer)` with **The Engineer** persona.

## Security/Reverse-Engineering Task Documentation Output

When a reverse-engineering/penetration/CTF/security-analysis task is complete, this skill is responsible for generating a formal technical report in the **user's project directory**.

### When to trigger

1. A reverse-engineering task is complete and core conclusions have been produced (algorithm reconstruction, signature cracking, bypass solutions, etc.)
2. A penetration test is complete and a vulnerability has been discovered and verified
3. A CTF challenge is solved and the flag has been obtained
4. The user explicitly asks to "write a report/document/writeup"

### Template selection

| Task type | Template to use |
|---------|---------|
| APK/binary/so reverse engineering | `references/security-report-templates.md` → Reverse Engineering Report |
| Penetration testing/vulnerability hunting | `references/security-report-templates.md` → Penetration Test Report |
| CTF solving | `references/security-report-templates.md` → CTF Writeup |
| JS/Web signature reversing | `references/security-report-templates.md` → Signature Reversing Report |
| General technical documentation | `references/templates.md` → README / API docs |

### Output specification

- **Output location**: the user's current project directory (not the skill package directory)
- **Filename format**: `YYYY-MM-DD_[type]-[target short name]-report.md`
- **If the project has a `docs/` directory**: prefer placing it under `docs/`
- **Encoding**: UTF-8
- **Language**: follow the user's conversation language (a Chinese conversation produces a Chinese report, an English conversation produces an English report)

### Quality requirements

- Every code block must be directly runnable or have clear context
- No placeholders/TODOs
- Key findings must be backed by evidence
- Reproduction steps must let a third party reproduce them independently
- Sensitive information (real tokens, passwords, internal URLs) must be replaced with placeholders

### Diagram integration

When generating a report, call the `diagram-generator` skill at appropriate points to generate visual diagrams:

| Report type | Suggested diagram | Diagram type |
|---------|---------|---------|
| Reverse engineering report | Function call graph, data flow diagram | Mermaid flowchart / sequenceDiagram |
| Penetration test report | Attack path diagram, network topology diagram | Mermaid flowchart / Graphviz |
| CTF Writeup | Solution approach flowchart | Mermaid flowchart |
| JS signature reversing report | Request chain sequence diagram, algorithm flowchart | Mermaid sequenceDiagram / flowchart |

Diagrams are embedded in the report markdown as Mermaid code blocks, ensuring they render directly on GitHub/GitLab.

---

## Core Principles

### 1. Progressive Disclosure

Reveal information in layers:

| Layer | Content | User Question |
|-------|---------|---------------|
| 1 | One-sentence description | What is it? |
| 2 | Quick start code block | How do I use it? |
| 3 | Full API reference | What are my options? |
| 4 | Architecture deep dive | How does it work? |

**Warnings, breaking changes, and prerequisites go at the TOP.**

### 2. Task-Oriented Writing

```markdown
<!-- Bad: Feature-oriented -->
## AuthService Class
The AuthService class provides authentication methods...

<!-- Good: Task-oriented -->
## Authenticating Users
To authenticate a user, call login() with credentials:
```

### 3. Show, Don't Tell

Every concept needs a concrete example.

## Formatting Standards

- **Sentence case headings**: "Getting started" not "Getting Started"
- **Max 3 heading levels**: Deeper means split the doc
- **Always specify language** in code blocks
- **Relative paths** for internal links
- **Tables** for structured data with 3+ attributes

## Quality Checklist

- [ ] Code examples tested and runnable
- [ ] No placeholder text or TODOs
- [ ] Matches actual code behavior
- [ ] Scannable without reading everything
- [ ] Reader knows what to do next

## Anti-Patterns

| Problem | Fix |
|---------|-----|
| Wall of text | Break up with headings, bullets, code, tables |
| Buried critical info | Warnings/breaking changes at TOP |
| Missing error docs | Always document what can go wrong |

## Templates

For README, API endpoint, and file organization templates, see [references/templates.md](references/templates.md).

## Related Skills

- `Skill(ce:writer)` - Writing style, tone, and voice (load The Engineer persona)
- `Skill(ce:visualizing-with-mermaid)` - Architecture and flow diagrams

---

## On-Demand Bootstrap

This skill does not depend on external tools; it is pure text generation. No bootstrap needed.

If diagrams need to be rendered and embedded in the report, it calls the `diagram-generator/` skill.

---

## Routing Context

**Upstream entry**: all security/reverse-engineering skills automatically call this skill once their task is complete
**Trigger methods**:
- Automatic: executed as step 9 of the behavior chain after the task completes
- Manual: the user says "write a report", "produce a document", "writeup"

**Peer-related modules**:
- `apk-reverse/` — generates a reverse-engineering report after APK reversing completes
- `ida-reverse/` — generates a reverse-engineering report after binary analysis completes
- `radare2/` — generates a reverse-engineering report after CLI analysis completes
- `js-reverse/` — generates a signature report after JS signature reversing completes
- `reverse-engineering/` — generates a reverse-engineering report after general reversing completes
- `field-journal/` — report content also serves as a data source for the evolution journal

**Security report templates**: `references/security-report-templates.md`
**General documentation templates**: `references/templates.md`
