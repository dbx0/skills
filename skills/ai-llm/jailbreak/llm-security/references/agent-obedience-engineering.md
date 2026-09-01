# AI Agent Obedience Engineering — Getting the AI to Actually Do the Work After Reading the Workflow

> Source: 2026 multi-source synthesis (Anthropic Skill Engineering, Microsoft Code Words, Strands Steering Hooks, Gradient Flow Harness Engineering)
> Applicable scenario: AI coding Agents (Claude Code / Codex / Cursor / Cline / Windsurf / Kiro, etc.) that, after reading README/RULES.md, only acknowledge without executing, skip steps, or unilaterally omit key operations

---

## Root-Cause Diagnosis

The root cause of an AI Agent "reading the workflow but not doing the work" is not insufficient model capability, but rather that **natural-language instructions contain semantic escape room**:

| Root Cause | Explanation |
|------|------|
| **Context attention decay** | Content in the middle of a long document is down-weighted by the LLM attention mechanism; the Agent effectively only "sees" the beginning and the end |
| **Semantic override** | When optimizing for "helpfulness", the model creatively reinterprets explicit instructions (e.g. reading MUST DO X as "it is recommended to do X") |
| **Passive language treated as optional** | "Ready for next step → invoke X" is taken as a suggestion rather than an instruction |
| **Stateless enforcement** | Lacking an external state machine to validate workflow order, the Agent can skip steps without being detected |
| **Silent state corruption** | The Agent produces results that are structurally correct but semantically wrong, and errors accumulate silently |

---

## Technique 1: Instruction-First Principle (Critical-First Pattern)

**Put "what to do next" at the very front, and the context afterward.**

```
WRONG (Agent ignores):
  [70 lines of project background and tool list]
  → "Next step: run bootstrap to install missing tools"

CORRECT (Agent executes):
  "## Execute immediately: run `bootstrap-reverse.ps1` to check and install missing tools
   → After completion read routing.md to determine which skill to enter"
  [then the project background and tool list]
```

**Principle**: the LLM assigns the highest attention weight to the beginning and end of the prompt. Middle content may be completely ignored.

**Applied to this project**:
- The "routing entry" section of RULES.md should come after the trigger keywords and before the execution principles
- The first section of every SKILL.md should be "Execute immediately" rather than "Applicable scenarios"

---

## Technique 2: Directive Language Substitution (Directive Over Suggestive)

Replace all "suggestive" language with RFC 2119-level directive language:

| Weak language (Agent may skip) | Strong language (Agent enforces) |
|---|---|
| "You can try..." | **MUST**: you must execute... |
| "Ready for next step → invoke X" | **NOW**: invoke X immediately, do not wait for confirmation |
| "It is recommended to read routing.md first" | **REQUIRED**: you must fully read routing.md before entering any submodule |
| "If a tool is missing you can bootstrap" | **NO EXCUSE**: when a tool is missing, the only correct action is to invoke bootstrap; manual install guessing is forbidden |
| "Remember to update the field-journal" | **CHECKLIST ENFORCED**: after the task completes, check off the Checklist item by item; you may not claim the task is finished until it is complete |
| "You should..." | **MUST** / **MUST NOT** |

**Key patterns**:
```
MUST — violation = task failure
MUST NOT — violation = security violation
SHOULD — not doing it requires stating a reason
MAY — truly optional
```

---

## Technique 3: Excuse Rebuttal Table

**This is the most critical patch in this project.** When an AI Agent hits resistance, it automatically generates "reasonable excuses" to skip a step. List common excuses in advance and rebut each one:

| Common Agent excuse | Rebuttal (enforcement) |
|---|---|
| "This step can be omitted, I'll just directly..." | **Skipping is forbidden.** Every step in the behavior chain is required. If you think it can be skipped, first output the specific reason and let the user decide. |
| "In my judgment, this is not required" | **Your judgment does not apply here.** List the specific criteria you used to judge, and explain why those criteria allow skipping an explicitly written step. |
| "The user probably doesn't need this" | **Never decide for the user.** Present all options to the user, mark the recommendation but do not hide the alternatives. |
| "I already know how to do this, I don't need to read X" | **Read X before acting.** Even if you are certain you know how, X may contain constraints specific to this task. Reading it takes only 2 seconds. |
| "To save time, I can skip in parallel..." | **The correct way to save time is to run independent steps in parallel, not to skip steps.** If two steps do not depend on each other, do them in parallel; if they depend, do them in order. |
| "I've used this tool before, I know the path" | **Guessing paths is forbidden.** You must obtain the actual path from the tool-index; install locations differ across machines. |
| "The task is basically complete, I don't need the checklist" | **The only definition of task completion is that the entire Checklist is checked off.** A task with an unfinished Checklist is not complete. |
| "I couldn't find the tool-index, so I'll just guess the path" | **A missing file is 100x safer than a wrong guessed path.** When the tool-index is missing, first run refresh-tool-index.ps1 to generate it. |
| "The user didn't explicitly ask for a report, so I won't write one" | **A report is the default behavior, not optional.** After a security task completes you must generate a report, unless the user explicitly says "no report". |
| "This is too simple to need a journal entry" | **Even simple tasks have pitfall value.** At minimum record: target type + what was used + whether there were surprises; a single line is fine. |

**How to use**: place this table near the end of RULES.md or another instruction file (high-attention region). The Agent sees the rebuttal before it makes an excuse.

---

## Technique 4: The Five Skill-Engineering Patterns (Anthropic 2026 official)

| Pattern | Applicable scenario | Key technique |
|---|---|---|
| **Linear Flow** | Processes with clear steps (deploy, install) | Provide safe defaults, use negative instructions ("MUST NOT use --force") |
| **Decision Tree** | Platform navigation, fault diagnosis | Tree navigation + `references/` progressive loading |
| **Iterative Loop** | TDD, review-fix loops | Hard rules up front + **excuse rebuttal table** to block shortcuts |
| **Baton Loop** | Multi-session, multi-Agent collaboration | Externalize state to `next-prompt.md` (MUST write it before exit) |
| **Multi-Phase + Checkpoints** | Multi-day complex workflows | Orchestrator "parent" skill + human Go/No-Go checkpoints, annotate time cost |

**Correspondence in this project**:
- Complete behavior chain = Linear Flow (15 steps executed in order)
- Routing matrix = Decision Tree (three-dimension matching)
- Checklist = Multi-Phase Checkpoint (each step must be checked off)
- Field Journal = Baton Loop (cross-session state externalization)

---

## Technique 5: In-Band Enforced Validation (Steering Hooks idea)

Do not rely on AI "self-discipline"; instead embed self-validation instructions in the Prompt:

```
Before claiming "task complete", you MUST first self-check:
1. Did I skip any step in the behavior chain? Which one?
2. Did I guess any tool path? If so, what is the actual tool-index path?
3. Is the entire Checklist checked off? For the unchecked ones, why?
4. If the answer to any of the above is "yes"/"unchecked", then the task is not complete;
   return to the corresponding step and re-execute, do not declare completion.
```

This approach makes the Agent self-audit before saying "done", which is more immediate than external validation.

---

## Technique 6: Opaque Identifiers (Code Words) — for API/tool parameters

Microsoft 2026 research found that semantic parameter names trigger the model's tendency to "help optimize".

```
WRONG: { "query": "...", "top": 9 }        → 68.4% parameter compliance rate
CORRECT: { "query": "...", "code": "alpha" } → 100% parameter compliance rate
```

**Application scenarios**:
- When precise configuration must be passed in a bootstrap script, use short codes instead of semantic parameters
- For parameters in tool calls that require strong guarantees, use a code-word mapping

---

## Technique 7: Dual-AI Review Loop (Dual Validation)

```
AI A (executor) produces output
  ↓
AI B (reviewer) checks it against the rules
  ↓ pass
output to the user
  ↓ fail
return to AI A for correction, with specific violation citations
```

**Application in this project**:
- Embed a "self-review" step in RULES.md: before outputting the report, the Agent uses its own capability to check against the Checklist item by item
- If it finds an incomplete item, it returns to the corresponding step and completes it

---

## Technique 8: Context-Window Layout Optimization

LLM attention distribution (high → low):
```
[first 10%] ████████████ ← highest attention, place "act immediately" instructions
[middle 80%] ████░░░░░░░░ ← decreasing attention, place reference material
[last 10%]  ████████████ ← attention rebound, place "do not skip" and the Checklist
```

**Concrete application**:
1. **First 10%**: immediate-execution instructions + trigger keywords
2. **Middle 80%**: detailed workflow, reference links, tool list
3. **Last 10%**: excuse rebuttal table + hard Checklist + forbidden-behavior list

---

## Practical Prompt Templates

### Template A: Forced-Start Template (embed at the beginning of RULES.md)

```markdown
## CRITICAL: after reading this you must immediately execute the following (do not just acknowledge, actually execute)

1. **NOW**: detect the directory this file is in → that is the package root
2. **NOW**: if this is the first use, write these rules into the global config (see the global-injection section)
3. **NEXT**: read `skills/SKILL.md` → `skills/routing.md` → determine which sub-skill to enter
4. **NEXT**: read `skills/tool-index.md` to confirm tool status
5. **THEN**: begin executing the actual task, do not remain in a "read" state

If you only reply "read", "done", "I understand" without actually executing the above steps,
you have failed. What the user needs is the tools installed, the code analyzed, the vulnerabilities verified,
not an acknowledgment message.
```

### Template B: Submodule-Entry Template (embed at the beginning of each SKILL.md)

```markdown
## ACTION REQUIRED (execute immediately after reading, do not wait)

After reading this file:
1. Confirm you understand the applicable scenarios of this skill
2. Check whether this machine has the required tools (read `../tool-index.md`)
3. If a tool is missing → invoke bootstrap
4. If the tools are present → begin the first step of the workflow
5. If you are unsure → list the specific questions, do not stay silent
```

### Template C: Task-Completion Self-Check Template (embed at the end of each SKILL.md)

```markdown
## Task-completion self-check (MUST confirm each item before claiming completion)

□ I actually executed every step in the behavior chain (no skipping)
□ I did not guess any tool path (all came from tool-index.md)
□ I produced reproducible commands/scripts/reports (not just described the steps)
□ I updated the field-journal (if there were pitfalls)
□ I ran the post-completion Checklist (report + charts + experience write-back)
```

---

## Forbidden Behaviors (supplement from the Agent-obedience angle)

- Forbidden to reply only "understood, please tell me the specific task" after reading RULES.md
  → Correct approach: perform global injection → read SKILL.md → read routing.md → determine the entry point
- Forbidden to say "steps 1-4 are complete" when you actually only read through them once
  → Correct approach: distinguish "document read" from "operation executed"; the latter produces actual side effects
- Forbidden to say "task complete" without having run the Checklist
  → The Checklist is the only definition of task completion
- Forbidden to substitute "from experience" for reading the tool-index
  → Paths differ across machines; reading the tool-index is the only way to locate them

---

## Summary: If You Can Only Change One Thing

**Add an "act immediately" instruction at the very top of RULES.md**, using bold, CRITICAL, NOW and other strong directive words.

This is the highest ROI change. Most Agents' "not working" behavior comes from automatically entering "wait for user instruction" mode after reading a file. A forced "act immediately" instruction can break this mode.

If you can change a second thing: **add the excuse rebuttal table**. The Agent finds an excuse to stop at the first bit of resistance; block these excuses in advance.
