# Community Evolution: Contributing Experience Back to the Main Repository

## How It Works

Every time you finish a project and generate a field-journal entry, the AI asks:

```
✅ Experience recorded in field-journal/

📤 Contribute this experience to the community main repository?
- The data has been anonymized per the template requirements (domains/IPs/tokens/PII replaced)
- Only new files under field-journal/ will be submitted
- Your private files such as tool-index, scope and findings will not be submitted
- Once contributed, other users can reuse your experience

Reply "yes" to submit, "no" to skip.
```

## Contribution Workflow

```text
1. The AI generates the field-journal entry (already anonymized)
2. The AI asks the user whether to contribute
3. The user agrees → the AI performs these steps:
   a. Check that anonymization is complete (double-check for real domains/IPs/tokens)
   b. Check for duplicates against existing entries in the main repository (read only _index.md, ~200 tokens)
   c. If it is not a duplicate → open a PR against the main repository
   d. PR title format: [field-journal] YYYY-MM-DD scenario type - keywords
4. GitHub Actions runs automated review:
   - ✓ Only field-journal/*.md was modified
   - ✓ No prompt injection indicators
   - ✓ No unredacted API key/token
   - ✓ No executable code
   - ✓ File size < 50KB
5. Review passes → auto-merge (no manual action needed from repository maintainers)
6. Review fails → an automated comment explains why, and the PR stays open awaiting fixes
```

### Security Guarantees

| Threat | Mitigation |
|------|------|
| Modifying non-journal files | Actions checks the changed files against an allow-list |
| Prompt injection | Regex detection for indicators such as "ignore previous"/"you are now" |
| Malicious code in disguise | Detection of `#!/`, `import`, `exec(`, `eval(` and similar |
| Unredacted token | Regex detection of AWS key/npm token/GitHub token patterns |
| Junk data | 50KB per-file cap |
| Mass junk PRs | GitHub's built-in rate limiting plus optional CODEOWNERS review |

## Technical Implementation

### Method 1: GitHub CLI (recommended)

```bash
# 1. Fork the main repository (if you have not forked it yet)
gh repo fork &lt;your-github-username&gt;/&lt;repo-name&gt; --clone=false

# 2. Create a contribution branch locally
git checkout -b contribute/journal-YYYY-MM-DD-keyword

# 3. Add only the field-journal files
git add skills/field-journal/YYYY-MM-DD_*.md
git add skills/field-journal/_index.md

# 4. Commit
git commit -m "[field-journal] scenario type: keyword summary"

# 5. Push to the fork
git push origin contribute/journal-YYYY-MM-DD-keyword

# 6. Open the PR
gh pr create --repo &lt;your-github-username&gt;/&lt;repo-name&gt; \
  --title "[field-journal] YYYY-MM-DD scenario type - keywords" \
  --body "## Contribution\n- Scenario: xxx\n- Keywords: xxx\n- Anonymization confirmed: ✓\n\n## Data Safety Statement\nThis entry has been anonymized per the template requirements and contains no real target information."
```

### Method 2: Direct push (if the user has write access to the main repository)

```bash
git checkout -b contribute/journal-YYYY-MM-DD-keyword
git add skills/field-journal/YYYY-MM-DD_*.md
git add skills/field-journal/_index.md
git commit -m "[field-journal] scenario type: keyword summary"
git push origin contribute/journal-YYYY-MM-DD-keyword
gh pr create --repo &lt;your-github-username&gt;/&lt;repo-name&gt; \
  --title "[field-journal] YYYY-MM-DD scenario type - keywords" \
  --body "Anonymization confirmed: ✓"
```

## Deduplication Rules (Low Token Cost)

Before submitting, the AI **only needs to read a single file, `_index.md`**, to deduplicate; it does not need the full content of every journal entry.

### Deduplication Workflow

```text
1. Read the main repository's field-journal/_index.md (usually only a few dozen lines)
2. Extract this entry's scenario category and keyword list
3. Search _index.md for existing entries under the same scenario category
4. Keyword matching:
   - 3 or more overlapping keywords → treat as a duplicate, do not submit
   - 1-2 overlapping keywords → likely a variant, submitting is fine
   - No overlap → a brand new scenario, submit directly
```

### Why This Is Good Enough

- The `_index.md` format is fixed: `- [date] short name - keywords: k1, k2, k3`
- Each entry is a single line, so 100 experiences is only 100 lines
- The AI only needs string matching, it does not need to understand the full content
- Token cost: reading _index.md ≈ 200-500 tokens (vs. reading every journal ≈ 10000+ tokens)

### If _index.md Is Unavailable

If the main repository's _index.md cannot be fetched (network problems, etc.), submit anyway and let the main repository maintainers deduplicate manually.

## Files Allowed in a Submission

**Allow-list** (only these files may appear in a PR):
- `skills/field-journal/YYYY-MM-DD_*.md` (new experience entries)
- `skills/field-journal/_index.md` (index update)

**Deny-list** (must never appear in a PR):
- `tool-index.*` (contains local paths from the user's machine)
- `pentest-tools/templates/scope.md` (contains target information)
- `pentest-tools/templates/findings.md` (contains vulnerability details)
- `pentest-tools/templates/progress.md` (contains operational records)
- `.claude/` (user configuration)
- `.kiro/` (user configuration)
- Any `.env`, `*.key` or `*.pem` file

## Second Anonymization Check

Before submitting, the AI must scan the files to be submitted and confirm they contain no:

- [ ] Real domains (anything other than `example.com`/`target.example.com`)
- [ ] Real IPs (anything other than `10.x.x.x`/`192.168.x.x`)
- [ ] Raw tokens/cookies/API keys
- [ ] Raw phone numbers/emails/usernames
- [ ] Company or product names (if the target came from an SRC program)

If any item is found unredacted, stop the submission and prompt the user to fix it.

## Value to the User

- The experience you contribute helps other users avoid the same pitfalls
- The richer the main repository's field-journal, the smarter every user's AI becomes
- Your contribution is preserved in _index.md (anonymously, only the scenario and keywords)
