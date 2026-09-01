---
name: sherlock
description: OSINT username search across 400+ social networks. Hunt down social media accounts by username.
version: 1.0.0
author: unmodeled-tyler
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [osint, security, username, social-media, reconnaissance]
    category: security
prerequisites:
  commands: [sherlock]
---

# Sherlock OSINT Username Search

Hunt down social media accounts by username across 400+ social networks using the [Sherlock Project](https://github.com/sherlock-project/sherlock).

## When to Use

- User asks to find accounts associated with a username
- User wants to check username availability across platforms
- User is conducting OSINT or reconnaissance research
- User asks "where is this username registered?" or similar

## Requirements

- Sherlock CLI installed: `pipx install sherlock-project` or `pip install sherlock-project`
- Alternatively: Docker available (`docker run -it --rm sherlock/sherlock`)
- Network access to query social platforms

## Procedure

### 1. Check if Sherlock is Installed

**Before doing anything else**, verify sherlock is available:

```bash
sherlock --version
```

If the command fails:
- Offer to install: `pipx install sherlock-project` (recommended) or `pip install sherlock-project`
- **Do NOT** try multiple installation methods — pick one and proceed
- If installation fails, inform the user and stop

### 2. Extract Username

**Extract the username directly from the user's message if clearly stated.**

Examples where you should **NOT** use clarify:
- "Find accounts for nasa" → username is `nasa`
- "Search for johndoe123" → username is `johndoe123`
- "Check if alice exists on social media" → username is `alice`
- "Look up user bob on social networks" → username is `bob`

**Only use clarify if:**
- Multiple potential usernames mentioned ("search for alice or bob")
- Ambiguous phrasing ("search for my username" without specifying)
- No username mentioned at all ("do an OSINT search")

When extracting, take the **exact** username as stated — preserve case, numbers, underscores, etc.

### 3. Build Command

**Default command** (use this unless user specifically requests otherwise):
```bash
sherlock --print-found --no-color "<username>" --timeout 90
```

**Optional flags** (only add if user explicitly requests):
- `--nsfw` — Include NSFW sites (only if user asks)
- `--tor` — Route through Tor (only if user asks for anonymity)

**Do NOT ask about options via clarify** — just run the default search. Users can request specific options if needed.

### 4. Execute Search

Run via the `terminal` tool. The command typically takes 30-120 seconds depending on network conditions and site count.

**Example terminal call:**
```json
{
  "command": "sherlock --print-found --no-color \"nasa\" --timeout 90",
  "timeout": 180
}
```

### 5. Report Results

Present found accounts in a clean format. The `--print-found` flag outputs only positive results, making output easy to parse.

---

## Notes

- Sherlock queries 400+ sites — some will timeout or block requests. This is normal.
- Results depend on public visibility of profiles; private accounts won't appear.
- Rate limiting varies by platform; `--timeout 90` helps but some sites may still fail.
- For production OSINT workflows, consider running via Docker for consistency: `docker run -it --rm sherlock/sherlock <username>`

---

## Example Usage

User: "Find social media accounts for elonmusk"

Assistant runs:
```bash
sherlock --print-found --no-color "elonmusk" --timeout 90
```

Returns found accounts across Twitter, GitHub, Instagram, etc.

---

## References

- [Sherlock Project GitHub](https://github.com/sherlock-project/sherlock)
- [Supported Sites List](https://github.com/sherlock-project/sherlock/blob/master/sherlock/resources/data.json)