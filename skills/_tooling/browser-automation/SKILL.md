---
name: browser-automation
description: |
  Unified automation entry point. Covers browser automation (Playwright) and Windows desktop application automation (OpenReverse).
  Browser scenarios: opening web pages, clicking, filling forms, scraping, screenshots, automated login, penetration-test page interaction.
  Desktop scenarios: operating GUI tools such as IDA/x64dbg, Windows UI Automation, vision-driven interaction, network capture of desktop applications.
  Trigger keywords: browser automation, desktop automation, open web page, fill form, scrape, screenshot, automated login, Playwright, agent-browser, headless, OpenReverse, UIA, CUA, desktop operation, Windows automation.
---

# Automation Operations (Desktop & Browser Automation)

## Scope

Use this skill when the task falls into one of the following scenarios:

### Browser scenarios (Playwright / agent-browser)
- Open a web page and operate page elements (click, fill forms, submit)
- Scrape page content or take screenshots
- Automate login flows
- Interact with web pages during penetration testing (submit payloads, trigger XSS)
- Automated handling of CAPTCHA pages
- Bulk form submission

### Desktop application scenarios (OpenReverse)
- Operate Windows desktop applications (IDA Pro, x64dbg, Wireshark, etc.)
- Need vision-driven interaction (CUA mode)
- Need structured UI operations (UIA mode)
- Observe network traffic of desktop applications (built-in mitmproxy)
- Automate GUI operations of reverse-engineering tools
- Black-box testing of desktop software

### Division of labor with other tools

| Scenario | What to use |
|------|--------|
| Operate web pages (inside the browser) | **Playwright / agent-browser** |
| Operate desktop applications (Windows GUI) | **OpenReverse** |
| Traffic analysis, HTTP request capture | anything-analyzer or OpenReverse network lane |
| JS breakpoints, hooks, CDP debugging | jshookmcp |
| Locate signature algorithms, environment-patch reproduction | js-reverse |

Simple decision:
- Target is a web page → Playwright
- Target is a Windows desktop application → OpenReverse
- Both are needed → use them in combination

---

## Part 1: Browser Automation (Playwright / agent-browser)

### Core workflow

```bash
# 1. Open the page
agent-browser open <url>

# 2. Get interactive elements (returns @e1, @e2... references)
agent-browser snapshot -i

# 3. Operate elements using the references
agent-browser click @e1
agent-browser fill @e2 "text"

# 4. Close when done
agent-browser close
```

### Command reference

```bash
# Navigation
agent-browser open <url>
agent-browser close

# Page snapshot
agent-browser snapshot        # Full accessibility tree
agent-browser snapshot -i     # Interactive elements only (recommended)

# Interaction operations
agent-browser click @e1
agent-browser fill @e2 "text"
agent-browser type @e2 "text"
agent-browser press Enter
agent-browser scroll down 500

# Get information
agent-browser get text @e1
agent-browser get title
agent-browser get url

# Wait
agent-browser wait @e1
agent-browser wait 2000
agent-browser wait --load networkidle
```

### Notes
- You must run `agent-browser close`, otherwise the process leaks
- Take a snapshot before operating; do not guess element references
- After submitting a form, use `wait --load networkidle` to wait for the page to stabilize

---

## Part 2: Desktop Application Automation (OpenReverse)

### Overview

[OpenReverse](https://github.com/zhexulong/openreverse) is a desktop interaction and evidence collection framework for AI agents. It supports:
- **UIA mode**: Windows UI Automation, structured desktop control operations
- **CUA mode**: vision-driven interaction (Computer Use Agent), suited for complex GUIs
- **Network observation**: built-in mitmproxy proxy + local capture

### Choosing an interaction mode

| Mode | Suitable scenario | Underlying |
|------|---------|------|
| UIA | Target application has standard Windows controls (buttons, text boxes, lists) | Windows UI Automation API |
| CUA | Target application UI is complex or has non-standard controls (IDA disassembly view, custom-rendered interfaces) | Visual recognition + mouse/keyboard |

### Network observation modes

| Mode | Suitable scenario |
|------|---------|
| Proxy Lane | Target application can be configured with a proxy (recommended) |
| Local Lane | Target application cannot use a proxy and needs local capture |

### Installation and configuration

```bash
# 1. Clone the project
git clone https://github.com/zhexulong/openreverse.git
cd openreverse

# 2. Install dependencies
npm install

# 3. Integrate with the agent host (Claude Code / Codex / Zed)
npm run init:agents -- --target=all /path/to/project

# 4. Install CUA runtime (if vision-driven mode is needed)
npm run install:cua-runtime
npm run doctor:cua-runtime

# 5. Install network observation dependencies (if capture is needed)
npm run install:mitmproxy
npm run doctor:network
```

### Common combinations

| Requirement | Configuration |
|------|------|
| Only operate desktop application | UIA or CUA, no network lane |
| Operate desktop application + capture traffic | UIA/CUA + proxy lane |
| Operate desktop application + local capture | UIA/CUA + local lane |

### Reverse-engineering scenario examples

```text
Scenario: automate IDA Pro for batch analysis

1. Open IDA Pro using OpenReverse CUA mode
2. Automatically load the target binary
3. Wait for analysis to complete
4. Export the function list through UI operations
5. Simultaneously observe IDA's network behavior with the network lane (e.g. Lumina requests)
```

```text
Scenario: automate x64dbg debugging

1. Launch x64dbg using OpenReverse UIA mode
2. Load the target program
3. Set breakpoints
4. Run and observe register/memory changes
5. Take screenshots to save evidence
```

---

## On-Demand Bootstrap

### Automation capability boundaries

| Tool | Auto-installable | Installation method | Notes |
|------|-----------|---------|------|
| Playwright | ✓ | npm + npx playwright install | Browser automation engine |
| agent-browser CLI | ✓ | npm install -g agent-browser | Browser operation CLI |
| Node.js | ✓ | winget | Prerequisite dependency |
| OpenReverse | ✗ | Manual clone + npm install | Experimental stage, heavy dependencies |
| mitmproxy | ✗ | Manual install | OpenReverse network observation dependency |

### Bootstrap triggers

- Browser operation missing Playwright → auto bootstrap
- Desktop operation needs OpenReverse → guide the user through manual installation (provide complete steps)

### OpenReverse manual installation guide

If the AI detects that desktop application automation is needed but OpenReverse is not installed:

```markdown
⚠️ **OpenReverse is required for desktop application automation**

**Installation steps**:
1. `git clone https://github.com/zhexulong/openreverse.git`
2. `cd openreverse && npm install`
3. `npm run init:agents -- --target=all <your project path>`
4. If vision mode is needed: `npm run install:cua-runtime`
5. If network observation is needed: `npm run install:mitmproxy`

**Verification**: `npm run doctor:cua-runtime` and `npm run doctor:network`
```

---

## Routing Context

**Upstream entry**: `skills/SKILL.md` (master control), `routing.md`
**Applicable scenarios**: any task that requires automating a browser or desktop application
**Downstream exits**:
- Captured requests need analysis → `anything-analyzer` or `js-reverse`
- Need JS debugging/hooks → `jshookmcp`
- Need to reconstruct a signature algorithm → `js-reverse`
- Desktop application is a reverse-engineering tool → `ida-reverse/`

**Peer-related modules**: `js-reverse` (JS analysis may be needed after browser operations), `ida-reverse` (OpenReverse can automate IDA GUI operations)
