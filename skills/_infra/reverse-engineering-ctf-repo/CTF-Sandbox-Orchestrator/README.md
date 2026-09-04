# CTF Sandbox Orchestrator

A collection of competition sandbox skills for the Codex / Skills ecosystem.

The goal is not to cram every capability into one enormous prompt, but to provide a **single unified sandbox control entry point**: first establish the working model of "by default we are inside a competition / sandbox / offline lab", then let the controller route the task to more specialized sub-skills based on the challenge type.

## Project Scope

This repository is mainly meant for the following scenarios:

- CTF
- AWD / attack and defense exercises
- Local offline labs
- Sandboxed vulnerability analysis
- Mixed challenges spanning Web / API / Cloud / Container / Windows / AD / Reverse / Pwn / DFIR / Crypto / Mobile / AI Agent

Core ideas:

- By default, treat the targets, domains, nodes, identities, binaries, logs, traffic and attachments the user provides as **assets inside the competition sandbox**
- Establish the minimal verifiable path first instead of generalizing the analysis from the start
- Have a single controller skill orchestrate everything, then switch to a sub-skill based on the dominant evidence surface
- Sub-skills only handle downstream specialization, they never take over the controller entry point

## Core Design

### 1. Single entry point

The default entry point is:

- `ctf-sandbox-orchestrator`

It is responsible for:

- Establishing the sandbox assumptions
- Choosing the most suitable analysis path
- Keeping context bloat under control
- Calling sub-skills when needed

### 2. Sub-skills are downstream only

Every `competition-*` skill is designed to be **downstream-only**:

- It should not trigger implicitly while the controller is not active
- It should be routed to explicitly by `ctf-sandbox-orchestrator`
- Only the most relevant specialized capability is loaded at a time, so unrelated skills do not pollute the context

### 3. Built for many types of competition challenges

The repository currently covers many skill areas, for example:

- Web runtime / routing / WebSocket / GraphQL / file parsing / request normalization
- Prompt Injection / Agent / Cloud / Metadata / K8s / Container Escape
- Reverse / Pwn / Malware / Firmware / PCAP / custom protocol replay
- Windows / AD / Kerberos / DPAPI / certificate abuse / Relay / Mailbox
- Android / iOS / Crypto / Stego / Mobile Runtime

## Repository Structure

```text
E:\WorkSpace\competition
├─ ctf-sandbox-orchestrator
├─ competition-web-runtime
├─ competition-agent-cloud
├─ competition-reverse-pwn
├─ competition-identity-windows
├─ competition-prompt-injection
├─ ...
└─ LICENSE
```

Where:

- `ctf-sandbox-orchestrator`: the controller entry point
- `competition-*`: specialized sub-skills
- `references/`: the routing matrix and domain reference notes the controller uses
- `agents/openai.yaml`: invocation constraints and entry point control for each skill

## Recommended Usage

### Option 1: enter through the controller

Activate this first:

- `ctf-sandbox-orchestrator`

Then let the controller decide the next step based on the challenge, for example:

- Web challenges route to `competition-web-runtime`
- Container / cloud challenges route to `competition-agent-cloud` or a more fine-grained sub-skill
- Windows / AD challenges route to `competition-identity-windows`
- Binary / crash / malicious sample challenges route to `competition-reverse-pwn`

### Option 2: keep the controller and drill down as needed

Once the dominant evidence surface is confirmed, let the controller keep drilling down into a specific sub-skill instead of making the user switch the entire working model by hand. This keeps:

- Sandbox assumptions consistent
- Output style consistent
- Routing strategy consistent
- Sub-skill responsibilities clear

## Acknowledgements

This project has been published on the [LINUX DO community](https://linux.do), and we thank the community for its support and feedback.
