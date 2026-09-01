---
name: subagent-hunt-orchestration
description: How to split offensive campaigns across specialist subagents without duplicating work. Use when a target is large enough that one linear agent loop wastes time.
sources: field_recon
report_count: 50
---

# Subagent Hunt Orchestration

Use this skill whenever the target is broad, the workflow is deep, or the current hypothesis tree has multiple live branches.

## Specialist roster

Default subagents:
- surface mapper
- business-logic hunter
- graphql-api hunter
- import-parser hunter
- chain builder
- report synthesizer

## Brief format

Every subagent task should include:
- target scope
- current dossier summary
- one surface family
- one success condition
- one stop condition

Example:
- Surface mapper: "Enumerate object families, role model, GraphQL helper objects, and export endpoints for target X. Stop when the dossier can support manual state testing."
- Import/parser hunter: "Test upload/import/render paths for parser confusion, symlink/archive extraction, and secondary-object leakage. Stop on one validated primitive or three disproven branches."

## Deconfliction

Do not send two subagents after the same surface with the same goal.

Use this split:
- mapper finds
- manual hunter reasons
- API hunter compares transports
- parser hunter stresses ingestion
- chain builder composes
- report synthesizer writes

## Merge discipline

After each subagent returns:
- update dossier
- add disproven paths
- add chain candidates
- decide whether to deepen, pivot, or report

If subagent output does not change campaign state, the brief was too vague.
