---
name: continuous-surface-monitoring
description: Continuous recon and campaign-memory methodology for tracking deltas in attack surface, deduplicating noisy signals, and turning change events into prioritized manual testing queues. Use during long hunts or repeated target coverage.
sources: local_tooling_corpus, field_recon
report_count: 0
---

# Continuous Surface Monitoring

Use this skill when the target is worth watching over time instead of probing once.

## Why it pays

Many high-value opportunities appear as changes:
- a new host goes live
- a client bundle gains a new module
- an archived route reappears
- a storage name changes
- a support flow is rewritten
- a certificate starts covering a new environment

Fresh change is often more valuable than a larger but stale corpus.

## Monitoring lanes

Track deltas in:
- live hosts and status changes
- certificate and SAN changes
- JavaScript bundle and source-map diffs
- public docs and support article changes
- changelog and release-note changes
- public API examples and collection changes
- historical URL resurfacing
- cloud-resource naming and attachment-path drift

## Dedup rules

Do not keep raw noise as your main output.

Deduplicate by:
- exact host or route
- normalized path template
- object family
- service family
- artifact origin
- environment marker

Then keep only what changed:
- new
- removed
- renamed
- behaviorally different

## Campaign memory model

Persist compact facts that help future turns:
- asset
- source
- first seen
- last seen
- confidence
- related workflow
- related object family
- why it matters

This lets the agent reason about trend and drift instead of repeatedly rediscovering the same lead.

## Turning deltas into tests

Every meaningful change should trigger one of four outcomes:
- ignore as low-signal
- append to dossier
- schedule a manual retest
- open a new hypothesis branch

High-priority deltas usually involve:
- new auth or onboarding routes
- new import/export or attachment functionality
- new admin or support modules
- new environment or region markers
- object-family growth in GraphQL or API schemas
- new background-job or webhook references

## Operational loop

1. Collect
2. Normalize
3. Deduplicate
4. Compare to prior state
5. Score for pivot value
6. Create manual test queue
7. Update dossier

## Good work product

End with:
- a delta report
- a ranked list of retest candidates
- a short note on why each change matters
- a clean dossier update that preserves only durable signal
