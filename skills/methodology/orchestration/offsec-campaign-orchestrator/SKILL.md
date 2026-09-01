---
name: offsec-campaign-orchestrator
description: Master workflow for offensive campaigns. Use when starting a target, scoping a hunt, or deciding how to split work across reconnaissance, manual testing, chain building, and reporting.
sources: field_recon, hackerone_public
report_count: 50
---

# Offsec Campaign Orchestrator

Use this skill when the job is bigger than one hypothesis.

## Purpose

Turn the agent into a campaign operator:
- select the crown jewel before choosing bug classes
- choose surfaces before bug classes
- create and maintain a target dossier
- import real traffic into a request map
- drive deep manual workflow modes
- split work into specialist tracks
- score findings for chainability, not only standalone severity
- close the loop with evidence and report-ready outcomes

## Start sequence

1. Run `/crown-jewel <target>` mentally or explicitly to choose the primary harm objective.
2. Create or update a dossier with `/target-dossier <target>`.
3. If the user has HAR, Burp, Caido, browser export, or raw HTTP requests, run `/request-import <path>` and merge the map into the dossier.
4. Create or update a campaign plan from `.offsec/templates/campaign-plan.md`.
5. Rank surfaces:
   - auth / recovery
   - invite / onboarding
   - role / ownership
   - imports / parsers
   - exports / attachments
   - GraphQL helper objects
   - AI / RAG objects
   - admin / support / control plane
   - public artifacts / client runtime / source maps
   - cloud identity / storage / backend services
   - non-HTTP infra and management surfaces
6. Choose one of three modes:
   - crown-jewel route planning mode
   - narrow target, deep manual mode
   - broad target, delegated campaign mode
7. For narrow target mode, invoke `/deep-hunt <workflow>` for the highest-value workflow.
8. When any primitive appears, invoke `/attack-chain <primitive>` before reporting.

Before choosing hypotheses, load the matching doctrine skill when applicable:
- `artifact-pivot-intelligence` for archived content, public API material, support docs, third-party metadata, and shadow-documentation pivots
- `client-runtime-intelligence` for JavaScript, source maps, mobile assets, route extraction, and hidden-parameter discovery
- `cloud-exposure-triage` for leaked backend configuration, storage, identity, and service metadata
- `protocol-surface-triage` for network services, TLS naming, and exposed management planes
- `continuous-surface-monitoring` for long-running targets, deltas, and retest queues

## Delegation map

If delegate_task is available, prefer these specialist subtasks:
- `surface mapper`: enumerate routes, objects, auth models, integrations
- `crown-jewel analyst`: define primary/secondary impact objectives and kill signals
- `request-map analyst`: convert HAR/Burp traffic into endpoint clusters and workflow candidates
- `artifact mapper`: mine public artifacts into second-order pivots
- `runtime mapper`: extract endpoint, object, and parameter intelligence from client assets
- `cloud triager`: normalize service clues into identity, data, storage, and control-plane hypotheses
- `infra triager`: classify exposed services by operating role and weak-boundary potential
- `delta hunter`: compare new assets and artifact changes against prior campaign state
- `business-logic hunter`: actor/state/path mismatch and workflow abuse
- `graphql-api hunter`: object-family abuse, helper mutation drift, secondary objects
- `import-parser hunter`: uploads, archive handling, renderers, ingestion chains
- `chain builder`: join weak primitives into high-impact paths
- `report synthesizer`: convert evidence into clean report structure

Each subagent brief must include:
- exact target scope
- current dossier summary
- one success condition
- one stop condition

## Default success criteria

At the end of a cycle, produce at least one:
- crown-jewel objective update
- request-map update
- updated hypothesis tree
- updated dossier
- validated exploit path
- exploit-chain card
- subagent result summary

If nothing changed in the dossier, the cycle was too vague.

## P0 Attack Modes

These are first-class slash-command modes:

- `/crown-jewel <target>`: chooses the highest-impact objective and surfaces.
- `/target-dossier <target>`: creates or updates persistent campaign state.
- `/request-import <path>`: converts HAR/Burp/raw HTTP traffic into an offensive request map.
- `/deep-hunt <workflow>`: attacks one workflow through actor/object/state/shape/time/side-effect boundaries.
- `/attack-chain <primitive>`: turns a primitive into a visible chain card with next pivots.

Use these modes together. A strong cycle looks like:

```text
/crown-jewel target.com
/target-dossier target.com
/request-import traffic.har
/deep-hunt billing
/attack-chain "refund accepted after entitlement remains active"
```
