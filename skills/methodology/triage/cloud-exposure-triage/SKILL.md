---
name: cloud-exposure-triage
description: Methodology for turning exposed cloud, identity, storage, and backend-service clues into a structured capability assessment and manual validation plan. Use when recon reveals hosted data services, identity platforms, storage endpoints, or public backend configuration.
sources: local_tooling_corpus, field_recon
report_count: 0
---

# Cloud Exposure Triage

Use this skill when the target leaks backend-service metadata, storage references, auth configuration, or public service credentials.

## Goal

Convert scattered cloud clues into a capability map:
- what service exists
- what trust boundary it serves
- what level of access is implied
- which nearby control plane or data plane deserves manual attention

## Normalize discoveries into capability buckets

1. Identity
- sign-in providers
- tenant or pool identifiers
- client IDs
- redirect and callback configuration
- onboarding and self-registration hints

2. Data
- table, collection, index, or dataset names
- query endpoints
- schema hints
- region markers
- export or sync workflows

3. Storage
- bucket or container names
- upload paths
- attachment conventions
- CDN and origin relationships
- object naming rules

4. Control plane
- admin panels
- support consoles
- integration dashboards
- job runners
- webhook management
- CI or deployment interfaces

5. Messaging and automation
- queue names
- mail or SMS providers
- webhook endpoints
- event processing
- retry workers

## Triage questions

For each discovery, answer:
- does it prove a data plane, a control plane, or both
- does it reveal actor classes such as public, user, staff, or service
- does it expose object naming that can be followed elsewhere
- does it imply region-specific or environment-specific endpoints
- does it sit near import, sync, export, preview, or background processing

## Credential-class reasoning

Not all exposed credentials imply the same risk.

Classify every token, key, or config fragment by what it appears to represent:
- public client configuration
- user-context artifact
- automation or server-to-server artifact
- support or admin artifact

Then ask:
- what trust assumptions would the application make about this class
- what metadata or capability can be confirmed without over-claiming
- which adjacent workflows might rely on the same trust boundary

## Service-to-workflow mapping

Map each exposed service back to product behavior:
- identity service -> signup, invitation, recovery, federation, session lifecycle
- data service -> object ownership, row or document segmentation, tenant handling
- storage service -> uploads, previews, exports, attachments, imports
- queue or worker -> async jobs, delayed side effects, retries, race windows
- admin tooling -> support actions, moderation, billing, role changes, integrations

## High-value manual follow-up

Translate service clues into workflow tests:
- compare public client behavior to backend-facing helpers
- compare read paths to write or export paths
- compare primary object actions to attachment, preview, import, or sync actions
- compare user paths to support or admin-adjacent paths leaked in config or docs
- compare one environment or region to another when identifiers suggest drift

## Evidence discipline

Save compact evidence for each service clue:
- exact artifact where it was found
- inferred service role
- affected workflow families
- confidence score
- next manual test

This keeps cloud findings tied to product impact instead of isolated token trivia.
