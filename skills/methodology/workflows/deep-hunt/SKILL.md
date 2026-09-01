---
name: deep-hunt
description: "Manual workflow attack mode for authorized bug bounty and pentest work. Use as /deep-hunt <workflow> to attack one business workflow deeply instead of scanning endpoints shallowly."
sources: field_recon, hackerone_public
report_count: 50
---

# Deep Hunt Mode

Use this mode when the operator invokes `/deep-hunt <workflow>`.

Supported workflows:
- `recovery`
- `invite`
- `billing`
- `graphql`
- `import`
- `export`
- `roles`
- `support`
- `ai`
- `race`
- `oauth`
- `saml`
- `upload`
- `webhook`
- `generic`

If the workflow is not recognized, map it to the closest one and state the mapping.

## Output Contract

Produce:
- `workflow`
- `crown_jewel_alignment`
- `actors_needed`
- `object_families`
- `state_machine`
- `attack_matrix`
- `side_effects_to_chase`
- `first_10_manual_tests`
- `chain_candidates`
- `evidence_to_capture`
- `stop_conditions`

The output must be actionable enough that the operator can run it in Burp/Caido immediately.

## Universal Deep-Hunt Loop

For the chosen workflow, test six boundaries:

1. **Actor boundary**: owner, member, invited, removed, expired, unauthenticated, API token, mobile session, support-like role.
2. **Object boundary**: primary ID, child ID, attachment ID, export ID, job ID, GraphQL GID, signed URL, webhook ID, AI source ID.
3. **State boundary**: draft, pending, approved, rejected, archived, deleted, imported, shared, transferred, expired, refunded, downgraded.
4. **Shape boundary**: JSON/form/multipart, scalar/array/object, duplicate keys, null plus real value, method override, mobile headers, content negotiation.
5. **Time boundary**: stale token, queued worker, after access removal, after role downgrade, during retry, parallel sessions.
6. **Side-effect boundary**: export, notification, webhook, audit log, support view, AI citation, background job output, generated file.

Do not declare the workflow done until all six have at least one concrete test result.

## Workflow Playbooks

### recovery / invite

Prioritize:
- destination field confusion
- stale link redemption
- target identity switch between generation and redemption
- preview/accept/resend/cancel mismatch
- recovery side channels in notifications, logs, webhooks, support views

First tests:
- scalar email -> array/object
- duplicate destination keys
- generate token for attacker, switch target state, redeem stale token
- accept invite after revocation
- compare web/mobile/API redemption paths

### billing

Prioritize:
- archived prices
- coupon/credit/rate races
- refund without entitlement revocation
- webhook replay/type confusion
- seat count and plan downgrade edges

First tests:
- finalize after cancellation
- apply discount after invoice finalization
- refund while consuming entitlement
- parallel redemption of same value
- stale idempotency key reuse

### graphql

Prioritize:
- object-family authorization mismatch
- helper mutation drift
- mixed-tenant nested IDs
- alias/batch partial leaks
- read/mutate mismatch

First tests:
- enumerate IDs/GIDs by family
- pair attacker parent with victim child
- pair victim parent with attacker child
- run read, preview, export, mutate, delete for same object family
- batch allowed and forbidden objects together

### import / upload

Prioritize:
- parser and archive trust
- symlink/hardlink/duplicate-name handling
- import from URL / redirect / local path confusion
- metadata and filename sinks
- imported object ACL drift

First tests:
- symlink archive into upload/import lane
- duplicate filenames and nested archives
- source URL redirect to internal-like destination
- payloads in metadata, CSV formulas, markdown, diagrams
- import private object reference into attacker workspace

### export

Prioritize:
- stale authorization in workers
- child-object direct access
- signed URL drift
- export requested by one actor and downloaded by another
- import/export ACL laundering

First tests:
- request export, remove access, download when job completes
- direct child ID download
- signed URL reuse after role downgrade
- export victim object via attacker-controlled parent/reference
- compare CSV/PDF/ZIP variants

### roles / support

Prioritize:
- read-only role write side effects
- helper object ownership
- support/operator rendering sinks
- API key, webhook, queue, alert, saved-search creation
- support-visible lower-privileged data

First tests:
- create helper object as observer/support role
- configure export/webhook/notification without read permission
- grant/assign through helper object
- inject marker into field rendered in support/admin context
- compare UI-hidden actions with API-available actions

### ai

Prioritize:
- cross-tenant source/citation leakage
- vector store and uploaded file IDOR
- saved prompt/tool config exposure
- action/tool misbinding
- support transcript leakage

First tests:
- swap thread/file/vector store/source IDs across tenants
- ask for citations and debug summaries
- duplicate assistant after access changes
- move/import/re-index documents and retest retrieval
- inspect support/admin views of AI conversations

### race

Prioritize:
- check-then-act gaps
- duplicate value issuance
- stale worker authorization
- retry/replay and idempotency mistakes
- parallel state transitions

First tests:
- parallel requests from two sessions
- approve/delete, invite/revoke, pay/cancel, refund/consume
- replay webhook and idempotency keys
- send browser and API request simultaneously
- observe delayed workers and retry queues

## Completion Standard

End with:
- the strongest current primitive
- the best next pivot
- what proof is missing for reportability
- whether `/attack-chain` should be invoked now

