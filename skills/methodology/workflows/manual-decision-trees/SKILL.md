---
name: manual-decision-trees
description: Manual testing trees for difficult bug bounty and pentest work. Use after mapping a workflow and before freeform poking so the agent systematically explores actor, state, transport, and secondary-object branches.
sources: hackerone_public, field_recon
report_count: 50
---

# Manual Decision Trees

## Core rule

Do not test one endpoint in isolation when the bug likely lives in the workflow.

For each high-value workflow, build four trees:
- actor tree
- state tree
- transport tree
- secondary-object tree

## Actor tree

For every object or action, test:
- unauthenticated
- low privilege
- sibling user
- elevated user
- owner/admin
- service/bot/background context

Question:
- who can read it?
- who can mutate it?
- who can trigger a side effect from it?

## State tree

Test the object in:
- draft
- pending
- approved
- archived
- deleted
- expired
- imported
- cloned
- restored

Question:
- which transition is validated only on the happy path?

## Transport tree

Test the same action through:
- UI flow
- REST
- GraphQL
- mobile client behavior
- background job or webhook
- import/export path

Question:
- where is policy weaker?

## Secondary-object tree

Pivot from main object to:
- attachment
- export
- preview
- quick action
- collaborator object
- certification/license/support object
- AI conversation/source/index
- audit log
- copy/clone/imported object

Question:
- is the nearby object protected like the primary one?

## Decision-tree trigger points

Use this skill immediately when you see:
- recovery or invite tokens
- GraphQL GIDs
- imports or archive extraction
- owner/admin helper panels
- markdown/rendering paths
- exports or attachments
- AI or RAG features
