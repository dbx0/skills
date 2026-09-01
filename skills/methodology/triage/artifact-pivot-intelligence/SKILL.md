---
name: artifact-pivot-intelligence
description: Public-artifact-first methodology for turning exposed client assets, archived content, public API material, support content, and metadata into high-signal attack-surface maps. Use when starting recon, when a target looks thin from the homepage, or when you need second-order pivots.
sources: local_tooling_corpus, field_recon
report_count: 0
---

# Artifact Pivot Intelligence

Use this skill when the visible application surface is too small to explain the real product.

## Core idea

Public artifacts are often better documentation than the app itself.

Treat every exposed artifact as one of three things:
- a map of hidden capabilities
- a leak of internal naming and trust boundaries
- a pivot into a second search space

## Artifact classes to prioritize

1. Client-side assets
- JavaScript bundles
- source maps
- static config files
- mobile web manifests
- embedded JSON state
- error pages with stack or route hints

2. Public operational artifacts
- API examples and public collections
- archived URLs and historical paths
- changelogs and release notes
- support-center articles
- onboarding docs and developer docs
- status pages and incident writeups

3. Third-party relationship artifacts
- tag-manager or analytics identifiers
- public webhook examples
- partner or marketplace listings
- callback URLs in docs
- job posts mentioning internal platforms
- login pages for adjacent admin tools

4. Cloud and infrastructure breadcrumbs
- storage object URLs
- CDN hostnames
- bucket-style naming
- tenant IDs and region markers
- auth-provider identifiers
- certificate SANs
- reverse-DNS naming

## Extraction goals

For every artifact, pull out:
- hosts and subdomains
- route templates
- hidden parameters
- object names and schemas
- environment names
- role names
- product modules
- auth providers
- storage names
- queue or background-job hints
- support/admin/control-plane references
- integration partner names

## Pivot graph

Turn each artifact into a graph instead of a flat note.

Artifact to surface:
- bundle -> routes, APIs, feature flags, object families
- source map -> original filenames, services, comments, TODOs, secret-like constants
- archived URL -> deprecated endpoints, backup flows, import/export paths
- public API example -> auth models, payload shape, helper objects, alternate transports
- support article -> exact workflow states, role assumptions, admin actions, fallback flows
- tag or analytics identifier -> related domains, sibling properties, reused deployment patterns
- storage URL -> region, provider, naming convention, upload paths, attachment logic

Surface to next pivot:
- object name -> GraphQL or REST enumeration
- role name -> authorization matrix
- feature flag -> hidden route discovery
- region marker -> regional endpoint discovery
- callback URL -> integration and webhook mapping
- queue/worker hint -> async workflow testing

## Second-order pivots

Do not stop at the first artifact.

Look for:
- the artifact that explains another artifact
- naming that links two product areas
- a route that implies a private helper API
- an object family that appears in UI, API, and docs under different names
- archived paths that still exist behind a new frontend
- support flows that describe edge cases the main app hides

## Confidence scoring

Score leads with four inputs:
- source quality
- recency
- repetition across unrelated sources
- pivot value

A small leak that unlocks a new search space outranks a large but generic endpoint list.

## Manual follow-up

Once an artifact yields a lead, move from scraping to reasoning.

Build:
- an actor matrix
- a state matrix
- a transport matrix
- a helper-object matrix

Ask:
- does this route exist in more than one transport
- does the documented flow imply a hidden fallback
- does the helper object inherit weaker checks than the primary object
- does the public example omit a state transition that still exists server-side

## Good work product

End with:
- a surface map grouped by artifact origin
- a list of second-order pivots
- a confidence-ranked queue of manual tests
- dossier notes that preserve naming, objects, roles, and inferred workflow states
