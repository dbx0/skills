---
name: protocol-surface-triage
description: Service-first infrastructure triage methodology for turning discovered ports and banners into attack-surface meaning, weak-boundary hypotheses, and follow-up validation plans. Use when network services, certificates, reverse DNS, or exposed management surfaces appear.
sources: local_tooling_corpus, field_recon
report_count: 0
---

# Protocol Surface Triage

Use this skill when recon reaches beyond HTTP into infrastructure and management services.

## Principle

An open service is not just a port. It is an organizational clue.

The useful question is:
"What operating role does this service imply, and what trust boundary lives next to it?"

## Cluster by operating role

1. Identity and directory
- domain and directory services
- SSO-adjacent endpoints
- certificate enrollment
- federation helpers

2. Remote administration
- shell or command interfaces
- remote desktop or remote management
- hypervisor or appliance management
- control dashboards

3. File and data movement
- file sharing
- sync endpoints
- backup surfaces
- mail handling
- transfer interfaces

4. Data stores
- relational databases
- document stores
- caches
- search backends
- message brokers

5. Web and app management
- reverse proxies
- admin portals
- metrics and observability
- job runners
- orchestration surfaces

## What to correlate

For each service, collect:
- banner or product family
- TLS names and certificate relationships
- reverse-DNS naming
- host naming conventions
- whether the service appears internal, partner-facing, or internet-facing
- adjacent web interfaces on the same host
- repeated patterns across hosts or ranges

## Triage questions

Ask:
- does this service imply a Windows-centric or Linux-centric estate
- does it sit near an admin or support web surface
- does naming suggest environment drift such as dev, test, backup, or migration
- does the same hostname expose both user and operator planes
- does the certificate or banner reveal internal naming that connects to other assets

## Weak-boundary hypotheses

Prioritize hypotheses like:
- exposed management intended for a narrower audience
- duplicated trust planes on the same host
- backup, migration, or legacy nodes with looser controls
- internal naming leaked through TLS or service banners
- data services exposed without the same segmentation as the main app

## Follow-up plan

A good protocol triage pass should produce:
- an infrastructure role map
- a shortlist of environments that look weaker than production
- a list of management or data planes requiring manual review
- correlation notes linking network services back to application workflows or identities

## Specialized surfaces

When a triaged service turns out to be **mobile-carrier / telecom core** (3GPP GBA/BSF, SIP/IMS,
XCAP, Diameter, HSS/AAA, EPC) — hostnames like `*.bsf.*`, `*.sipgeo.*`, `*.ims.*`, SOAP with
`urn:3gpp:*` namespaces, or certs issued to `O=GSM Association` — switch to [[telecom-surface-triage]]
for element recognition, trust-boundary mapping, and the subscriber-data-safe proof method.
