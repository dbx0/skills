---
name: telecom-surface-triage
description: Recognize and safely triage exposed mobile-carrier / telecom core infrastructure (3GPP GBA/BSF, SIP/IMS, XCAP/XDM, RCS, Diameter, GGSN/PGW, HSS/AAA) reachable over the internet. Use when recon surfaces hosts like *.bsf.*, *.sipgeo.*, *.ims.*, *.rcs.*, *.epc.*, SOAP endpoints with 3gpp namespaces, or any carrier-network naming — especially in bug bounty programs that scope "cellular network auth" or "sensitive network segments".
sources: field_recon (carrier engagement — unauth 3GPP GBA BSF)
report_count: 1
---

# Telecom Surface Triage

Carrier core network elements are increasingly fronted by ordinary web infra (nginx, Akamai, F5)
and given DNS names under the corporate domain. When one is exposed, generic web scanners see
"a 200 with some XML" and move on. This skill teaches you to recognize the element, understand the
trust boundary it violates, and prove the exposure **without touching subscriber data**.

## Why it matters
Telecom core auth elements hold or derive **subscriber key material**. An internet-reachable,
unauthenticated one is often a Critical / Special-Target finding ("cellular network auth bypass",
"access to sensitive network segments") — the highest payout tier in carrier bug bounty programs.

## Step 1 — Recognize the element from weak signals

Hostname patterns (search subs for these tokens):
`bsf, sipgeo, ims, imscore, rcs, xcap, xdm, naf, ggsn, pgw, sgw, mme, hss, aaa, diameter, dra,
epc, volte, vowifi, hlr, eir, scef, nef, sepp, pcrf, ocs, smsc, mmsc, ussd, ss7, sigtran, gtp`

Response / banner signals:
- **SOAP with a 3GPP namespace** → `urn:3gpp:gba:GBAService...` (GBA/BSF), `urn:3gpp:...:xcap`,
  Diameter AVPs, `application/vnd.3gpp.*` content types.
- **SIP** on 5060/5061 or in banners (`SIP/2.0`, `Via:`, `CSeq:`), IMS `P-Asserted-Identity`.
- **XCAP/XDM**: `application/xcap-*+xml`, paths like `/org.openmobilealliance.*`.
- Certs issued to `O=GSM Association` / `O=GSMA` / carrier IPX orgs — a strong "this is telecom
  inter-operator infra" tell.

## Step 2 — Map the element to its trust boundary

Know what each element is supposed to be reachable by, so you can judge the misconfiguration:

| Element | Interface | Should be reachable by | Should enforce |
|---------|-----------|------------------------|----------------|
| BSF (GBA) | Zn (NAF→BSF), Zh (BSF→HSS), Ub (UE→BSF) | NAFs / HSS on trusted net; UE over Ub | mutual TLS / IPsec (NDS/IP, TS 33.210) |
| HSS/AAA | Diameter (Cx/Sh/S6a) | MME/CSCF on core | IPsec, peer allow-list |
| P-CSCF/IMS | SIP (Gm) | subscriber UEs | IMS-AKA / TLS |
| XCAP/XDM | XCAP (Ut) | authenticated subscribers | GBA-derived auth (Ks_NAF) |
| SCEF/NEF | T8/API | trusted 3rd-party AS | OAuth + mTLS |

The rule of thumb: **any core interface other than the UE-facing one (Gm/Ub/Ut) should never be
internet-reachable, and even UE-facing ones require per-subscriber auth.** An unauthenticated core
interface on the public internet is the finding.

## Step 3 — Prove exposure SAFELY (the hard part)

You must demonstrate the exposure without accessing any subscriber's data. Discipline:

1. **Identify** — GET the root, capture the banner/SOAP fault + the 3GPP namespace. This alone
   proves "live carrier element answering anonymously".
2. **Prove no mTLS** — `openssl s_client -connect host:443 -servername host </dev/null`. Look for
   **`No client certificate CA names sent`** = server does not request a client cert = no mutual
   TLS. Record the cert subject (`O=GSM Association` etc.).
3. **Prove it processes operations** — send ONE well-formed operation with **deliberately fake,
   non-subscriber identifiers** (e.g. a fake B-TID `AAAA...@bsf.domain`, `nafId=test.invalid`).
   A response that changes from "invalid request" (empty) to "internal error / not found"
   (structured) proves the element parsed your op and advanced into its lookup path — unauthenticated.
4. **Contrast with siblings** — hit peer nodes in the same cluster with the identical request. When
   they return 401/403/412 and your target returns 200, you've proven it's a *misconfiguration*,
   not by-design-public. This is powerful, credible evidence.

### Hard prohibitions (get this wrong and the whole report is void, or worse)
- **Never submit a real subscriber's B-TID / IMPI / IMSI / MSISDN.** Fake identifiers only.
- **Never extract key material (Ks/Ks_NAF), tickets, or vectors.** Stop at "it processes my op".
- **Never send high volume** — these are live auth nodes; a handful of requests, spaced out.
- If a response ever contains apparent subscriber data, STOP immediately, do not save it, report it.

## Step 4 — Write it as impact, not trivia

Frame: "core cellular-auth element X is internet-reachable, requires no client cert (no mTLS),
requires no credentials, and actively processes operation Y — every precondition for
[key theft / subscriber impersonation] is demonstrated; the only missing input is a valid
subscriber identifier, which I deliberately did not supply." Cite the 3GPP spec that says the
interface must be protected (TS 33.220/33.210/29.109 for GBA). Map to the program's cellular /
sensitive-network-segment tier.

## Worked example (GBA BSF)
```
curl https://nds.bsf.<carrier>/            -> HTTP 200, SOAP fault, xmlns urn:3gpp:gba:GBAService
openssl s_client -connect host:443 ...     -> "No client certificate CA names sent", O=GSM Association
POST requestBootstrappingInfo {fake B-TID} -> fault flips "Invalid SOAP request" -> "Internal error"
sibling bsf.<carrier>                       -> 412 ; aprcs.<carrier> -> 401   (target -> 200)
```
See also: [[protocol-surface-triage]] (generic service triage), [[credential-verification]]
(if the element leaks a credential), [[manual-decision-trees]].
