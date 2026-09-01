---
name: archive-credential-recovery
description: Use when a target has dead, replaced, or superseded hosts/deployments and you want to mine Internet Archive (Wayback CDX) for old JS/JSON bundles that may still carry live credentials, or when archived API responses may still expose sensitive data even after the live endpoint is fixed. Trigger on "wayback machine", "archive.org", "CDX", "old deploy secrets", "archived credentials", or "dead host recon".
version: 1.0.0
author: field-derived (iFood engagement, Zoop receipts + dead-host sweep)
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [wayback, archive, cdx, osint, secrets, recon]
    related_skills: [credential-verification, build-env-secret-triage, artifact-pivot-intelligence, bug-bounty]
---

# Archived/Wayback Credential and Data Recovery

Dead or replaced hosts can still leak through the Internet Archive, and archived HTTP responses can
remain publicly retrievable long after the live endpoint is fixed, gated, or shut down. This is a
distinct disclosure surface from the live site and is easy to skip entirely during a live-host-only
engagement.

## When to Use

- Recon surfaces hosts that never resolve/answer HTTP, or currently return `404`/dead-deployment
  signals, that were plausibly live at some point
- A high-value host has been replaced/migrated and you want to check whether the old deployment's
  bundles are still archived
- You've exhausted the live-site sweep and want additional coverage before declaring a target area
  clean

## Method

### 1. Index candidates via the Wayback CDX API

Query `web.archive.org/cdx/search/cdx` for each candidate host. Two useful candidate sets:
- Hosts that never answer HTTP today, or answer `404` (deployment gone/replaced)
- Archived copies of currently-live high-value hosts, to catch secrets from a superseded deploy that
  predates a rotation

### 2. Filter and dedupe

- Keep JS/JSON captures only
- Dedupe to the most recent capture per unique URL (older captures of the same file are redundant
  unless you're specifically hunting for a rotated-out secret)
- Filter out third-party library/plugin/CDN code — same discipline as a live JS sweep

### 3. Fetch and mine

- Fetch raw bodies via `web.archive.org/web/<timestamp>id_/<url>` (the `id_` suffix returns the
  unmodified original, not Wayback's UI-wrapped version)
- Mine with the same secret and build-env patterns used on live bundles (see
  `build-env-secret-triage`)

### 3b. When archive.org rate-limits or IP-bans you (it will, at volume)

The Wayback CDX and `id_` endpoints **429 hard and then ban the source IP across all of
archive.org** once you flood them (dozens of wildcard/filtered CDX queries, or a bulk `id_` fetch of
tens of thousands of URLs). The ban is by IP, not by method — switching CDX/`id_`/timetravel does
not help. Discipline and failover:

- **Pace CDX**: one query per apex domain (filter locally), spaced seconds apart — not dozens of
  per-extension filtered queries. A run of 429s means STOP; continuing deepens the ban.
- **`id_` bulk fetch**: 2-4 req/s max, and expect the ban mid-run. Fetch high-value hosts (auth,
  api, account, admin) first so the useful bytes land before you are throttled.
- **Failover to independent sources** (not archive.org, so unaffected by its ban):
  - **urlscan.io** - `api/v1/search/?q=domain:<d>` (keyless) lists captures; each capture's
    `result/<id>/` JSON enumerates every JS/config resource it loaded. (The result API itself
    rate-limits without an API key - the *search* API is more tolerant.)
  - **CommonCrawl** - `index.commoncrawl.org/<crawl-id>-index?url=*.<d>&output=json` (flaky but
    independent).
  - **Shodan/Censys** banners, certificate transparency - for versions/hosts without fetching.
- If several unrelated services block the same exit at once (archive 429 + Akamai 403 + urlscan
  403), the **IP is burned** - rotate the egress rather than retry. See [[egress-waf-evasion]].

### 4. Verify against live, in-scope endpoints only

An archived secret is only a finding if it still works today. Run it through
`credential-verification`'s three-state test against the **current, live, in-scope** service — never
test a recovered credential against a host that is itself out of scope, even if the credential was
found via that host's archive.

### 5. Separately: check whether the archive discloses sensitive *data*, not just secrets

An API route that returns PII, financial data, or other sensitive records may have been crawled and
cached with `200` responses before the endpoint was properly gated — and archived copies can remain
renderable from web.archive.org even after the live route now returns `401`/`403`/nothing.

- Confirm via CDX metadata alone which routes were captured `200` vs `401`/`403`, and how many
  captures exist — this proves the historical exposure existed without requiring you to fetch bodies
  containing real third-party data.
- **Do not fetch archived bodies containing real third-party PII/payment/financial data.** Build the
  report from CDX metadata (URL patterns, capture counts, status codes, date ranges) plus the
  service's own public documentation of what that route type returns. If you must confirm content
  shape, fetch the minimum number of samples needed and stop the moment PII is visible — do not bulk
  download.
- Note in the report that the program should consider requesting Internet Archive exclusion for the
  exposed URL patterns.

## Common Mistakes

- Testing a recovered credential against an out-of-scope host just because that's where it was found
- Bulk-fetching archived response bodies that contain real customer/PII data instead of proving the
  exposure via CDX metadata and stopping there
- Treating "the live route now 404s" as proof there's no finding — the archived copies may still be
  retrievable and that is the actual, current exposure
- Skipping the dedupe step and burning archive rate-limit budget refetching identical historical
  captures

## Cross-References

- `build-env-secret-triage` for triaging any secret-looking value recovered from archived bundles
- `credential-verification` for proving a recovered credential is still live
- `artifact-pivot-intelligence` for the broader public-artifact pivoting methodology this slots into

---

## Addendum — two pitfalls that silently void an archive sweep

*(field_recon: fintech engagement — 52% of a corpus scanned as binary before this was caught)*

### 1. The `id_` endpoint returns RAW bytes, including `Content-Encoding: gzip`

`https://web.archive.org/web/<ts>id_/<url>` replays the origin's **original response bytes**. If
the origin served gzip, you receive gzip — and `curl` without `--compressed`, or any raw
`urlopen().read()`, writes compressed data to disk. A regex secret-scan over that file matches
nothing and reports a clean negative.

This fails **silently**. There is no error, just a corpus that looks scanned.

```python
raw = resp.read()
if raw[:2] == b"\x1f\x8b":                       # gzip magic
    try:    raw = gzip.decompress(raw)
    except: raw = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw)
```

**Audit an existing corpus before trusting it:**

```bash
for f in corpus/*; do head -c2 "$f" | od -An -tx1 | grep -q '1f 8b' && echo "GZIPPED: $f"; done
```

In the reference case that was 710 of 1,366 files. Re-scanning after decompression changed the
hit count from 1,697 to 2,256 — no new secrets as it happened, but the earlier "the archive is
clean" claim had not been supportable.

### 2. Archived **hosts** are a discovery source, not just archived files

Most sweeps mine archived *URLs* for endpoints and stop there. Extract the **host** column and
diff it against your enumeration — CDX records hosts that no longer resolve, were never
certificate-logged, and appear in no passive-DNS source.

```bash
awk '{print $2}' cdx_all.txt \
  | sed -E 's#https?://([^/:]+).*#\1#' | tr 'A-Z' 'a-z' | sort -u > archive_hosts.txt
grep -vxFf enumerated_hosts.txt archive_hosts.txt      # the delta is the prize
```

This surfaced an entire **sharded production fleet** (`prod-s0-` … `prod-s9-` across ~24 services,
130+ hosts) that subfinder, certspotter, crt.sh and the target's own service-discovery API had all
missed. Confirm there is no DNS wildcard first, or the results are meaningless:

```bash
dig +short zzzz-notreal-9v8x7.target.com    # must be empty
```

Feed the recovered internal service *names* back in as a permutation wordlist — internal codenames
(`maxwell`, `balrog`, `arcus`) are impossible to guess and often reveal further hosts.

### 3. Enumerate path variants, not just paths

Edge/WAF rules frequently match an exact path. Append a trailing slash to every candidate:

```
/api/metrics    → 403  (WAF block page)
/api/metrics/   → 200  (44 MB Prometheus dump, unauthenticated)
```

One character. Cheap to add to any wordlist sweep; also try `//path`, `/./path`, `/path;.css`,
`/path.json`.
