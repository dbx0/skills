# Recon Methodology for Bug Bounty

Passive and active reconnaissance on an external attack surface. Used when target is a live application or when scope (domains, IP ranges, GitHub org) is provided.

---

## Subdomain Enumeration

- Certificate transparency logs (crt.sh)
- Brute force with common wordlists
- DNS zone transfer attempts
- For each discovered subdomain: identify IP, hosting provider, tech stack, response headers
- Flag subdomains pointing to unclaimed cloud assets → subdomain takeover candidates

### Subdomain Takeover False Positives
- CloudFront: `server: CloudFront` header = ACTIVE (not takeover)
- Okta/Auth0: 302 redirect = ACTIVE tenant
- AWS ALB: 404/503 = ACTIVE load balancer
- TRUE takeover: check HTTP body for service-specific strings (`NoSuchBucket`, `NoSuchDomain`, `There isn't a GitHub Pages site here`)

## HTTP Surface Mapping

- Check all subdomains for: open redirect params, login pages, API version enumeration, admin paths
- Spider JS bundles for: hardcoded API keys, internal URLs, commented-out endpoints, sensitive variable names
- HTTP response headers: `Server`, `X-Powered-By`, `X-AspNet-Version` → tech fingerprinting
- `/.well-known/`, `/robots.txt`, `/sitemap.xml` → path disclosure

## Secrets & Credential Exposure

- GitHub org: search public repos for hardcoded secrets (`*.env`, `config.js`, `secrets.yaml`)
- Wayback Machine / CommonCrawl: historical snapshots may contain rotated API keys
- npm/PyPI packages: check for accidental secret inclusion in package tarballs
- Error messages: stack traces, DB connection strings, internal IPs

## API & GraphQL Surface

- GraphQL introspection: `POST /graphql` with `{"query":"{__schema{types{name}}}"}`
- REST API versioning: if v2 is in scope, check if v1 still responds (often less hardened)
- Swagger/OpenAPI exposure: `/api-docs`, `/swagger.json`, `/openapi.json`
- Mass assignment: send extra JSON fields (`role`, `admin`, `is_verified`) in POST/PUT

## Cloud & Infrastructure

- S3: `<company>.s3.amazonaws.com`, `s3.amazonaws.com/<company>` — test read/write
- GCS: `storage.googleapis.com/<bucket>`
- Azure: `<account>.blob.core.windows.net/<container>`
- Elasticsearch/Kibana: ports 9200, 5601 — check unauthenticated access
- Jenkins/Gitlab/Jira: default credentials, CVE checks for exposed versions

## Recon Output Format

```
asset_type: subdomain | s3-bucket | api-endpoint | github-secret | contract | infrastructure
discovery_method: <how it was found>
evidence: <URL, response snippet, or log entry proving the exposure>
takeover_possible: true | false | unknown
```
