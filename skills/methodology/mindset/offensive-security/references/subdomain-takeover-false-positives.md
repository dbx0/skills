# Subdomain Takeover — False Positive Patterns

## CloudFront (Most Common FP)
ACTIVE: server: CloudFront/awselb/2.0, x-cache: Error from cloudfront, x-amz-cf-* headers
TRUE takeover: NoSuchDistribution, The specified distribution does not exist

## Okta/Auth0 Custom Domains
ACTIVE: 302 redirect, x-okta-request-id header, service branding in page
TRUE takeover: tenant completely deleted (rare)

## AWS ALB/ELB
NEVER a takeover — owned by AWS account. 404/503 = active LB with broken backend.

## Third-Party SaaS
ACTIVE: 404/503/redirect on root path
TRUE takeover: "domain not configured" or "account not found" page

## Verification Checklist
1. CNAME target resolves? → likely active
2. Any HTTP response? → likely active
3. Service-specific headers? → likely active
4. Fingerprint matches TRUE takeover indicator?
5. Can you register the resource yourself?

## financial institution Case Study (May 2026)
143 subdomains, 60+ CNAMEs. Two scanning approaches:

**Custom Python scanner:** Reported 4 "vulnerable" — all FPs:
- `rocnew.example-bank.tld` → 404 from AWS ALB (Apache Tomcat backend, ALB is active)
- `authsrvcsqa.example-bank.tld` → 302 from Okta Preview (active tenant)
- `authsrvcsprd.example-bank.tld` → 302 from Okta (active tenant)
- `ir.example-bank.tld` → 200 from GCS Web (active investor relations site)

**Root cause:** Fingerprint list too broad — matched service names ("CloudFront", "Okta") in error page content, and matched generic 404/503 responses.

**Verified non-takeovers:**
- `auth.integrations.digital.example-bank.tld` — 404 with `awselb/2.0` + CloudFront headers = active distribution
- `cloud.customer.example-bank.tld` — 404 from SFMC with `X-Cache-Status: CACHED` = active endpoint
- `prontotest.example-bank.tld` — 503 from fundation.com = service outage, tenant exists
- `rocnew.example-bank.tld` — 404 from Apache Tomcat behind AWS ALB = app-level 404

**Result: 0 actual takeovers out of 143 subdomains.**

## SFMC (Salesforce Marketing Cloud)
ACTIVE: `X-Cache-Status: CACHED` header, 404 from SFMC infrastructure
These are managed by Salesforce — cannot be taken over by third parties.

## Citrix ShareFile
Active ShareFile instances return `X-Frame-Options: DENY` and have their own auth.
Cannot be taken over without Citrix decommissioning the account.

## Fundation
503/timeout = service outage or backend misconfiguration, NOT a takeover.
True takeover: Fundation would show a "domain not configured" page.
