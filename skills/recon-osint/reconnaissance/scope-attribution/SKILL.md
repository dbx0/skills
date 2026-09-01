---
name: scope-attribution
description: Verify a host is actually operated by the target before testing it. A DNS name inside an in-scope wildcard does NOT mean the target owns the infrastructure behind it — CNAMEs to SaaS vendors, ISP circuits and honeypots all appear as legitimate subdomains. Use before testing any newly discovered host, before reporting cloud storage found by name permutation, and whenever a subdomain resolves outside the target's usual hosting.
sources: field_recon (fintech engagement — ISP-run VPN, vendor whistleblowing portal, honeypot buckets)
report_count: 0
---

# Scope Attribution

`vpn.target.com` being inside `*.target.com` tells you the target controls the **DNS record**.
It tells you nothing about who owns the **machine**. Testing the machine is what the program
scopes, and what the law cares about.

The failure is asymmetric: skipping this check costs nothing until it costs you the program.

## The three-question check

Run before the first request to any newly discovered host.

```bash
attrib () {  # attrib <host>
  ip=$(dig +short "$1" | grep -E '^[0-9]+\.' | head -1)
  echo "host   : $1"
  echo "cname  : $(dig +short CNAME "$1" | head -1)"
  echo "a      : ${ip:-none}"
  [ -n "$ip" ] && whois "$ip" 2>/dev/null | grep -iE '^(orgname|netname|owner|descr|inetnum)' | head -3
  [ -n "$ip" ] && echo "rdns   : $(dig +short -x "$ip" | head -1)"
}
```

**1. Where does the CNAME point?** A CNAME to a SaaS provider means the vendor runs the app.
Real examples, all on in-scope wildcards, all out of bounds:

| CNAME target | Vendor | What it looked like |
|---|---|---|
| `www.contatoseguro.com.br` | Contato Seguro | a *fraud-reporting portal* with a submission form and file uploads — the most attractive target on the estate |
| `cname.createsend.com` | Campaign Monitor | a login panel branded as the target |
| `ghs.googlehosted.com` | Google Sites | internal-looking staff tooling |
| `proxy-ssl.webflow.com` | Webflow | a marketing site |
| `*.hosted-by-discourse.com` | Discourse | the customer community |

**2. Who owns the IP?** Compare against the target's known ranges. A bank running on AWS
`sa-east-1` does not suddenly host a VPN on a consumer ISP circuit:

```
vpn.target.com.mx → <isp-ip>
  OrgName: Megacable Comunicaciones de Mexico
  rdns   : service-static-...mcm-telecom.com.mx     ← ISP kit, NOT the target's
```

Probing that box touches an ISP's equipment shared with their other customers.

**3. Does the page load third-party assets?** If every script comes from
`cdn-site.<vendor>.com`, the vendor wrote the app. Grep the HTML for `src="https://` hosts
before assuming the target wrote the code you're about to test.

## Cloud storage: name permutation is not attribution

Bucket-name permutation (`{prefix}-{service}-{suffix}`) produces hits owned by strangers.
Generic dictionary names — `credit`, `notifications-static`, `kyc-media`, `customers-staging` —
belong to whoever registered them first, which is rarely your target.

**Honeypot markers.** A bucket that lists exactly the files you hoped for is bait:

```
banner-uploads/  →  who.txt, writeable_bucket.txt, images.jpeg
customers-staging/ → .env, backup.zip, payroll.xlsx, prod-wg-vpn.conf, user-backup.csv
```

That second listing is either a canary or a real third party's payroll. Both mean: do not download.

**S3 enumeration is also unreliable.** The same bucket returned a key listing and `NoSuchBucket`
minutes apart, and AWS deliberately returns `AccessDenied` for buckets you don't own to defeat
enumeration — so "EXISTS" from a 403 proves nothing.

**Only treat a bucket as in scope if the target's own assets reference it.** Grep your harvested
JS and source for `s3.amazonaws.com` / `storage.googleapis.com` / `blob.core.windows.net` and
test *those* names. In the reference engagement that reduced ~330 permutation "hits" to exactly
one attributable bucket — which was correctly locked down.

## When the DNS is theirs but the box isn't

Report it, don't test it. A dangling or third-party-pointing record is worth telling the program
about (it's their DNS hygiene), but the machine belongs to someone who never authorized you.

Note the asymmetry in write-ups: *"`vpn.target.com.mx` resolves to a Megacable ISP circuit"* is a
legitimate observation. *"I port-scanned it"* is testing a non-participant.

## Red flags that should stop you mid-recon

- rDNS or whois naming an ISP, telecom, or hosting reseller rather than the target or a major cloud
- A CNAME leaving the target's domain entirely
- A page whose assets all load from one unfamiliar CDN
- A storage bucket whose name you *guessed* rather than *found referenced*
- Contents that are too convenient (`.env` + `payroll.xlsx` + VPN config in one listing)

## Interaction with program rules

Most programs carry some form of *"do not test third-party services, vendors, or SSO providers
not owned by the program."* Attribution is how you comply with that clause — it is not optional
diligence, it is the clause itself.
