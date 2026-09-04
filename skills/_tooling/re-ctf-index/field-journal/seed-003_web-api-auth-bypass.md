# [Seed] Web API Unauthorized Access + IDOR

## Scenario Category
Penetration testing

## Target Overview
Black-box testing of a web application's REST API, which turned up unauthorized access and IDOR vulnerabilities.

## Full Execution Chain

1. Recon: Nmap scan → found port 443 running Nginx + a backend API
2. Directory discovery: FFUF brute force → found the `/api/v1/` path
3. API enumeration: hit `/api/v1/docs` → found exposed Swagger documentation
4. Auth analysis: registered two test accounts, A and B
5. IDOR test: used account A's token to access account B's resource → success (horizontal privilege escalation)
6. Unauthorized access test: stripped the Authorization header → some endpoints still returned data (unauthorized access)
7. Impact validation: confirmed that any user's personal information could be read (name, email, phone number)
8. Evidence collection: saved request/response screenshots, redacted them, and wrote up the report

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| FFUF blocked by the WAF | Request rate too high, tripping rate limiting | Lower the rate with `-rate 10`, add `-H "User-Agent: Mozilla/5.0..."` | 10min |
| Swagger docs returned 404 | The path was not the standard /swagger | Try `/api/v1/docs`, `/api-docs`, `/openapi.json` | 5min |
| Unclear whether the IDOR test succeeded | The returned data had no obvious user identifier | Diff the responses from the two accounts and locate the user_id field difference | 15min |
| Report rejected by the SRC program | Only screenshots were submitted, with no complete reproduction steps | Add curl commands + full request/response | 20min |

## Toolchain Findings

- FFUF is faster than Gobuster, but the rate needs to be controlled to avoid getting banned
- Exposed Swagger/OpenAPI documentation is the fastest way to enumerate an API
- IDOR testing must be done between two of your own accounts, never touch anyone else's data
- An SRC report must include reproducible curl commands, screenshots alone are not enough

## Key Code / Commands

```bash
# Directory discovery
ffuf -u https://target.example.com/api/v1/FUZZ -w /path/to/SecLists/Discovery/Web-Content/api/api-endpoints.txt -rate 10

# IDOR test
# Use account A's token to access account B's resource
curl -H "Authorization: Bearer <token_A>" https://target.example.com/api/v1/users/USER_B_ID

# Unauthorized access test
curl https://target.example.com/api/v1/users/USER_B_ID
# If it returns 200 + data → unauthorized access
```

## Improvement Suggestions for This Package

- pentest-tools should add a dedicated "API penetration testing" checklist
- src-hunter's IDOR playbook is very useful, but it lacks guidance on "how to determine the impact scope of an IDOR"

## Reusable Patterns / Script Snippets

**Three-step method for API unauthorized access testing**:
```text
1. Normal request (with token) → record the normal response
2. Strip the token → see whether data is still returned (unauthorized access)
3. Swap in another user's token → see whether access succeeds (privilege escalation)
```

**Quick IDOR validation**:
```text
1. Register two accounts, A and B
2. Obtain A's resource ID and B's resource ID
3. Request B's resource ID with A's token
4. If B's data comes back → IDOR confirmed
```

## Evolution Actions
- [ ] No routing matrix update needed
- [ ] No bootstrap-manifest update needed
- [ ] No sub-skill documentation update needed

## Environment Information
- OS: Windows (local machine) → target Linux server
- Tool versions: FFUF 2.x, curl, Burp Suite
- Target platform: Web API (REST, JSON)

## Redaction Requirements
This entry is seed data, written from publicly known technical patterns, and does not involve any real target.

---
<!-- [Evolution stats] Cumulative projects completed by this package: 3 | New patterns added this round: 2 | Toolchain issues fixed this round: 0 -->
<!-- [Community contribution] Seed data, no PR needed -->
