# Well-Known Endpoints & MCP Server Recon

> **Context:** AraraHQ pentest (2026-06-17).
> Probing `docs.ararahq.com` for `.well-known/` endpoints and `mcp.ararahq.com` for MCP tool discovery — both yielded high-value recon data without authentication.

## When to Use This Technique

- You discover a `docs.*` or `developer.*` subdomain during enumeration
- The target offers an MCP server or AI agent integration
- You want to map the full API surface before attempting authenticated testing
- Standard API crawling returns limited results

## .well-known/ Endpoint Probing

Many documentation platforms (especially Mintlify) and API gateways publish metadata under `/.well-known/`. Always probe these on docs subdomains:

```bash
# Standard well-known endpoints for API metadata
for endpoint in \
  /.well-known/api-catalog \
  /.well-known/mcp/server-card.json \
  /.well-known/oauth-protected-resource \
  /.well-known/agent-card.json \
  /.well-known/agent-skills/index.json \
  /.well-known/openapi.json; do
    echo "=== $endpoint ==="
    curl -s -w "\nHTTP %{http_code}\n" "https://docs.target.com$endpoint" | head -5
    echo ""
done
```

### What Each Endpoint Reveals

| Endpoint | Reveals |
|----------|---------|
| `mcp/server-card.json` | MCP server URL, transport type, capabilities, tool count |
| `oauth-protected-resource` | OAuth server URL, authorization server metadata |
| `agent-card.json` | Agent name, skills list, protocol version, provider info |
| `agent-skills/index.json` | Individual skill definitions |
| `api-catalog` | API catalog with endpoint groupings |
| `openapi.json` | Full OpenAPI spec (rare on docs, common in GitHub repos) |

### Real-World Example: AraraHQ (2026-06-17)

`docs.ararahq.com` returned 200 on 4 of 6 well-known endpoints:
- `mcp/server-card.json` → MCP server at `https://arara.main-kill-isr.mintlify.me/mcp`, 2 tools (search + filesystem)
- `oauth-protected-resource` → OAuth server at `https://arara.main-kill-isr.mintlify.me/mcp/oauth`
- `agent-card.json` → Agent name "Arara — API de WhatsApp Business", 1 skill, protocol v0.3
- `agent-skills/index.json` → Skill definition URL

The `llms.txt` endpoint (not `.well-known` but linked from HTML) exposed the **complete API specification** including base URL, auth scheme, all endpoint schemas, error codes, and business logic — 114 lines of machine-readable API docs.

## MCP Server Reconnaissance

MCP (Model Context Protocol) servers expose tools via JSON-RPC 2.0 over HTTP. Even when the actual MCP endpoint is behind a WAF, the root page often leaks tool names and descriptions.

### Discovery Patterns

```bash
# 1. Check for MCP subdomain
curl -s "https://mcp.target.com/" -H "User-Agent: Mozilla/5.0"

# 2. Check well-known for MCP server card
curl -s "https://target.com/.well-known/mcp/server-card.json"

# 3. Check docs subdomain
curl -s "https://docs.target.com/.well-known/mcp/server-card.json"
```

### MCP Root Page HTML Parsing

Many MCP servers serve an HTML landing page at `/` that lists all available tools. Parse it:

```bash
# Extract tool names from MCP root page
curl -s "https://mcp.target.com/" | python3 -c "
import sys, re
html = sys.stdin.read()
# Look for tool names in the HTML
tools = re.findall(r'<div class=\"group-title\">([^<]+)</div>', html)
descs = re.findall(r'<div class=\"group-tools\">([^<]+)</div>', html)
for t, d in zip(tools, descs):
    print(f'{t}: {d}')
"
```

### CORS Wildcard on MCP Servers

MCP servers sometimes have overly permissive CORS. Always test:

```bash
curl -s -X OPTIONS "https://mcp.target.com/" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -D - -o /dev/null | grep -i 'access-control-allow-origin'
```

If the response includes `access-control-allow-origin: *`, any website can make cross-origin requests to the MCP server — a potential security issue if the MCP server handles sensitive operations.

### Real-World Example: AraraHQ MCP (2026-06-17)

- `mcp.ararahq.com` root page (HTTP 200) listed **16 tool groups** with **50+ individual tools** including: auth (login/logout/whoami), messaging, templates, campaigns, contacts, conversations, brain (AI), smart links, recovery, numbers, account, API keys, phone lookup, guardian, payment gateway
- CORS: `Access-Control-Allow-Origin: *` — wildcard, any origin
- Actual MCP endpoint (`POST /mcp`) behind Cloudflare (403)
- Express server (`x-powered-by: Express`) — not a managed MCP service

## GitHub Org → OpenAPI Spec + Postman Collection

When the target has a public GitHub org, check for API specs and collections:

```bash
# List org repos
curl -s "https://api.github.com/orgs/{org}/repos?per_page=100" | python3 -c "
import json, sys
repos = json.load(sys.stdin)
for r in repos:
    print(f\"{r['name']} — {r.get('description','')}\")
"

# Check for OpenAPI spec in docs repo
curl -s "https://raw.githubusercontent.com/{org}/{repo}/main/openapi.yaml"

# Check for Postman collection
curl -s "https://raw.githubusercontent.com/{org}/{repo}/main/*.postman_collection.json"

# Check for MCP server source (reveals OAuth client IDs, API base URLs)
curl -s "https://api.github.com/repos/{org}/{repo}/git/trees/main?recursive=1" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data.get('tree', []):
    if item['path'].endswith(('.ts', '.go', '.py')) and 'src' in item['path']:
        print(item['path'])
"
```

### What to Extract from Source

- **OAuth client IDs** — in constants/config files
- **API base URLs** — confirms the actual backend URL
- **Tool/endpoint definitions** — reveals undocumented capabilities
- **Auth flow implementation** — shows how tokens are refreshed, validated
- **Rate limiting logic** — shows limits per endpoint/tier

## Output Template

```markdown
# Well-Known & MCP Recon — target.com

## .well-known/ Endpoints
| Endpoint | Status | Content |
|----------|--------|---------|
| /.well-known/mcp/server-card.json | 200 | MCP at https://... |
| /.well-known/oauth-protected-resource | 200 | OAuth at https://... |

## MCP Server
| Property | Value |
|----------|-------|
| URL | https://mcp.target.com |
| CORS | Wildcard (*) |
| Tools | 50+ in 16 groups |
| Transport | HTTP (behind Cloudflare) |

## GitHub Findings
| Repo | Finding |
|------|---------|
| docs | openapi.yaml (3673 lines, 63 endpoints) |
| ararahq-mcp | OAuth client ID: ***, API base: https://api... |
| cli | OAuth device flow implementation |
```
