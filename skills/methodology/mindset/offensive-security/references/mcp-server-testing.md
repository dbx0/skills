# MCP Server Security Testing

Techniques for discovering and testing MCP (Model Context Protocol) servers during bug bounty / red-team engagements.

---

## MCP Server Discovery

### Standard MCP Endpoint Patterns

```
/mcp
/api/mcp
/v1/mcp
/v2/mcp
/mcp/sse
/mcp/schema
```

### Look for in Documentation

- Docs sites (Mintlify, ReadMe, GitBook) — look for "MCP", "Model Context Protocol", "AI agent"
- OpenAPI/Swagger specs — search for `mcp` in paths
- GitHub repos — search for `mcp-server`, `mcp-client`, `@modelcontextprotocol`
- Blog posts about "Claude Desktop integration", "Cursor integration", "AI agent tools"

### Subdomain Patterns

```
mcp.target.com
docs.target.com/mcp
api.target.com/mcp
```

---

## MCP Protocol Basics

JSON-RPC 2.0 over Stdio, HTTP/SSE, or StreamableHTTP.

### Core Methods

| Method | Purpose |
|--------|---------|
| `tools/list` | List available tools |
| `tools/call` | Invoke a tool |
| `initialize` | Start session (no auth usually) |

### Request Format

```json
{"jsonrpc":"2.0","id":1,"method":"tools/list"}
```

**Required headers:**
```
Content-Type: application/json
Accept: application/json, text/event-stream
```

---

## Testing Workflow

### Probe with `tools/list` (No Auth)

```bash
curl -s -X POST "https://docs.target.com/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

**Response interpretation:**
- `200` with tool list → No auth, full access
- `403` with JSON-RPC error → Auth required
- `406` "Not Acceptable" → Missing correct Accept header
- `200` with SSE stream → Parse `event: message\ndata: {...}`

### Probe with Fake API Key

```bash
curl -s -X POST "https://mcp.target.com/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer *** \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

- `400` with "No valid session ID" → Auth middleware accepted the fake key (presence check only)
- `403` "Invalid API key" → Auth validates actual key value

### Initialize Session (if needed)

```json
{
  "jsonrpc": "2.0", "id": 1, "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "test", "version": "1.0.0"}
  }
}
```

---

## Common Vulnerability Patterns

### Filesystem/Search Tool Injection

Tools that accept `command` args with `cat`, `head`, `ls`, `rg`:

```json
{"command": "ls -la /"}
{"command": "cat /etc/passwd"}
{"command": "cat ../../../../etc/passwd"}
{"command": "env"}
{"command": "pwd"}
```

**If `cat /etc/passwd` returns content → sandbox escape!**

### API Proxy Tools (Financial Operations)

Tools that proxy to REST APIs for payment operations:
- Test withdrawals, PIX transfers, payouts without proper auth
- Test IDOR by passing other users' IDs
- Test rate limiting on financial tools

---

## Docs MCP vs Production MCP

**Critical distinction found in real testing (payment-gateway engagement):**

| Aspect | Docs MCP | Production MCP |
|--------|----------|----------------|
| URL | `docs.target.com/mcp` | `mcp.target.com/mcp` |
| Auth | Usually **NONE** | API key required |
| Tools | Search + filesystem only | Actual business tools |
| Hosting | Mintlify/Vercel docs | Custom server (fly.io, etc.) |
| Risk | Sandbox escape via path traversal | Financial tool abuse, credential theft |

**Key findings:**
- Docs MCP (`docs.target.com/mcp`) exposed a `query_docs_filesystem` tool with `cat`/`head`/`ls` — properly sandboxed (path traversal blocked)
- Production MCP (`mcp.target.com/mcp`) exposed financial tools (withdraw, billing, pix, coupon) — required API key
- Both MCP instances on the same domain can have different tools and auth levels
- Always check both!

### payment gateway Case (2026-06)

```
docs.example-pay.tld/mcp → Mintlify-hosted, no auth
  Tools: search_abacate_pay, query_docs_filesystem_abacate_pay (sandboxed)
  
mcp.example-pay.tld/mcp → fly.io + Cloudflare, API key required
  Tools: createWithdraw, createBilling, createCoupon, createCustomer, 
         listCustomers, createPixQrCode (via upstream API)
  Source: github.com/<vendor>/<product>-mcp (TypeScript/Bun)
```

**Pitfall:** Don't conflate the two. A "no auth" finding on docs MCP doesn't apply to the prod MCP, and financial tools in the prod MCP source don't mean they're accessible without credentials.

## Source Code Analysis (GitHub)

Check open-source MCP repos for:

### Auth Middleware

```typescript
app.use('/mcp', validateApiKeyMiddleware);
```

Key question: does it check **presence** or **validity**?

### DNS Rebinding Protection

```typescript
// If this is commented out → SSRF possible:
// enableDnsRebindingProtection: true,
// allowedHosts: ['127.0.0.1'],
```

### API Key Resolution

Priority: 1) per-request param → 2) session context → 3) global env var

---

## Enumeration Checklist

- [ ] `docs.target.com/mcp` (usually no auth, search + filesystem)
- [ ] `mcp.target.com/mcp` (usually API key required)
- [ ] Scan open ports: 80, 443, 3000, 8080, 8443
- [ ] Check GitHub: `github.com/{org}/{name}-mcp`
- [ ] Check Mintlify docs for `/openapi-v1.yaml`
- [ ] DNS rebinding protection status in source
- [ ] Auth middleware — presence check vs validity check