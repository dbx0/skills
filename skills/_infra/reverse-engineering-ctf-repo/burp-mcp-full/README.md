# BurpSuite MCP Full Control Extension

Full control of every core BurpSuite feature over the MCP protocol. Cross-platform: Windows / Linux (Kali) / macOS.

## Quick start

### 1. Build the extension

**Windows**:
```cmd
cd burp-mcp-full
build.bat
```

**Linux / Kali / macOS**:
```bash
cd burp-mcp-full
chmod +x build.sh
./build.sh
```

### 2. Load it into Burp

```
Burp Suite → Extensions → Add → Java → select build/libs/burp-mcp-full.jar
```

### 3. Configure the MCP client

Add the following in any MCP client (Claude Code / Kiro / Cursor / Cline / Windsurf):

```json
{
  "mcpServers": {
    "burpsuite": {
      "command": "node",
      "args": ["<path to this directory>/mcp-bridge.js"]
    }
  }
}
```

### 4. Start using it

Tell the AI: "analyze the requests in Burp's proxy history and find security vulnerabilities"

## Feature list

| Tool | Function | Parameters |
|------|------|------|
| `proxy_history` | View and filter proxy history | `limit`, `offset`, `url_filter`, `method_filter` |
| `send_request` | Send an HTTP request through Burp | `method`, `url`, `body`, `headers` |
| `send_to_repeater` | Send a request to Repeater | `request`, `tab_name` |
| `send_to_intruder` | Send a request to Intruder | `request` |
| `intruder_attack` | **Automated enumeration attack** | `url_template`, `from`, `to`, `pad_digits`, `method`, `headers`, `success_indicator`, `success_length_not` |
| `sitemap` | View the sitemap | `url_prefix`, `limit` |
| `intercept_toggle` | Toggle interception | `enable` |
| `encode` | Encode (Base64/URL) | `input`, `type` |
| `decode` | Decode (Base64/URL) | `input`, `type` |
| `scan` | Start a vulnerability scan | `url` |
| `add_to_scope` | Add to scope | `url` |

## Installation

### Option 1: use the prebuilt jar

```
1. Download burp-mcp-full.jar
2. Burp → Extensions → Add → Extension Type: Java → Select file
3. After loading, Output shows "[MCP] Server started on http://127.0.0.1:9876"
```

### Option 2: build from source

```bash
cd burp-mcp-full
gradlew.bat jar
# Output: build/libs/burp-mcp-full.jar
```

## MCP configuration

### Kiro (.kiro/settings/mcp.json)
```json
{
  "mcpServers": {
    "burpsuite": {
      "url": "http://127.0.0.1:9876"
    }
  }
}
```

## Usage examples

### View proxy history
```json
POST http://127.0.0.1:9876
{"tool": "proxy_history", "params": {"limit": 10, "url_filter": "personalblog"}}
```

### Send a request
```json
POST http://127.0.0.1:9876
{"tool": "send_request", "params": {"method": "GET", "url": "https://example.com/api/test"}}
```

### Automated enumeration attack (the core feature)
```json
POST http://127.0.0.1:9876
{
  "tool": "intruder_attack",
  "params": {
    "url_template": "https://target.com/api/verify?code=§§",
    "method": "POST",
    "from": 0,
    "to": 999999,
    "pad_digits": 6,
    "success_length_not": 176,
    "headers": {"User-Agent": "Mozilla/5.0"}
  }
}
```

### Toggle interception
```json
POST http://127.0.0.1:9876
{"tool": "intercept_toggle", "params": {"enable": false}}
```

## Ports

Listens on `127.0.0.1:9876` by default, the same port as PortSwigger's official MCP extension.
If you run the official extension at the same time, change the port number in the source.
