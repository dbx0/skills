# OMV Audit — Vulnerability Patterns & Code Examples

Reference patterns from the OpenMediaVault audit (2026-05-21). These are concrete examples of the abstract pitfalls described in the main SKILL.md.

## Pattern 1: XPath Injection via Unsanitized Query Operators

**File**: `config/databasebackendquerybuilder.inc`

The `buildPredicate()` method uses `escapeshellarg()` for string operators but NOT for comparison operators:

```php
// SAFE — uses escapeshellarg()
case "stringEquals":
    $result = sprintf("%s=%s", $filter['arg0'], escapeshellarg($filter['arg1']));

// UNSAFE — no sanitization
case "equals":
    $result = sprintf("%s=%s", $filter['arg0'], $filter['arg1']);
case "less":
    $result = sprintf("%s<%s", $filter['arg0'], $filter['arg1']);
```

**Lesson**: When auditing query builders, check EVERY operator — not just the "string" ones. Numeric/comparison operators often skip escaping.

## Pattern 2: Shell Command via String Concatenation

**File**: `system/process.inc`

The `Process` class builds a shell command string by imploding args with spaces, then passes to `exec()`:

```php
public function getCommandLine() {
    $cmdArgs = array_merge($cmdArgs, $this->cmdArgs);
    return implode(" ", $cmdArgs);
}

public function execute(...) {
    $cmdLine = $this->getCommandLine();
    $result = exec($cmdLine, $output, $exitStatus);  // SHELL INJECTION
}
```

**Lesson**: Any system that builds shell commands via string concatenation is vulnerable if ANY argument is user-controlled. Look for `implode(" ", $args)` → `exec()` chains.

## Pattern 3: os.system() with Joined Args (Python)

**File**: `mkrrdgraph.py`

```python
def call_rrdtool_graph(args):
    return os.system(' '.join(['rrdtool', 'graph', *args, '>/dev/null']))
```

**Lesson**: Python's `os.system()` with `' '.join()` is equivalent to PHP's `exec()` with string concatenation. If `args` comes from config that an admin can modify, it's RCE.

## Pattern 4: Download Proxy Trusts Server-Side Paths

**File**: `rpc/proxy/download.inc`

```php
protected function handleResponse($response) {
    @readfile($response['filepath']);
    if (TRUE === $response['unlink']) {
        @unlink($response['filepath']);
    }
}
```

**Lesson**: Generic download proxies that accept a `filepath` from another component are dangerous. If ANY RPC method returns a controllable `filepath`, it becomes arbitrary file read. Audit all callers of the download proxy.

## Pattern 5: Session ID from HTTP Header (Session Fixation)

**File**: `session.inc`

```php
public function start() {
    $sessionId = array_value($_SERVER, "HTTP_X_OPENMEDIAVAULT_SESSIONID", FALSE);
    if (FALSE !== $sessionId) {
        session_id($sessionId);  // No validation!
    }
    session_start();
}
```

**Lesson**: When you see `session_id()` called with user-supplied data, it's session fixation. The fix is to regenerate the session ID on login.

## Pattern 6: Commented-Out Security Check

**File**: `session.inc`

```php
public function validate() {
    $this->validateAuthentication();
    // $this->validateIpAddress();  // DISABLED
    $this->validateUserAgent();
    $this->validateTimeout();
    $this->validateUser();
}
```

**Lesson**: Always check for commented-out security code. It often indicates a known issue that was "temporarily" disabled and never re-enabled.

## Pattern 7: Type Validation ≠ Sink Sanitization

The RPC layer validates parameters with JSON schema (type checking), but the validated strings are then used in XPath queries without XPath-specific escaping. This is the most common pattern in modern web apps — the validation layer gives a false sense of security.

**Lesson**: Always check what happens AFTER validation. The sink context determines what sanitization is needed.

## Pattern 8: XXE Loading Enabled

**File**: `config/databasebackend.inc`

```php
libxml_disable_entity_loader(false);  // XXE enabled!
```

**Lesson**: Check for `libxml_disable_entity_loader(false)` in PHP apps. If an attacker can influence XML content, this enables XXE.

## Pattern 9: Stack Trace in API Error Responses

**File**: `rpc.php`

```php
"trace" => $e->__toString()  // Full stack trace to client
```

**Lesson**: Stack traces in API responses leak file paths, class names, internal architecture. Check all catch blocks in web-facing scripts.

## Pattern 11: Unauthenticated Login RPC with System-Level Rate Limiting Only

**File**: `var/www/openmediavault/rpc/session.inc` + `etc/pam.d/openmediavault-webgui`

The login RPC is unauthenticated and relies entirely on PAM/faillock for brute force protection. There is NO application-level rate limiting, CAPTCHA, or account lockout. If faillock is misconfigured (e.g., `deny=0` or `unlock_time=0`), brute force is unrestricted.

**Lesson**: When auditing login endpoints, check both application-level AND system-level rate limiting. Don't assume PAM is properly configured.

## Pattern 12: GET-Based RPC with Direct $_GET→Params Mapping

**File**: `rpc/proxy/json.inc`

```php
protected function getParams() {
    if (!empty($_GET)) {
        $this->params = [];
        foreach ($_GET as $key => $value) {
            $this->params[$key] = $value;  // Direct copy, no filtering
        }
    }
```

The RPC endpoint accepts GET parameters and maps them directly to RPC params. This enables:
- CSRF via GET requests (though the login requires knowing credentials)
- HTTP parameter pollution if both GET and POST are sent
- Easier fuzzing (no need to craft JSON POST bodies)

**Lesson**: Check if RPC endpoints accept GET. If so, test for CSRF, parameter pollution, and whether GET-based requests bypass any POST-only security checks.

**File**: `system/shellscript.inc`

```php
class ShellScript {
    public function execute(array &$output = NULL, &$exitStatus = NULL) {
        $cmdLine = $this->script;
        $result = exec($cmdLine, $output, $exitStatus);  // Raw exec, no sanitization
    }
}
```

**Lesson**: Classes that wrap `exec()` with no sanitization are time bombs. Even if current callers use hardcoded strings, future features might pass user input.
