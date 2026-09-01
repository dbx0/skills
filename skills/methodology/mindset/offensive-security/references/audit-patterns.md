# Source Code Audit — Vulnerability Patterns & Code Examples

Reference patterns from real audits (OMV 2026-05-21, Nextcloud 35.0.0 2026-05-21). These are concrete examples of the abstract pitfalls described in the main SKILL.md.

---

## Pattern 1: XPath Injection via Unsanitized Query Operators

**Source**: OpenMediaVault audit
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

---

## Pattern 2: Shell Command via String Concatenation

**Source**: OpenMediaVault audit
**File**: `system/process.inc`

```php
public function getCommandLine() {
    $cmdArgs = array_merge($cmdArgs, $this->cmdArgs);
    return implode(" ", $cmdArgs);
}
// ...
$result = exec($cmdLine, $output, $exitStatus);  // SHELL INJECTION
```

**Lesson**: Any system that builds shell commands via string concatenation is vulnerable if ANY argument is user-controlled. Look for `implode(" ", $args)` → `exec()` chains.

---

## Pattern 3: os.system() with Joined Args (Python)

**Source**: OpenMediaVault audit
**File**: `mkrrdgraph.py`

```python
def call_rrdtool_graph(args):
    return os.system(' '.join(['rrdtool', 'graph', *args, '>/dev/null']))
```

**Lesson**: Python's `os.system()` with `' '.join()` is equivalent to PHP's `exec()` with string concatenation.

---

## Pattern 4: Download Proxy Trusts Server-Side Paths

**Source**: OpenMediaVault audit
**File**: `rpc/proxy/download.inc`

```php
@readfile($response['filepath']);
if (TRUE === $response['unlink']) {
    @unlink($response['filepath']);
}
```

**Lesson**: Generic download proxies that accept a `filepath` from another component are dangerous. Audit all callers of the download proxy.

---

## Pattern 5: Session Fixation via Custom Header

**Source**: OpenMediaVault audit
**File**: `session.inc`

```php
$sessionId = array_value($_SERVER, "HTTP_X_OPENMEDIAVAULT_SESSIONID", FALSE);
if (FALSE !== $sessionId) {
    session_id($sessionId);  // No validation!
}
```

**Important**: Modern PHP session IDs have 128-bit entropy — you cannot guess them remotely. The realistic attack requires MITM/XSS to set the header, not remote exploitation. Check if `session_regenerate_id()` is called on login (mitigates but doesn't eliminate).

---

## Pattern 6: Commented-Out Security Check

**Source**: OpenMediaVault audit
**File**: `session.inc`

```php
// $this->validateIpAddress();  // DISABLED
```

**Lesson**: Always check for commented-out security code. It often indicates a known issue that was "temporarily" disabled.

---

## Pattern 7: Type Validation ≠ Sink Sanitization

**Source**: OpenMediaVault audit

JSON schema validates types, but validated strings are then used in XPath without XPath-specific escaping.

**Lesson**: Always check what happens AFTER validation. The sink context determines what sanitization is needed.

---

## Pattern 8: XXE Loading Enabled

**Source**: OpenMediaVault audit

```php
libxml_disable_entity_loader(false);  // XXE enabled!
```

**Lesson**: Check for `libxml_disable_entity_loader(false)` in PHP apps.

---

## Pattern 9: Stack Trace in API Error Responses

**Source**: OpenMediaVault audit

```php
"trace" => $e->__toString()  // Full stack trace to client
```

**Lesson**: Stack traces in API responses leak file paths, class names, internal architecture.

---

## Pattern 10: GET-Based RPC with Direct $_GET→Params Mapping

**Source**: OpenMediaVault audit
**File**: `rpc/proxy/json.inc`

```php
foreach ($_GET as $key => $value) {
    $this->params[$key] = $value;  // Direct copy, no filtering
}
```

**Lesson**: Check if RPC endpoints accept GET. Test for CSRF, parameter pollution.

---

## Pattern 11: Raw exec() Wrapper Class

**Source**: OpenMediaVault audit
**File**: `system/shellscript.inc`

```php
class ShellScript {
    public function execute(...) {
        $result = exec($this->script, $output, $exitStatus);
    }
}
```

**Lesson**: Classes that wrap `exec()` with no sanitization are time bombs.

---

## Pattern 12: CSRF Bypass via Custom Header

**Source**: Nextcloud 35.0.0 audit (2026-05-21)
**File**: `lib/private/AppFramework/Http/Request.php`

```php
public function passesCSRFCheck(): bool {
    if ($this->getHeader('OCS-APIRequest') !== '') {
        return true;  // Automatic pass!
    }
    // ... token validation ...
}
```

**Lesson**: Many APIs exempt certain request types from CSRF protection for non-browser client compatibility. Check for header-based CSRF exemptions that could be exploited via XSS.

---

## Pattern 13: Unauthenticated Status Endpoint with CORS

**Source**: Nextcloud 35.0.0 audit
**File**: `status.php`

```php
header('Access-Control-Allow-Origin: *');
echo json_encode(['version' => '...', 'installed' => true, ...]);
```

**Lesson**: Unauthenticated JSON endpoints with `Access-Control-Allow-Origin: *` enable cross-origin info gathering (version fingerprinting, etc.).

---

## Pattern 14: Username Leakage via Redirect Parameters

**Source**: Nextcloud 35.0.0 audit
**File**: `core/Controller/LoginController.php`

```php
$args = $user !== null ? ['user' => $originalUser, 'direct' => 1] : [];
$response = new RedirectResponse($this->urlGenerator->linkToRoute('core.login.showLoginForm', $args));
```

**Lesson**: Login failure redirects with username in URL leak to browser history, server logs, and referrer headers.

---

## Pattern 15: IP-Based Rate Limiting Spoofable Behind Proxy

**Source**: Nextcloud 35.0.0 audit
**File**: `lib/private/AppFramework/Middleware/Security/BruteForceMiddleware.php`

```php
$remoteAddress = $this->request->getRemoteAddress();
$this->throttler->sleepDelayOrThrowOnMax($remoteAddress, $action);
```

**Lesson**: Check `trusted_proxies` configuration. If misconfigured, `X-Forwarded-For` spoofing bypasses rate limiting.

---

## Pattern 16: App File Inclusion via Path Routing

**Source**: Nextcloud 35.0.0 audit
**File**: `public.php`, `remote.php`

```php
$app = $parts[0];
$appManager->loadApp($app);
require_once $file;  // $file derived from URL path
```

**Lesson**: Systems that route to app files based on URL paths expose ALL installed apps' PHP files. The attack surface includes third-party apps.

---

## Pattern 17: Large Codebase Strategy (5000+ files)

**Source**: Nextcloud 35.0.0 audit

For large codebases, prioritize:
1. **Entry points**: `index.php`, `public.php`, `remote.php`, `status.php`, `ocs/v1.php`
2. **Auth flow**: login controller, session management, CSRF middleware, brute force middleware
3. **Dangerous functions**: grep for `exec()`, `system()`, `eval()`, `unserialize()`, `readfile()`, `require/`
4. **File operations**: download handlers, file serving, upload processing
5. **Service definitions**: RPC methods, API controllers, route definitions

Use `grep -rn` to find patterns, then manually trace only reachable sinks. Don't try to read 5000+ files linearly.

---

## Pattern 18: PHP 8 Attribute vs PHPDoc Annotation for Auth Bypass

**Source**: Nextcloud 35.0.0 audit

PHP 8 introduced attributes (`#[PublicPage]`) as a replacement for PHPDoc annotations (`@PublicPage`). Both can be used in the same codebase:

```bash
# This MISSES PHP 8 attributes:
grep -rn "@PublicPage" --include="*.php" .

# This catches BOTH forms:
grep -rn "PublicPage" --include="*.php" .
```

**Lesson**: When searching for unauthenticated endpoints, always search for the bare keyword, not just the annotation form. In Nextcloud 35, all 64 `#[PublicPage]` attributes were in apps — none in core. The core uses `#[NoAdminRequired]` which still requires auth.

---

## Pattern 19: Username Enumeration via Unauthenticated Password Reset

**Source**: Nextcloud 35.0.0 audit (user_ldap app)
**File**: `apps/user_ldap/lib/Controller/RenewPasswordController.php`

```php
#[PublicPage]
public function showRenewPasswordForm(string $user): TemplateResponse|RedirectResponse {
    if (!$this->userConfig->getValueBool($user, 'user_ldap', 'needsPasswordReset')) {
        return new RedirectResponse(...);  // User doesn't need reset → redirect
    }
    // Shows password reset form → user exists and needs reset
}
```

**Route**: `GET /renewpassword/{user}`

**Lesson**: Unauthenticated endpoints that accept a username and behave differently based on user state enable username enumeration. Check all `@PublicPage`/`#[PublicPage]` endpoints that take user identifiers.

---

## Pattern 20: Federated Share Token as Sole Authentication

**Source**: Nextcloud 35.0.0 audit (federatedfilesharing app)

The `RequestHandlerController` has 8 `#[PublicPage]` methods that accept only a `$token` parameter:
- `createShare`, `reShare`, `acceptShare`, `declineShare`, `unshare`, `revoke`, `updatePermissions`, `move`

```php
#[PublicPage]
public function acceptShare(string $id, ?string $token = null): DataResponse {
    // Only $token authenticates the request!
}
```

**Lesson**: Federation endpoints that use shared secrets/tokens as the only authentication are vulnerable to token brute-force. Check token entropy and rate limiting.

---

## Pattern 21: OAuth2 Token Rotation Race Condition

**Source**: Nextcloud 35.0.0 audit (oauth2 app)
**File**: `apps/oauth2/lib/Controller/OauthApiController.php`

```php
$this->db->beginTransaction();
try {
    $updatedRows = $this->accessTokenMapper->rotateToken(...);
    if ($updatedRows !== 1) {
        $this->db->rollBack();
        // ... error ...
    }
    $appToken = $this->tokenProvider->rotate($appToken, $decryptedToken, $newToken);
    $this->db->commit();
} catch (\Throwable $e) {
    if ($this->db->inTransaction()) { $this->db->rollBack(); }
    $this->tokenProvider->invalidateToken($newToken);
    throw $e;
}
```

**Lesson**: Concurrent token rotation requests can race between the `updatedRows` check and `rotate()`. If `rotate()` succeeds but `updatedRows` check fails for the second request, the token state may be inconsistent.
