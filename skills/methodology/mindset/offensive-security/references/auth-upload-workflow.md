# Authenticated File Upload Testing on React SPAs

## Pattern: Browser XHR + Curl Upload

When testing file upload on authenticated React SPAs (especially AWS Cognito), the upload endpoint requires session cookies only available in the browser. Use a hybrid approach:

### Workflow

1. **Login via browser** (handle React Cognito login)
2. **Get presigned URL via browser XHR**:
   ```javascript
   const res = await fetch('/api/upload/thumbnail-url', {
     method: 'POST',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({'contentType': 'image/svg+xml', 'extension': '.svg'})
   });
   const data = await res.json();
   // data.putUrl = presigned S3 upload URL (valid ~5 min)
   // data.publicUrl = public CDN URL
   ```
3. **Upload via curl** using the presigned URL:
   ```bash
   curl -s -X PUT "<putUrl>" -H "Content-Type: image/svg+xml" --data-binary @/tmp/payload.svg
   ```
4. **Update profile** with the public URL:
   ```javascript
   await fetch('/api/me/profile', {
     method: 'PUT',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({'avatarUrl': data.publicUrl})
   });
   ```

### CORS Gotcha

When SVG is opened as a standalone document, all embedded resources must be on the **same origin** OR the remote domain must send `Access-Control-Allow-Origin: *`. **Best practice**: upload ALL assets (SVG, images, audio) to the **same CDN**.

### example-auto.tld Specifics

- Upload: `POST /api/upload/thumbnail-url` (requires auth)
- Profile: `PUT /api/me/profile` with `{"avatarUrl": "CDN_URL"}`
- CDN: `d3vlaibgctkr2s.cloudfront.net`
- No content-type or magic byte validation on upload
- CDN assets are publicly accessible (no auth required)
