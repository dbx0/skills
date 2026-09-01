# Shell Script Security Audit Patterns

Adapt the source-code-audit methodology for bash/sh scripts. Pi-hole, OMV, and many Linux projects are shell-script-heavy.

## Dangerous Patterns in Shell Scripts

### 1. Unquoted Variables (Word Splitting + Glob Injection)

```bash
# Vulnerable - unquoted $var
rm -f $filename
cat $user_input > /tmp/file
sed -i "s/$pattern/$replacement/" "$file"

# Safer
rm -f "$filename"
```

**Grep pattern:**
```bash
grep -rn 'echo $' --include="*.sh" | grep -v '"\$'
grep -rn 'rm \$' --include="*.sh" | grep -v '"\$'
grep -rn 'cat \$' --include="*.sh" | grep -v 'cat <<' | grep -v '"\$'
```

### 2. Variable Interpolation in sed Expressions

```bash
# Vulnerable - $key and $value injected into sed pattern
sed -i "/^${key}=/c\\${key}=${value}" "${file}"
```

If `$value` contains `/`, `\`, `&`, or `\n`, the sed command breaks or writes unexpected content.

**Grep pattern:**
```bash
grep -rn 'sed.*\${\|.*\${\|c\\\\\$' --include="*.sh"
```

### 3. eval with Variable Content

```bash
# Dangerous even with validation
eval "${key}=\${value}"
```

Validate: Is the key allowlisted? Is the value character-restricted? Check the validation regex.

**Grep pattern:**
```bash
grep -rn 'eval ' --include="*.sh"
```

### 4. curl | bash Pattern

```bash
curl -sSL https://example.com/install.sh | bash
```

Check: Does the script verify its own integrity before execution? Are downloads verified with checksums?

### 5. curl Downloading Without Checksum Verification

```bash
curl -sSL "$url" -o /usr/bin/binary

# Better
curl -sSL "$url" -o binary
curl -sSL "$url.sha256" -o binary.sha256
sha256sum -c binary.sha256
```

Check: Is the hash algorithm SHA1 (weak) or SHA256? Is the hash downloaded over the same channel?

### 6. URL Validation Bypass

```bash
regex="[^a-zA-Z0-9:/?&%=~._()-;]"
if [[ "${check_url}" =~ ${regex} ]]; then
    echo "Invalid"
fi
```

Check: Does the regex allow `;`, `|`, `&`, `>`, `<`, backtick? These are harmless in URLs but dangerous if the value is later used in shell contexts.

### 7. file:// Protocol Handling

```bash
file_path=$(echo "${url}" | cut -d'/' -f3-)
if [[ -f ${file_path} ]]; then  # unquoted!
    ...
```

Check: Is there path validation beyond existence checks? Can an attacker point to sensitive files?

**Grep pattern:**
```bash
grep -rn 'file:///\|file:/' --include="*.sh"
```

### 8. Command Injection via Array Expansion

```bash
custom_arg="$domain:$port:$ip"
curl ... ${customUpstreamResolver:+${customUpstreamResolver}} ...
```

If `$domain` contains spaces, the single `--resolve` argument splits into multiple args.

**Grep pattern:**
```bash
grep -rn 'resolve\|customArg\|customOpt' --include="*.sh" | grep -v '//'
```

### 9. Password/Secret in Command-Line Arguments

```bash
pihole-FTL --config password "${PASSWORD}"
```

Any local user can read `/proc/<pid>/cmdline` to see the password in plaintext.

**Grep pattern:**
```bash
grep -rn 'password\|passwd\|secret\|token\|api_key' --include="*.sh" | grep -i 'config\|--\|-p\|set'
```

### 10. Temporary File Race Conditions

```bash
tmpFile="$(mktemp)"
mv "${tmpFile}" "${tmpFile%.*}.gravity"
# Window where symlink attack is possible
```

More secure: use `mktemp -d` for a private directory, or use file descriptors.

### 11. Password Entropy Analysis

```bash
pw=$(tr -dc _A-Z-a-z-0-9 </dev/urandom | head -c 8)
```

64-character alphabet, 8 chars = ~48 bits entropy. NIST recommends minimum 64 bits for passwords.

**Grep pattern:**
```bash
grep -rn 'head -c\|tr -dc.*urandom' --include="*.sh"
```

### 12. Unsanitized Input to grep/sed/awk

```bash
tail -f $LOGFILE | grep --line-buffered -- "${1}"
```

Check: Is `$1` a regex or literal string? `grep` treats it as regex — crafted input can cause ReDoS.

## Shell Script Audit Checkpoint

When auditing a shell-script project, always check:

1. **Install script**: Is it `curl | bash`? Does it verify itself?
2. **Download handler**: Are binaries checked with SHA256 (not SHA1)?
3. **Password generation**: Entropy quality? Printed to logs?
4. **Password storage**: Passed on command line (visible in /proc)?
5. **Config file parsing**: Any `eval` of file content?
6. **sed/awk with variables**: Is user data interpolated?
7. **URL validation**: Regex too permissive? `;` and `|` allowed?
8. **File protocol support**: `file://` paths validated?
9. **Unquoted variables**: `$var` vs `"$var"`?
10. **Privilege escalation**: Does the script re-exec as root via sudo?
