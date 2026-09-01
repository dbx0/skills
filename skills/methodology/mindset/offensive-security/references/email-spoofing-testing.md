# Email Spoofing Testing (SPF/DMARC)

Quick workflow for testing SPF, DKIM, and DMARC email security during bug bounty recon.

---

## DNS Verification

```bash
# Check SPF record
host -t TXT target.com | grep "v=spf1"

# Check DMARC
host -t TXT _dmarc.target.com

# Check MX records
host -t MX target.com
```

**What to look for:**
- **No SPF record** → Any server can send as this domain
- **DMARC `p=none`** → No enforcement even if SPF/DKIM fails
- **DMARC `p=quarantine` or `p=reject`** → Enforcement active

---

## Sending a Test Email (swaks)

```bash
# Install swaks (if not available)
apt-get install -y swaks

# Send spoofed email directly to the MX server
swaks --to recipient@test.com \
      --from spoofed@target.com \
      --header 'Subject: Test - no SPF' \
      --body 'This is a spoofed email' \
      --server aspmx.l.google.com:25
```

**Server selection:**
- For Gmail/Google Workspace: `aspmx.l.google.com:25` (try `--tls`)
- For Mailinator (testing): `mail.mailinator.com:25`
- For Yahoo: `mta7.am0.yahoodns.net:25`
**Note:** Gmail enforces SPF/DKIM on their MX servers even when DMARC is `p=none` (block email `5.7.26`). Test against non-Google providers to confirm spoofing works.

**⚠️ Pitfall — Gmail IPv6 PTR rejection:**
Gmail may reject spoofed emails with `550-5.7.1 Gmail has detected that this message does not meet IPv6 sending guidelines regarding PTR records and authentication` when sending from a VPS IPv6 address without proper reverse DNS. This is Gmail-specific behavior. To properly test:
1. Force IPv4 with `swaks --server <mx>:25 --inet4` if available
2. Use a mail provider that has proper PTR records
3. Test against non-GMX providers (Outlook, Yahoo, self-hosted) to confirm acceptance

**⚠️ Pitfall — Disposable email services block spoofed mail regardless of SPF/DKIM:**
Mailinator (`mail.mailinator.com`) and similar disposable email providers maintain internal abuse/spam filters that reject spoofed emails even when the sending domain has no SPF/DKIM/DMARC at all. Error: `500 This Email is flagged for abuse`. This is the provider's own filtering, NOT a DNS-level control. To properly test spoofing:
1. Send to a real inbox (Gmail, Outlook, Yahoo) — Gmail may reject via SPF/DKIM policy, but Outlook/Yahoo often accept
2. Send from your own SMTP server (e.g., your VPS) directly to the target MX
3. Use `swaks --server <target-MX>:25` to bypass intermediary filtering
4. If the target domain has no MX records, connect directly to the A record IP on port 25
5. Best approach: use your own VPS (with Postfix) to send directly — full control over both sides

**MX Records for Major Providers:**
```
Gmail:      gmail-smtp-in.l.google.com (priority 5)
Yahoo:      mta5.am0.yahoodns.net
Outlook:    outlook-com.olc.protection.outlook.com
ProtonMail: mail.protonmail.ch
iCloud:     mx01.mail.icloud.com
Zoho:       smtpin.zoho.com
```
Find MX for any domain: `dig +short <domain> MX`

**Note:** Gmail enforces SPF/DKIM on their MX servers even when DMARC is `p=none` (block email `5.7.26`). Test against non-Google providers to confirm spoofing works.

---

## What Proves the Finding

The SMTP conversation logs showing:
```
MAIL FROM:<spoofed@target.com> → 250 Ok ✅
RCPT TO:<recipient@test.com> → 250 Ok ✅  
DATA → 250 Ok ✅ EMAIL ACCEPTED
```

This proves the receiving server accepted the unauthenticated email.

---

## Report Wording (Portuguese)

> **Spoofing de email — Ausência de SPF e DMARC sem enforcement**
>
> O domínio `target.com` não possui registro SPF e o DMARC está configurado como `p=none`. Isso permite que qualquer pessoa envie emails falsos se passando pelo domínio.
>
> **Verificação DNS:**
> - SPF: Nenhum registro SPF encontrado
> - DMARC: `v=DMARC1; p=none;`
>
> **Provedores que aceitariam:** Mailinator ✅ aceito
> **Provedores que bloqueiam por política própria:** Gmail (5.7.26)
>
> **Impacto:** Phishing direcionado a funcionários, clientes e parceiros.