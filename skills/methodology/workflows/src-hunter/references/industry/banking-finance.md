# Banking / finance industry pentest playbook

> Perspective: black-box, targeting domestic banks (state-owned / joint-stock / city commercial / private) + third-party payment + aggregated payment + internet-finance platforms.
> Data basis: 2,919 real cases in the finance domain, with a 68%-88% high-severity share.

---

## 1. One-line positioning

Vulnerability profile of the banking/finance sector: **funds-class bugs are a small share but high value per instance**, and **the authentication and interface layers are the main battleground**. A single payment-bypass bounty can equal a whole year's earnings from an ordinary SaaS target.

Do not fixate on "online-banking RCE" — that was the game ten years ago. What pays today is:
- signature flaws in third-party / aggregated payment interfaces
- mobile-banking app interfaces (authz is often weaker than the web)
- the "lightweight" business systems of direct banking / WeChat banking
- broken access control in credit / risk-control admin panels

---

## 2. Layered attack-surface model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Layer 1: internet edge                          │
├─────────────────────────────────────────────────────────────────────────┤
│  online banking │ mobile banking │ WeChat banking │ direct banking │ credit-card center │ website/event pages │
│  mini-program   │ app            │ H5             │ official account │ marketing campaigns │ support system   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────┐
│                          Layer 2: interface / channel                    │
├─────────────────────────────────────────────────────────────────────────┤
│  payment interface │ UnionPay channel │ quick pay │ agency debit/credit │ aggregated payment │ open-banking API │
│  card-issuing interface │ risk-control interface │ SMS gateway │ second-factor auth │ digital certificate │ face recognition │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────────────┐
│                          Layer 3: internal systems                       │
├─────────────────────────────────────────────────────────────────────────┤
│  core banking │ credit system │ risk-control system │ anti-money-laundering │ customer management CRM │ reporting system │
│  reconciliation system │ clearing system │ bill system │ derivatives │ internal OA │ mail system │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. High-severity vulnerability distribution (finance-specific)

### 3.1 First tier: funds class (68%-88% high severity)

| Vulnerability type | High-severity share | Bank-specific scenario | Main playbook |
|---------|---------|-------------|--------------|
| Password reset | 88.0% | online/mobile banking login password, transaction password, payment password | `logic-flaws.md` §3.1 |
| Withdrawal | 83.1% | transfer-limit bypass, withdrawal-validation flaws | this file §4.3 |
| Amount tampering | 83.0% | transfer amount, investment amount, repayment amount | `logic-flaws.md` §3.4 |
| Balance tampering | 77.9% | account balance, points, virtual card | this file §4.4 |
| Order tampering | 74.2% | credit-card orders, investment orders | `logic-flaws.md` §3.4 |
| Price tampering | 74.3% | investment product price, value-added services | `logic-flaws.md` §3.4 |
| Payment bypass | 68.7% | quick pay, agency debit/credit, interbank transfer | this file §4.1 |

### 3.2 Second tier: authentication / information class

| Vulnerability type | Cases | Bank-specific scenario |
|---------|-------|------------|
| Weak passwords | 7,513 | online-banking ops panels, ATM monitoring, in-bank OA |
| Broken access | 1,705 | viewing others' accounts / statements / customer info |
| Verification codes | 334 | login, transfer, password reset, face recognition |
| Information disclosure | 4,858 | customer PII / transaction records / credit materials |

### 3.3 Third tier: client / mobile

Bank-specific, rarely covered by generic SRC libraries:

- **Mobile-banking app hardening bypass**: Frida / Objection anti-debugging
- **SSL pinning bypass**: Frida hook
- **Sensitive data in local storage**: sqlite / sharedPrefs / cleartext passwords in memory
- **Reversing signing algorithms**: transaction-request signatures (HMAC / RSA)
- **Hardcoded mini-program secrets**: the AppSecret / signing key inside a WeChat mini-program package

---

## 4. Bank-specific attack scenarios

### 4.1 Third-party / aggregated payment interfaces (a key mine)

```
Attack surface:
├── merchant key disclosure (GitHub/Gitee/outsourced code)
├── async-notification (notify_url) signature flaws
├── sync-callback (return_url) controllable parameters
├── missing second amount validation
├── merchant-number broken access (using merchant A's mch_id with merchant B's key)
└── test payment-gateway credentials (sandbox key used in production)
```

**Probe checklist**:

```bash
# 1. notify_url replay
curl -X POST https://target/pay/notify \
  -d "out_trade_no=ORDER001&total_fee=100&trade_status=SUCCESS&sign=XXX"
# see whether it ships the goods multiple times

# 2. missing-signature-check test
# remove sign / empty sign / use a wrong sign
curl -X POST https://target/pay/notify -d "out_trade_no=ORDER001&trade_status=SUCCESS"

# 3. modify total_fee but keep sign
# (most implementations check sign first, then process the amount, but a few expose the sign algorithm in the frontend)
```

**Key parameters**: `amount` / `total_fee` / `price` / `total` / `out_trade_no` / `trade_no` / `mch_id` / `sign` / `signature` / `appid` / `nonce_str` / `notify_url` / `return_url` / `attach`.

### 4.2 Mobile-banking app

```
App pentest flow:
1. Traffic capture: bypass SSL pinning (Frida / Objection)
2. Reverse analysis: unpack → jadx decompile → reverse the signing algorithm → extract the key
3. Hook testing: bypass face/fingerprint/gesture checks, modify limit checks
4. Interface comparison: app interfaces vs web interfaces (app interfaces often have weaker authz)
5. Internal SDKs: whether the analytics/push/support-IM SDK exposes internal interfaces
```

**Common app authz flaws**:
- The app interface only checks the token, not the role
- The app interface skips the web's WAF / risk control
- The app interface's user-agent / client-type check can be bypassed (forge `User-Agent: BankApp/1.0`)

See `playbooks/mobile.md`.

### 4.3 Withdrawal / transfer (83.1% high severity)

```
Transfer-interface test matrix:
1. Negative amount
   amount = -1000  → the payee is debited, the payer is credited
2. Limit bypass
   - change the amount data type: number → string ("100")
   - use scientific notation: 1e10
   - use tiny decimals: 0.001 × 1000 times (to reach the limit)
3. Double spend / race
   concurrent withdrawals of N times the balance limit
4. Change the payee (to_account / payee_id)
   redirect the transfer target to an attacker-controlled account
5. State machine
   - set status=SUCCESS (forge a completed state)
   - replay a successful transfer callback
```

**Red line**:
- Do not actually transfer to a stranger's account. All amount tests use the researcher's own account → their own account.
- Stop at a tiny amount (0.01 yuan).
- Screenshot any "refund" / "reversal" operation immediately as evidence, for later reconciliation.

### 4.4 Balance / points / coupons

| Attack | Method |
|------|------|
| Negative transfer | `amount=-100` |
| Balance-computation bypass | change the `balance` parameter in the client request |
| Decimal-precision flaw | withdraw 0.001 × 10000 times (rounding accumulation) |
| Coupon generation | call the card-issuing interface arbitrarily |
| Points exchange rate | change the "1 point = X yuan" value in the redemption interface |

Real cases:
- Shenzhou Zhuanche recharge flow skips the credit-card transaction password (cash-out bypass)
- Yupaopao app arbitrary-user login can affect balances (sign bypass)
- Bank of Ningbo direct banking views any card's balance
- A validation-logic issue at Ping An led to managing product prices

### 4.5 Verification bypass (finance-sector edition)

#### SMS verification codes

```
├── Brute force: 4-6 digits + 100 threads, cracked in 30 seconds
├── Concurrency: bypass the rate limit
├── Reuse: use the same code multiple times
├── Echo: leaked in the response
├── Universal: 0000 / 1234 during the test period
└── Cross-flow: the registration-flow code used for reset
```

#### Face recognition

```
├── Photo attack: printed photo / screen replay
├── Video attack: blink / head-shake video
├── Hook the return value: Frida hook the face-check function
├── Interface replay: replay a successful face-API response
└── Replace the face data: intercept and modify the face_data field
```

#### USB shield / digital certificate

> Most USB-shield attacks were superseded after 2020 by biometrics + a hardware TEE; only a small amount remains online in corporate online banking.

#### Transaction signing

```
├── Signing key hardcoded / found via GitHub
├── Key fields not covered by the signature (e.g. changing amount passes with sign unchanged)
├── Optional signature check (removing the sign field passes directly)
└── Signing-algorithm downgrade (RSA → HMAC → MD5 → none)
```

---

## 5. High-value target assets

| Target system | Value | Black-box visibility |
|---------|-----|-----------|
| Core banking system | ⭐⭐⭐⭐⭐ | very low (internal) |
| Credit system | ⭐⭐⭐⭐ | medium (some approval/query interfaces exposed externally) |
| Risk-control system | ⭐⭐⭐⭐ | low |
| Anti-money-laundering system | ⭐⭐⭐⭐ | low |
| CRM / KYC | ⭐⭐⭐ | medium |
| Support / ticketing system | ⭐⭐ | high (easiest to break into) |
| Marketing campaign / H5 | ⭐⭐ | very high (most common entry point) |
| Credit-card center | ⭐⭐⭐⭐ | medium |

**Practical path**: from a marketing-campaign H5 / support system → credential stuffing / broken access → customer PII → pivot to the credit-card center → the credit system.

---

## 6. GetShell / lateral movement

### 6.1 Edge devices

```
VPN / gateway vulnerabilities:
├── Pulse Secure CVE-2019-11510
├── Fortinet CVE-2018-13379
├── Citrix CVE-2019-19781
├── Sangfor VPN arbitrary password reset
└── DBAppSecurity / Venustech / Topsec device weak passwords

CDN origin pull:
├── find the real IP (fofa "icon_hash" / historical DNS)
├── hit the origin directly
└── config layer: Host header injection
```

### 6.2 Third-party outsourcing / supply chain

```
Supply-chain paths:
├── outsourcing company → dev/test environment → production
├── device vendor → preset accounts
├── service provider → SMS / identity-verification / anti-fraud SDK
└── printing house / card vendor → card numbers / encryption keys
```

### 6.3 GetShell priority (finance scenarios)

```
1. Struts2 RCE (S2-045/046/048/052/057/059) — common in old bank systems
2. WebLogic deserialization (CVE-2017-10271 / 2019-2725 / 2020-14882)
3. Shiro deserialization (rememberMe) — common in CN OA / ticketing systems
4. Fastjson RCE 1.2.x — common at the interface layer
5. Log4Shell — internal logging frameworks
6. File-upload bypass — OA / CMS editors
```

See `playbooks/rce.md` and `playbooks/file-upload.md`.

---

## 7. Practical checklist

### 7.1 Information gathering
- [ ] Subdomain enumeration (including IPv6)
- [ ] Download and analyze the app / mini-program / official account
- [ ] GitHub / Gitee / Code Cloud code search (company name + committer email)
- [ ] Historical interfaces via the Wayback Machine
- [ ] H5 pages in the WeChat mini-program + official account bottom menu
- [ ] Marketing-campaign pages / Double-11 / Spring Festival red-packet pages
- [ ] Subdomains of the support / ticketing system
- [ ] The credit-card center's standalone sub-site

### 7.2 Vulnerability probing
- [ ] Weak passwords (ops panels / OA / mail)
- [ ] Business logic (payment / transfer / password reset / credit-card installments)
- [ ] Broken access (horizontal / vertical)
- [ ] Interface security (signature / encryption / replay)
- [ ] App client security (unpacking / pinning / local storage)
- [ ] Third-party payment notify_url flaws
- [ ] Verification codes (SMS / graphical / face)
- [ ] Arbitrary-X sub-authorization (arbitrary account / arbitrary operation)

### 7.3 Deep exploitation
- [ ] Payment amount tampering (own account → own account)
- [ ] Concurrent verification-code brute force
- [ ] Face-recognition interface replay
- [ ] Concurrency race conditions (withdrawal / coupon)
- [ ] Internal-interface broken access (only where provable)

---

## 8. Real-case fingerprints (finance)

| Case | One-line fingerprint | Vulnerability class |
|------|----------|---------|
| Zhongyuan Bank GetShell (affecting Tenpay / Alipay) | edge web RCE → internal network | edge RCE |
| Allinpay file-traversal read (Oracle EBS) | `/oracle.../read?path=` | arbitrary file read |
| A third-party payment institution SOAP injection (DBA + 9 databases) | WSDL exposed + WS injection | SQLi |
| Shenzhou Zhuanche recharge without transaction password | client skips the PIN | payment bypass |
| Yupaopao app arbitrary account | sign field empty-value bypass | arbitrary account |
| Bank of Ningbo direct banking views any card balance | API does not check account ownership | IDOR |
| Baixing Pharmacy 20M PII + balance | weak password + backend broken access | weak password |
| Ping An 1M PII + price management | authz + missing price validation | broken access |

---

## 9. Red lines (finance-sector SRC edition)

- **Never**: transfer to a stranger's account. Stop at a researcher's own-to-own transfer.
- **Never**: actually test credit-card fraud / cash-out / physical redemption.
- **Never**: use a real customer's ID card / bank card / phone number for testing. Prepare 5+ test cards in the researcher's own name.
- **Never**: scan a bank's public IP ranges (potential violation of the Critical Information Infrastructure Security Protection Regulations). Only scan assets explicitly authorized by the bug-bounty program.
- **Never**: leave a webshell / cron / SSH public key in production. Stop at proving RCE, clean up immediately, and note the cleanup time in the report.
- **Never**: exfiltrate data (even to the vendor). Paste only 1-3 redacted samples in the report.

---

## 10. Links to methodology / dictionaries

```
methodology/05-srctimebox-priority.md   →  the 88% / 83% priority bugs in finance
playbooks/logic-flaws.md                 →  payment / order / password-reset details
playbooks/arbitrary-x-authz.md           →  arbitrary account (86.4%) / arbitrary operation
playbooks/oauth-saml-jwt.md              →  SSO / JWT / federated identity
playbooks/mobile.md                      →  mobile-banking app
playbooks/race-conditions.md             →  concurrent withdrawal / coupons
dictionaries/default-credentials-cn.md   →  CN default credentials for online banking / OA / monitoring
dictionaries/chinese-srcfingerprints.md  →  common finance component fingerprints (Seeyon OA / Yonyou / Kingdee, etc.)
```
