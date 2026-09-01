---
name: egress-waf-evasion
description: Diagnose and work around reachability failures during authorized recon — distinguish geo-block vs rate-limit vs bot-manager vs origin-error, manage burned egress IPs, choose the right vantage (residential vs datacenter vs archive/proxy), and fingerprint enterprise edge/gateway stacks (Akamai, Incapsula, F5, IBM DataPower). Use when in-scope hosts return 403/429/500/000 and you need to tell "blocked" from "down", or when a target is geo-restricted.
sources: field_recon (carrier engagement — geo-locked Keycloak, archive.org IP burns, DataPower mTLS gateway)
report_count: 0
---

# Egress & WAF Evasion (authorized recon)

A blocked request is a *diagnosis problem* before it is a bypass problem. Most wasted time in
recon comes from misreading the block. This skill is the decision tree.

## Step 0 — The control fetch (do this before you trust any result)

Steps 1-5 assume you *noticed* the block. The expensive failure is the block you don't notice,
because it renders as a **plausible test result**.

Worked example: a forged-JWT sweep across six services returned a uniform `403`. That reads as
"every service verifies signatures correctly" — a clean negative, exactly what a passing test looks
like. It was an edge ACL rejecting the source IP. The sweep had never reached a single application.
Same trap twice in one engagement, because nothing about the output looked wrong.

**The rule: before concluding anything about a host, fetch a known-good URL on that host in the same
run. Not 200/302/307 → the host is unreachable from this vantage and every result against it is
void.** Cheap, and it is the only thing that catches a silent block.

```bash
ctl () {  # ctl <known-good-url> — run FIRST, and again after any long batch
  c=$(curl -s --compressed -o /dev/null -w '%{http_code}' -m 15 "$1")
  case "$c" in 200|301|302|307) echo "control OK ($c)";;
    *) echo "CONTROL FAILED ($c) — results against this host are MEANINGLESS"; return 1;; esac
}
ctl https://target.example.com/ || exit 1
```

**Which uniform results should trigger suspicion.** Any of these across a batch is a block until the
control proves otherwise — a real application almost never answers a *varied* set of payloads with a
*single* status:

| Batch result | Looks like | Often actually is |
|---|---|---|
| every forged/invalid credential → same 4xx | "auth is solid" | edge ACL, never reached the app |
| every host in a sweep → same code | "consistent hardening" | your IP, not their config |
| every payload incl. the benign one → same error | "input validation" | rate-limit / WAF |

**Self-inflicted throttling is the same bug with a local cause.** After firing list + DELETE + PATCH
in quick succession, a payments service began returning `400 "aguarde uns minutos"` to *everything*,
including the untouched baseline. The IDOR under test appeared to fail safely. It hadn't been tested
at all. **Re-run the benign baseline after any burst; if the baseline degraded, the batch is
inconclusive, not negative.** Record it as inconclusive — a false negative you believe is worse than
a gap you know about, because you never revisit it.

**Corollary — an application error is proof of reach.** `400 Bad Request` from the app means your
packet arrived and was parsed. Do not read app-layer 4xx as "blocked" and retreat; that is a
*successful* connection with a rejected payload, and on a gateway it can be the finding itself
(see [[gateway-layer-attribution]]).

---

## Step 1 — Classify the block by its signature (do not guess)

| Response | Usual meaning | What changes it |
|----------|---------------|-----------------|
| **403** "Access Denied" + `Reference #...errors.edgesuite.net` | Akamai edge ACL / **geo-block** | a *different source IP* in an allowed region (not headers) |
| **403** Cloudflare / Incapsula branded | WAF rule or geo | source IP / passing JS challenge |
| **429** | Rate-limit / IP reputation burn | wait, or a fresh IP; slow down |
| **500 / 000** intermittently, with an injected `<script src="/…">` | **Bot Manager** (Akamai/Imperva) wants the sensor cookie | a *real browser* that executes the sensor JS |
| **412 Precondition Failed** | origin expects a header / mTLS / specific method | the missing precondition (often mTLS) |
| **401 / custom 4xx JSON** | genuine app auth | credentials (out of unauth scope) |
| clean **000** on a direct IP while CDN name resolves | origin firewalled; only the CDN edge is public | nothing external — it's internal-only |

Key discriminator: **geo-blocks and IP-reputation return a stable 4xx; origin-down returns a stable
5xx from an allowed IP.** If a US-egress *datacenter* proxy gets 500 while your IP gets 403, the
target is likely US-geo-locked AND bot-managed (datacenter IP passes geo but fails bot-manager).

## Step 2 — Header spoofing rarely beats geo (know why)

`X-Forwarded-For`, `True-Client-IP`, `X-Real-IP`, `CF-Connecting-IP`, `X-Akamai-Edgescape` almost
never bypass a real geo-block: **Akamai/Cloudflare geo-decide on the real TCP source IP**, not on
a client header. Spoofing can flip 403→500 by reaching a different edge node, but that is noise,
not a bypass. Try it once to confirm, then stop and change the actual egress.

## Step 3 — Choose the right vantage

- **Geo-block** → a *residential or clean* IP in the allowed country (usually US for US carriers).
  A commercial VPN in the wrong region (e.g. EU) may clear one target and not another — geo policy
  is per-target.
- **Bot-manager (500 on API/HTML from an allowed IP)** → a **real browser** from an allowed IP
  (headless with a full JS engine that runs the Akamai `_abck` / Imperva sensor). Datacenter fetch
  proxies (jina, corsproxy, allorigins) pass *geo* if their egress is allowed but still hit the
  bot 500 — they are simple fetchers, not browsers.
- **Passive first** — before burning an IP, try archive/scan sources that already fetched it:
  urlscan.io search, Wayback (`id_` raw bytes), Shodan/Censys banners, certificate transparency.
  These give version/banner/JS without you touching the target. See [[archive-credential-recovery]].

## Step 4 — Protect your egress (IP-burn hygiene)

Recon at volume burns IPs. Rules:
- **archive.org rate-limits hard and bans by IP** across all its endpoints (CDX, `id_`, timetravel)
  once you flood it — pace to a few req/s, and if you get a run of 429s, STOP (further hits deepen
  the ban). It bans the IP, not the method.
- One heavily-used exit gets flagged by *multiple* services at once (Akamai 403 + archive 429 +
  urlscan 403). When several unrelated services block the same IP, the IP is burned — rotate, don't
  retry.
- Keep a **clean US residential** vantage separate from the **bulk-scan** vantage.

## Step 5 — Fingerprint the edge/gateway stack (it tells you the real defense)

Read response headers + cookies to identify the stack — this decides whether an exposed credential
or endpoint is actually exploitable:

| Signal | Component | Implication |
|--------|-----------|-------------|
| `Server: AkamaiGHost`, `Reference #...edgesuite.net` | Akamai edge | geo + bot manager likely |
| `X-CDN: Incapsula`, `visid_incap_*` / `incap_ses_*` cookies | Imperva Incapsula | WAF + bot |
| `BIGipServer<pool>` cookie | F5 BIG-IP LTM | load-balanced origin; node-dependent responses (noise) |
| `X-Backside-Transport: FAIL FAIL` | **IBM DataPower** SOAP gateway | often enforces **client-side auth (mTLS / WS-Security)** at the gateway |
| `snow_adc` server | ServiceNow instance | see ServiceNow unauth-portal testing |

**The high-value inference:** a leaked HTTP-Basic/API credential that returns "anonymous / from
client" through a DataPower or mTLS-fronted gateway is usually **not externally exploitable** — the
gateway authenticates the *client app* via mTLS the attacker can't present. Fingerprint the stack
*before* writing an exposed credential up as exploitable, or you'll file an N/A. See
[[credential-verification]].

## Anti-patterns
- **Reporting a negative you never ran a control for.** The most costly error in this skill.
- Retrying the same burned IP because "maybe it recovered" — it won't within a session; rotate.
- Reporting a 403 host as "protected/secure" — 403 means *reachable but walled*; a different IP may
  open it. Distinguish 403 (walled) from 000 (firewalled/down).
- Concluding "origin down" from a bot-manager 500 — try a real browser from an allowed IP first.
