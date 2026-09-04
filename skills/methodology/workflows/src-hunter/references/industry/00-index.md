# Industry-vertical playbooks — master index

> "Target-oriented" playbooks organized by industry, mapping to each industry's asset inventory + high-value vulnerability distribution.
> Relationship to `playbooks/`:
> - `playbooks/` is organized by **vulnerability type** (IDOR / RCE / SSRF / ...).
> - `industry/` is organized by **target industry** (banking / telecom / ...) → given a target, read this directory first for the approach, then open the matching type playbook.

---

## How to use

```
Got a target → identify the industry  →  open the matching industry playbook
                          │
                          ├─ layered attack-surface map (asset inventory)
                          ├─ vulnerability types with high value specific to the industry
                          └─ probe paths specific to the industry

  Target asset already on the attack-surface map → jump to the matching type playbook to carry out exploitation
  Target asset not there → map sub-products to expand scope (GitHub / app / WeChat mini-program / subdomains)
```

---

## Industry directory

| File | Main assets | Primary vulnerability types | High-severity band |
|------|---------|-------------|----------|
| `banking-finance.md` | online banking / mobile banking / WeChat banking / direct banking / credit-card center / third-party payment / aggregated payment | amount tampering (83%) / payment bypass (68.7%) / password reset (88%) | top band |
| `telecom-isp.md` | web hall / mobile hall / BOSS / SP-CP platform / SMS gateway / IoT SIM platform / NMS | broken access (62.3%) / weak passwords (58.2%) / unauthenticated access / edge devices | mid-high band |

---

## The shared skeleton of an industry approach

Every industry playbook is written to this structure:

```
1. Layered attack-surface model (three asset layers: internet / interface channel / internal systems)
2. High-severity vulnerability types specific to the industry (with WooYun case counts)
3. Attack surface specific to the industry (hard to find in generic OWASP / H1 playbooks)
4. GetShell / lateral-movement paths (by priority)
5. Practical checklist (information gathering / vulnerability discovery / deep exploitation)
```

---

## Relationship to SRC platforms

| Industry | Matching SRC entry points |
|------|--------------|
| Banking / finance | each bank's SRC (CMB / CCB / Ping An / Ant / Alipay / UnionPay / Tenpay) + Butian finance program + HVV finance sector |
| Telecom / ISP | each carrier's SRC (Mobile / Unicom / Telecom / Radio-TV) + HVV carrier sector |

**Red line**: finance and telecom are both critical infrastructure, so evidence discipline is stricter than generic SRC — do not write, delete, modify, or leave a webshell. See `methodology/03-evidence-discipline.md`.

---

## Links to methodology / dictionaries

```
methodology/05-srctimebox-priority.md   →  select the priority bugs within an industry by time box
playbooks/<specific type>.md             →  carry out the probe/exploitation for a vulnerability type
dictionaries/default-credentials-cn.md   →  default credentials of CN vendors within the industry
dictionaries/chinese-srcfingerprints.md  →  component fingerprints and default paths within the industry
```
