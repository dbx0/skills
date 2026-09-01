# Smart Contract Judging — 4-Gate Evaluation

Every deduplicated smart.contract finding passes four sequential gates. Fail any gate → **REJECTED** or **DEMOTED** to LEAD. Later gates are not evaluated for failed findings.

---

## Gate 1 — Refutation

Construct the strongest argument that the finding is wrong. Find the guard, check, or constraint that kills the attack — quote the exact line and trace how it blocks the claimed step.

- **Concrete refutation** (specific guard blocks the exact claimed step) → **REJECTED** (or **DEMOTE** if a code smell remains worth investigating)
- **Speculative refutation** ("probably wouldn't happen", "likely intended") → **clears**, continue to Gate 2

---

## Gate 2 — Reachability

Prove the vulnerable state exists in a live/deployed system.

- **Structurally impossible** (enforced invariant prevents the state) → **REJECTED**
- **Requires privileged actions outside normal operation** (owner must misconfigure, multi-sig must collude) → **DEMOTED**
- **Achievable through normal usage** (fee-on-transfer tokens, rebasing, common admin actions) → **clears**, continue to Gate 3

---

## Gate 3 — Trigger

Prove an unprivileged (or minimally privileged) actor can execute the attack profitably.

- **Only a trusted role can trigger** → **DEMOTED** (report as medium/low, not critical)
- **Costs exceed extraction** (gas/capital > gain) → **REJECTED**
- **Unprivileged actor can trigger profitably** → **clears**, continue to Gate 4

---

## Gate 4 — Impact

Prove material harm to an identifiable victim.

- **Self-harm only** (attacker loses own funds, no other victim) → **REJECTED**
- **Dust-level, non-compounding, no cascade** → **DEMOTED** to low/informational
- **Material loss to identifiable victim** (funds drained, protocol shutdown, data breached) → **CONFIRMED**

---

## Severity Adjustment After Gates

After all four gates clear, adjust severity downward if:
- Requires specific timing (e.g., within 1 block window): **-1 severity level**
- Requires non-trivial capital (>$100K flash loan for medium-value target): **-1 severity level**
- Impact is bounded (attacker can profit but not drain entire pool): **-1 severity level**
- Fix already deployed on mainnet but not in reviewed commit: **DEMOTE** + note

---

## LEAD Promotion Rules

1. **Cross-contract echo:** Same root cause confirmed in Contract A → promote in Contract B where identical pattern appears (confidence 75).
2. **Multi-agent convergence:** 2+ agents flagged same area, finding demoted (not rejected) → promote to FINDING at confidence 75.
3. **Partial path completion:** Only weakness is incomplete trace, but path is reachable and unguarded → promote at confidence 75, no fix required.
4. **Cross-feature:** Confirmed auth bypass in endpoint A enables IDOR in endpoint B → chain and promote.

---

## Smart Contract Safe Patterns (Do NOT Flag)

- `unchecked` in Solidity 0.8+ with correct reasoning
- Explicit narrowing casts in 0.8+
- `MINIMUM_LIQUIDITY` burn on first deposit
- `SafeERC20` usage
- `nonReentrant` (flag only cross-contract reentrancy)
- Two-step admin transfer pattern
- Consistent protocol-favoring rounding without compounding effect
- Ecosystem-standard unauthenticated operator RPC
- Plaintext local signer/CL↔EL communication (default dev convenience)
- JWT without `exp` when `iat` freshness is enforced
- Version/health endpoints without auth
- No CORS headers on non-browser APIs
