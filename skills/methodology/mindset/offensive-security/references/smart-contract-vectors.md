# Smart Contract Attack Vectors (Multi-Chain)

## EVM / Solidity

### Reentrancy
- Single function: state updated after external call
- Cross-function: Function A updates state, Function B reenters via same external call
- Cross-contract: External call to untrusted contract triggers callback into caller
- Read-only: view functions returning stale state during reentrant call (oracle attacks)

### Integer Arithmetic
- Overflow/underflow: pre-0.8 Solidity or `unchecked` blocks
- Truncation: `uint256 → uint128 → uint64` downcasts without range check
- Multiplication before division: `(a / b) * c` loses precision vs `(a * c) / b`
- Division by zero: unchecked denominator
- `mulDiv` rounding direction: protocol-favoring vs user-favoring

### Signature & Replay
- Missing `chainId` in signed messages → cross-chain replay
- Missing `nonce` → same-chain replay
- `ecrecover` returns `address(0)` on invalid sig → not checked
- Signature malleability: `s > secp256k1n/2`
- Signature front-running: attacker copies pending sig and submits first

### Access Control
- Unprotected initializer on implementation contract
- Inconsistent guards: sibling functions, one has `onlyOwner`, other doesn't
- `tx.origin` used for authorization
- Uninitialized proxy: implementation self-destruct via `delegatecall`
- UUPS: `_authorizeUpgrade` not guarded

### Oracle Manipulation
- Spot price: AMM reserve ratio used directly, skewed by large swap
- TWAP: short window (1-5 blocks) manipulable with sufficient capital
- Chainlink stale: `updatedAt` not checked against staleness threshold
- Multi-oracle fallback: primary fails → falls back to manipulable secondary

### Flash Loan Attacks
- Borrow → manipulate price → use as collateral → borrow real assets → repay
- Borrow → drain liquidity → trigger artificial liquidation → profit
- Governance: borrow voting tokens, pass malicious proposal, repay

### Proxy / Upgrade
- Storage slot collision: proxy admin slot overlaps implementation storage
- Implementation callable directly (bypasses proxy's access control wrapper)
- Upgrade without timelock: owner upgrades to malicious implementation instantly
- EIP-1967 slot compliance check

### Cross-Chain / Bridges
- Message replay across domains: missing `(nonce, sourceDomain, destDomain)` validation
- Attester/relayer single point of failure
- Replace-before-revoke gap: both old and new attester valid during window
- Orphaned roles: minters/attesters remain active after replacement

### General EVM
- Unchecked return values from low-level `call`/`delegatecall`/`staticcall`
- Block timestamp dependence for critical logic
- Predictable randomness (`blockhash`, `block.timestamp` as entropy)
- Denial of service: unbounded loop, forced revert, block gas limit
- First depositor inflation attack on vault contracts

---

## Move / Aptos

### Resource & Capability Model
- Missing `acquires` annotation → undefined behavior
- Capability passed as value → can be copied or dropped unexpectedly
- `borrow_global_mut` on resources not owned by caller
- Object type confusion: attacker passes wrong object type to function expecting specific type
- Generic type `T` not constrained → attacker passes arbitrary coin type

### Access Control
- `upgrade_policy` too permissive (`compatible` vs `immutable`)
- Upgrade capability stored in publicly accessible resource
- `set_operator`/`set_voter` missing authorization on capability object
- Missing zero-address guard on role functions
- Freeze/pause flag not checked in all critical functions

### CCTP / Cross-Chain (Aptos-specific)
- Single attester threshold: 1 compromised key drains bridge
- `replace_attester` race: attacker front-runs legitimate replacement
- Minter allowance not reset on `remove_minter` → orphaned allowance spendable
- `burn_with_caller_address` caller not validated against stored message sender

---

## Solana / Anchor

### Account Validation
- Missing owner check: account not verified as owned by expected program
- Missing signer check: expected signer not verified
- Missing `has_one` or `constraint`: attacker substitutes arbitrary accounts
- PDA seed collision: two different inputs produce same PDA
- Non-canonical bump seed: attacker uses different bump for same PDA

### CPI (Cross-Program Invocation)
- Unchecked CPI target: calling program passed as account without ID verification
- Signer privilege escalation: calling program's signer seeds not validated
- Token account owner not validated (attacker creates account owned by their key)

### Token Program
- Wrapped SOL not unwrapped at end of instruction → locked funds
- Missing freeze authority check

---

## TRON

- TRC20 `transferFrom` without allowance check
- `int` overflow in `mulDiv` (pre-0.8 patterns common in TRON contracts)
- `block.number` used as timestamp substitute (manipulable)
- Stake 2.0 resource ceiling: exceeding bandwidth/energy silently fails (no revert)
- `eth_call` with `pending` block tag falls through to `latest` → stale state

---

## Cross-Chain / Bridge (All Chains)

- Message replay across domains
- Missing destination domain validation
- Attester/relayer single point of failure
- Replace-before-revoke gap window
- Bridge message race condition
