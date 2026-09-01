# Business Logic Vulnerability Patterns

## What Makes Business Logic Bugs Special

- Nearly impossible for automated tools to find consistently
- Require understanding of the application's intended workflow
- Duplicate rates are lowest — most hunters skip these
- Impact can range from informational to critical

## Common Patterns

### Race Conditions
**Concept:** Two requests for the same limited resource sent simultaneously.
**Tool:** Burp "Send group in parallel" (Turbo Intruder for advanced cases).
**Targets:**
- Coupon codes (single-use codes applied multiple times)
- Referral bonuses (same referral counted multiple times)
- Stock purchases (buy more than available)
- Loyalty points (redeem same points multiple times)
- Account balance (double-spend)

**Test:** Send 10 identical requests simultaneously. Did the action execute more than once?

### Negative Values
**Concept:** Enter negative numbers where only positive values are expected.
**Targets:**
- Shopping cart quantities (-1 items → negative price)
- Bank transfers (transfer -$100 → gain $100)
- Refund amounts
- Point redemption

**Test:** Set quantity to -1, -0.01, or very large negative numbers.

### Integer Overflow
**Concept:** If price = int and amount = int and total = int, then price * amount can overflow.
**Impact:** May result in the target returning money to the attacker.
**Test:** Multiply two large integers near the max value for the data type.

### Workflow Bypass
**Concept:** Skip a required step in a multi-step process.
**Targets:**
- Skip payment step in checkout
- Skip email verification
- Skip identity verification
- Skip terms acceptance
- Access step 3 directly without completing steps 1-2

**Test:** Capture the request for the final step and replay it without completing intermediate steps.

### State Manipulation
**Concept:** Send a request that's only valid in state A while the resource is in state B.
**Targets:**
- Approve an already-approved item
- Cancel a cancelled order
- Re-verify a verified account
- Re-submit a submitted form

### Limit Bypass
**Concept:** A feature limits you to N items — can you send N+1?
**Targets:**
- "Maximum 5 items" → try 6
- "One coupon per user" → try 2
- "Rate limit: 10 requests/min" → try 11
- "Maximum file size: 10MB" → try 10.1MB

### Privilege Gates (Client-Side)
**Concept:** Does the price come from the client? Does the role come from the client?
**Targets:**
- Hidden form fields with price values
- Client-side role checking
- Disabled UI elements (but JS functions still work)
- Read-only form fields that can be modified

**Test:** Intercept and modify all client-side values before submission.

### Duplicate Registration
**Concept:** Registering with an existing username/email takes over the account.
**Impact:** Account takeover — critical severity.
**Test:** Register with the same email or username as an existing user.

### Import Overwrite
**Concept:** Importing products/data with the same name as existing entries overwrites them.
**Impact:** Even if the entries belong to other users and you shouldn't be able to modify them.
**Test:** Import data with the same identifiers as other users' data.

### Client-Side Calculations
**Concept:** Price calculations done in JavaScript rather than server-side.
**Impact:** Modify prices before they're submitted.
**Test:** Intercept the request and change price/amount/total values.

### Coupon/Promotion Abuse
**Concept:** Stack multiple coupons, apply expired codes, reuse single-use codes.
**Test:**
- Apply the same coupon twice
- Apply multiple different coupons
- Modify coupon codes to find valid ones
- Use expired coupons

## Impact Assessment

| Scenario | Typical Severity |
|---|---|
| Client-side price manipulation | Critical |
| Negative values → money gain | Critical |
| Integer overflow → money gain | Critical |
| Duplicate registration → ATO | Critical |
| Race condition on payments | High |
| Workflow bypass (skip payment) | High |
| Import overwrite (other users' data) | Medium-High |
| Coupon abuse | Medium |
| Username enumeration | Low (unless usernames are secret) |
| Like/comment count manipulation | Low |

## Testing Methodology

1. **Map the business flow:** Understand how the application is supposed to work
2. **Identify assumptions:** What does the developer assume about user behavior?
3. **Break assumptions:** Test what happens when users behave unexpectedly
4. **Test boundaries:** Min/max values, negative values, zero, very large numbers
5. **Test sequences:** Skip steps, repeat steps, reverse steps
6. **Test concurrency:** Race conditions on shared resources
7. **Test state:** What happens when you're in the wrong state for an action?
