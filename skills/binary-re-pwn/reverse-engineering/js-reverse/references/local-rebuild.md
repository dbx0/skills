# Local Reproduction

Confirm the following on the page side before returning to Node:

- The real entry function
- The call order
- The parameter sources
- The browser objects it depends on
- Whether it depends on time, random numbers, storage, cookies, UA, canvas, or crypto

Reproduce minimally first, then shim the environment step by step; do not simulate the whole browser at once.
