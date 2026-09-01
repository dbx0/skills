# Environment-Shimming Rules

- Only shim objects that page evidence has proven are actually needed
- Shim one minimal causal unit at a time
- Shim the value first, then the function shell, then the return-object contract
- After every patch, re-run and record whether the first divergence has moved earlier
