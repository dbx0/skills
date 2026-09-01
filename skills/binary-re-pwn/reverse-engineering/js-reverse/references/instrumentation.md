# Instrumentation

Prefer lightweight observation:

- XHR/Fetch breakpoints
- Function-text breakpoints
- After pausing, read the call stack and local variables

Only escalate to heavier source rewriting or local instrumentation when lightweight observation is not enough.
