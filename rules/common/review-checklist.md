# Review Checklist

- Review for secrets leakage, destructive git operations, and accidental config churn.
- Check sensitive diffs twice: once for intent, once for unintended exposure.
- Confirm every new dependency, script, or workflow change has a clear reason.
- If a false positive appears in a security check, add a narrow allowlist rule instead of disabling the module.

