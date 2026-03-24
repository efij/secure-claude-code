# Security Baseline

- Never hardcode secrets, internal hosts, or live connection strings in tracked files.
- Prefer environment variables, secret managers, or local-only config files that stay out of git.
- Treat `.env`, deploy manifests, workflow files, cloud config, and auth material as high-risk edits.
- Before any push, scan the diff for credentials, private network references, and machine-specific paths.
- Do not weaken safety controls to "get unstuck". Fix the root cause instead of bypassing hooks or review.

