---
description: Tune Secure Claude Code with stricter or lighter profiles and explain individual guards.
disable-model-invocation: true
---

Use this skill when the user wants to tighten, relax, or understand the local policy.

- Switch profiles:
  - `./bin/secure-claude-code install strict`
  - `./bin/secure-claude-code install balanced`
  - `./bin/secure-claude-code install minimal`
- Inspect coverage:
  - `./bin/secure-claude-code list protections`
- Explain guards:
  - `SIGNATURES.md`
  - `GUARDS.md`

Keep the posture understandable. Prefer small, reviewable changes over broad blanket exceptions.
