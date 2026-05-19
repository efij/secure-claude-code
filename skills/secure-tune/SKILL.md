---
description: Tune Stallion with stricter or lighter profiles and explain individual guards.
disable-model-invocation: true
---

Use this skill when the user wants to tighten, relax, or understand the local policy.

- Switch profiles:
  - `./bin/stallion install strict`
  - `./bin/stallion install balanced`
  - `./bin/stallion install minimal`
- Inspect coverage:
  - `./bin/stallion list protections`
- Explain guards:
  - `SIGNATURES.md`
  - `GUARDS.md`

Keep the posture understandable. Prefer small, reviewable changes over broad blanket exceptions.
