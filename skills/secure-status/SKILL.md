---
description: Inspect the current Secure Claude Code posture, enabled protections, and recent audit events.
disable-model-invocation: true
---

Use this skill when the user wants to see whether Secure Claude Code is active and what it is doing.

- Check posture:
  - `./bin/secure-claude-code doctor`
  - `./bin/secure-claude-code validate`
- Review protections:
  - `./bin/secure-claude-code list protections`
- Review recent blocks and warnings:
  - `./bin/secure-claude-code logs 20`

Summarize the active profile, installed protections, and whether recent warnings or blocks were recorded.
