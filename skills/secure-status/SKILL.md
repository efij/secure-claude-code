---
description: Inspect the current Stallion posture, enabled protections, and recent audit events.
disable-model-invocation: true
---

Use this skill when the user wants to see whether Stallion is active and what it is doing.

- Check posture:
  - `./bin/stallion doctor`
  - `./bin/stallion validate`
- Review protections:
  - `./bin/stallion list protections`
- Review recent blocks and warnings:
  - `./bin/stallion logs 20`

Summarize the active profile, installed protections, and whether recent warnings or blocks were recorded.
