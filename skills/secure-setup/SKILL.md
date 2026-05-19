---
description: Install or enable Stallion with the recommended balanced baseline.
disable-model-invocation: true
---

Use this skill when the user wants the fastest safe setup path.

- Prefer the Claude Code plugin flow first:
  - `/plugin marketplace add efij/stallion`
  - `/plugin install stallion@stallion`
- If the user wants profiles, local audit state, update, uninstall, or repair controls, use the CLI:
  - `./bin/stallion install balanced`
  - `./bin/stallion doctor`
  - `./bin/stallion validate`

Explain that the plugin gives a balanced baseline, while the CLI keeps the full `minimal`, `balanced`, and `strict` profile workflow.
