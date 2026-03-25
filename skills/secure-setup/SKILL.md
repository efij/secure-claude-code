---
description: Install or enable Secure Claude Code with the recommended balanced baseline.
disable-model-invocation: true
---

Use this skill when the user wants the fastest safe setup path.

- Prefer the Claude Code plugin flow first:
  - `/plugin marketplace add efij/secure-claude-code`
  - `/plugin install secure-claude-code@secure-claude-code`
- If the user wants profiles, local audit state, update, uninstall, or repair controls, use the CLI:
  - `./bin/secure-claude-code install balanced`
  - `./bin/secure-claude-code doctor`
  - `./bin/secure-claude-code validate`

Explain that the plugin gives a balanced baseline, while the CLI keeps the full `minimal`, `balanced`, and `strict` profile workflow.
