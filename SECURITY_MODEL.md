# Security Model

Secure Claude Code is a **local-first pre/post tool guardrail layer** for Claude Code.

## What It Tries To Stop

- hook bypasses and unsafe git shortcuts
- secret leakage before push
- direct reads of local secret material
- suspicious exfiltration command chains
- remote-content writes into agent control files
- prompt-injection style rule-override edits in control files
- test deletion and obvious test/check suppression patterns

## What It Does Not Replace

- OS sandboxing
- Git host protections
- CI secret scanning
- code review
- endpoint protection
- least-privilege credentials

## Design Assumptions

- the user can edit their own machine and local config
- Claude Code hook execution is available and not globally disabled
- bash and python3 are available for the supported local-first path
- Windows users use Git Bash or WSL for the current hook runtime

## Logging

Secure Claude Code records local JSONL audit events for warnings and blocks by default.

- default path: `~/.secure-claude-code/state/audit.jsonl`
- mode: `SECURE_CLAUDE_CODE_AUDIT_MODE=alerts|all|off`

## Known Limits

- content-level prompt-injection detection is limited because hooks primarily see tool inputs, not full remote content bodies
- Windows-native hook execution is not yet first-class
- central team policy sync is intentionally out of scope for the local-first edition

