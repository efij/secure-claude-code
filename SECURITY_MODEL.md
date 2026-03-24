# Security Model

Secure Claude Code is a local pre-tool and post-tool guardrail layer for Claude Code.

## Defended Behaviors

- hook bypasses and unsafe git shortcuts
- push-time secrets and live connection strings
- direct reads of local secret material
- suspicious outbound transfer commands involving sensitive material
- remote-content writes into Claude control files
- rule-override and jailbreak-style text written into control files
- test deletion and obvious quality-check suppression patterns

## Out Of Scope

- OS sandboxing
- Git host protections
- CI secret scanning
- endpoint security
- least-privilege credential management
- centralized team policy distribution

## Assumptions

- Claude Code hook execution is available
- `bash` and `python3` are available on supported paths
- the local machine and user account are already trusted enough to run Claude Code
- Windows users run through Git Bash or WSL for the current hook runtime

## Logging

Warnings and blocks are written to local JSONL audit logs by default.

- path: `~/.secure-claude-code/state/audit.jsonl`
- mode: `SECURE_CLAUDE_CODE_AUDIT_MODE=alerts|all|off`

## Known Limits

- hook visibility is strongest around tool inputs, not full remote content bodies
- Windows-native hook execution is not yet first-class
- the project intentionally stays local-first and does not include enterprise policy sync
