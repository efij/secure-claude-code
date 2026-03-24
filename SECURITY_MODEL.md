# Security Model

Secure Claude Code is a local pre-tool and post-tool guardrail layer for Claude Code.

It is designed to sit on top of normal safe setup choices such as Claude Code sandbox mode, repo protections, and secret hygiene. It does not replace them.

## Defended Behaviors

- hook bypasses and unsafe git shortcuts
- push-time secrets and live connection strings
- direct reads of local secret material
- suspicious outbound transfer commands involving sensitive material
- archive-and-upload chains involving sensitive or high-value material
- risky MCP and tool permission grants in MCP control files
- risky tool origins, remote droppers, and executable payload staging
- sandbox escape patterns, sandbox policy weakening, and cloud metadata access
- tunnel and git-hook persistence patterns that try to bypass normal review boundaries
- workspace-boundary escapes into system paths
- CI, publish, and prod-target mutations that widen trust or move outside local review
- live token pastes, clipboard exfiltration, and SSH agent abuse patterns
- dependency install hooks and destructive migration flows
- remote-content writes into Claude control files
- rule-override and jailbreak-style text written into control files
- tampering with Claude, MCP, or CI control files through bypass-style edits
- test deletion and obvious quality-check suppression patterns

## Out Of Scope

- OS or container isolation itself
- Git host protections
- CI secret scanning outside local hooks
- endpoint security or EDR
- least-privilege credential management
- centralized team policy distribution

## Assumptions

- Claude Code hook execution is available
- `bash` and `python3` or `python` are available on supported paths
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
