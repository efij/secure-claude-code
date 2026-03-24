# Changelog

## 0.3.0

- added `mcp-permission-guard` to block wildcard or high-risk MCP and tool permission grants in MCP control files
- added `archive-and-upload-guard` to block archive-then-transfer chains that package secret or high-value material
- added `config-tamper-guard` to block bypass-style weakening of Claude, MCP, and CI control files
- added new plain-text policy files for MCP control files, risky permission patterns, archive-sensitive sources, security control files, and tamper phrases
- expanded validation and smoke coverage for the new guard packs

## 0.2.0

- added bootstrap installers for shell and PowerShell so the project can be installed directly from a release or repository URL
- added `doctor --fix` to repair or reinstall a missing or broken local install
- expanded `logs` with filtering by module, decision, and recent time window for faster local audit triage
- aligned wrapper scripts around `bin/secure-claude-code`
- hardened release packaging to exclude local editor, agent, temp, and audit-state directories
- refreshed README and install guidance for bootstrap, package-manager paths, and repair workflows

## 0.1.0

- initial public release of Secure Claude Code
- profile-based Claude Code hardening with `minimal`, `balanced`, and `strict`
- protection packs for git safety, push-time secret scanning, secret-file access, outbound exfiltration, Claude control-file abuse, sensitive file edits, and test integrity
- local JSONL audit logging and CLI log viewing
- generated Homebrew formula and Scoop manifest release assets
- smoke tests, CI workflow, release workflow, security policy, and security model docs
