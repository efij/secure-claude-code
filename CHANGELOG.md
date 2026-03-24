# Changelog

## 0.9.0

- added `repo-mass-harvest-guard`
- added `binary-payload-guard`
- added `package-publish-guard`
- documented the project as a modular signature-pack system with a forward guard pipeline

## 0.8.0

- added `ci-secret-release-guard`
- added `dependency-script-guard`
- added `dangerous-migration-guard`
- added `prod-target-guard`

## 0.7.0

- added `credential-export-guard`
- added `clipboard-exfiltration-guard`
- added `ssh-agent-abuse-guard`
- added `token-paste-guard`
- added `test-fixture-secret-guard`

## 0.6.0

- added `tool-origin-guard`
- added `workspace-boundary-guard`
- added `remote-script-dropper-guard`

## 0.5.0

- added `mcp-permission-guard`
- added `archive-and-upload-guard`
- added `config-tamper-guard`

## 0.4.0

- added bootstrap installers for shell and PowerShell
- added `doctor --fix`
- added filtered audit log views by module, decision, and time window
- aligned wrapper scripts around `bin/secure-claude-code`
- hardened release packaging against local editor, agent, temp, and audit-state leakage

## 0.3.0

- added `abuse-chain-defense`
- added `network-exfiltration`
- added `block-dangerous-commands`
- expanded validation and smoke coverage for advanced shell and exfiltration guards

## 0.2.0

- added `protect-secrets-read`
- added `protect-sensitive-files`
- added `protect-tests`
- added `post-edit-quality-reminder`
- established profile-driven installs with `minimal`, `balanced`, and `strict`

## 0.1.0

- initial public release of Secure Claude Code
- added `block-unsafe-git`
- added `pre-push-scan`
- added local JSONL audit logging
- added generated Homebrew and Scoop release assets
- added smoke tests, CI workflow, release workflow, security policy, and security model docs
