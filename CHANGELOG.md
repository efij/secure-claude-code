# Changelog

## 1.1.0

- added Claude Code plugin marketplace support with `.claude-plugin/marketplace.json`, `.claude-plugin/plugin.json`, root plugin skills, and generated `hooks/hooks.json`
- added `plugin-manifest-guard`
- added `mcp-install-source-allowlist`
- added `browser-profile-export-guard`
- added `git-history-rewrite-guard`
- added `release-key-guard`
- documented the new signatures in `SIGNATURES.md`
- updated the README so the Claude Code plugin flow is now the clean primary install path, with the CLI kept for profile control and repair workflows
- expanded smoke coverage to validate plugin files, generated plugin hooks, and the new guard pack set

## 1.0.0

- added `local-webhook-guard`
- added `dns-exfiltration-guard`
- added `browser-cookie-guard`
- added `container-socket-guard`
- added `signed-commit-bypass-guard`
- added `artifact-poisoning-guard`
- added `mass-delete-guard`
- added `kube-secret-guard`
- added `registry-target-guard`
- added `devcontainer-trust-guard`
- added a full plain-English signature deep dive in `SIGNATURES.md`
- simplified the public install story around the bootstrap installer and main CLI entrypoint
- expanded smoke coverage for the new guard pack set
- promoted Secure Claude Code to `1.0.0`

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
