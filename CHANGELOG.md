# Changelog

## 1.4.0

- added `instruction-source-dropper-guard`
- added `skill-install-source-guard`
- added `skill-exec-chain-guard`
- added `skill-trust-boundary-tamper-guard`
- added `mcp-server-command-chain-guard`
- added `mcp-secret-env-guard`
- expanded `balanced` and `strict` for malicious skill, trusted-instruction, and MCP server coverage
- updated `README.md`, `GUARDS.md`, and `SIGNATURES.md` for the new skill and MCP blind-spot coverage
- expanded smoke coverage and generated plugin hook output for the new guard pack set

## 1.2.0

- added `indirect-prompt-injection-guard`
- added plain-text prompt-injection signature sets for instruction override, jailbreak text, obfuscation, context manipulation, and instruction smuggling
- expanded `balanced` and `strict` to scan tool output from files, web fetches, shell output, grep hits, task output, and MCP responses
- updated `README.md`, `GUARDS.md`, and `SIGNATURES.md` for the new indirect prompt-injection coverage
- expanded smoke coverage and generated plugin hook output for the new guard pack

## 1.3.0

- added `plugin-hook-origin-guard`
- added `plugin-exec-chain-guard`
- added `plugin-surface-expansion-guard`
- added `sideloaded-extension-guard`
- added `plugin-trust-boundary-tamper-guard`
- expanded plugin-malware coverage from install-source checks into post-install hook behavior, sideloaded extension paths, and trust-boundary tampering
- updated `README.md`, `GUARDS.md`, and `SIGNATURES.md` for the new malicious-plugin signature pack set
- expanded smoke coverage and generated plugin hook output for the new plugin guard pack set

## 1.1.7

- split smoke coverage by platform so Windows runners keep install, plugin, and lifecycle validation while macOS and Linux continue running the full direct-hook behavior suite
- republished the plugin-enabled release on a clean green build

## 1.1.6

- replaced the plugin manifest guard's risky-source matcher with a shell-native cross-platform path and domain check so plugin-manifest blocking behaves consistently on macOS, Linux, and Windows Git Bash
- republished the plugin-enabled release on a clean green build

## 1.1.5

- relaxed the MCP marketplace allowlist smoke assertion from “no output at all” to “no block fired” so Windows shell noise no longer causes false CI failures
- republished the plugin-enabled release on a clean green build

## 1.1.4

- normalized generated-vs-checked-in plugin hook comparisons in smoke tests so Windows CRLF checkouts no longer create false CI failures
- republished the plugin-enabled release on a clean green build

## 1.1.3

- replaced the marketplace source guard's risky-source matcher with a shell-native cross-platform path and domain check so plugin-source blocking behaves consistently on macOS, Linux, and Windows Git Bash
- republished the plugin-enabled release on a clean green build

## 1.1.2

- stabilized Windows smoke coverage for the new plugin and marketplace source guard by using a simpler cross-runner unapproved-source test case
- republished the plugin-enabled release on a clean green build

## 1.1.1

- fixed Windows matcher portability in `mcp-install-source-allowlist` so the new plugin and marketplace source guard pack passes CI across macOS, Linux, and Git Bash on Windows
- republished the plugin-enabled release on a clean green build

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
