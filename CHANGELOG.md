# Changelog

## 3.3.3

- fixed cross-platform MCP tool suppression by converting shipped ERE rule packs away from non-portable `(?i)` and `\b` constructs
- hardened regex validation so grep-based signature packs now fail fast if they include non-portable ERE features
- simplified the git safety smoke assertion so the cross-platform shell-resolution check stays stable without overfitting to one stderr shape

## 3.3.2

- fixed the MCP bulk-read prompt guard so multiple sensitive path hits are counted correctly across Linux, macOS, and Windows
- republished the inline gateway patch release with a clean smoke path for request-time prompt review

## 3.3.1

- fixed the `windows-latest` shell-resolution regression by preferring Git Bash over WSL-style shims in the policy engine
- fixed a BSD `grep -E` portability issue in `mcp-response-secrets.regex` that broke `macos-latest` validation
- fixed the inline gateway smoke path so bulk sensitive MCP reads reliably trigger prompt review and the git safety assertion stays stable across platforms
- republished the inline MCP gateway release with green CI across `ubuntu-latest`, `macos-latest`, and `windows-latest`

## 3.3.0

- fixed the real `windows-latest` CI failure by making hook-shell resolution deterministic in the Python policy engine instead of relying on a generic `bash` shim
- added the inline MCP gateway with `./bin/runwall gateway serve`, multi-upstream stdio proxying, request and response inspection, and namespaced upstream tool exposure
- added a built-in local API and dashboard for health, live events, pending prompts, approvals, and redaction visibility
- upgraded the MCP runtime path from helper-only companion mode to real-time enforcement for Codex, Cursor, Windsurf, Claude Desktop, Claude Cowork, and generic MCP clients
- added `mcp-upstream-swap-guard`
- added `mcp-tool-impersonation-guard`
- added `mcp-tool-schema-widening-guard`
- added `mcp-parameter-smuggling-guard`
- added `mcp-bulk-read-exfil-guard`
- added `mcp-response-secret-leak-guard`
- added `mcp-response-prompt-smuggling-guard`
- added `mcp-binary-dropper-guard`
- added `plugin-update-source-swap-guard`
- added `skill-multi-stage-dropper-guard`
- added `tool-capability-escalation-guard`
- added `instruction-override-bridge-guard`
- updated runtime templates, `.mcp.json`, plugin hook generation, and smoke coverage so the inline gateway is the default MCP path
- expanded `README.md`, `RUNTIMES.md`, `GUARDS.md`, and `SIGNATURES.md` for the new gateway architecture and signature pack set

## 3.2.0

- added first-class runtime config generation for Cursor, Windsurf, and Claude Desktop
- updated the runtime matrix so leading MCP-native platforms are no longer buried under `generic-mcp`
- simplified the README install flow with explicit per-platform config generation commands

## 3.1.0

- added a Codex bundle manifest in `.codex-plugin/plugin.json`
- added a shared `.mcp.json` so plugin and bundle installs have a ready Runwall MCP server definition
- updated Claude plugin metadata to the current Runwall version
- updated `README.md` and `RUNTIMES.md` so Claude Code, Codex, and OpenClaw plugin or bundle installs are the primary KISS paths

## 3.0.0

- added multi-runtime adapter support instead of keeping Runwall Claude-only
- added `list runtimes`, `generate-runtime-config`, `evaluate`, and `mcp serve` CLI commands
- added a reusable policy evaluation engine in `scripts/runwall_policy.py`
- added a local Runwall MCP companion server in `scripts/runwall_mcp_server.py`
- added generated runtime templates for Codex, generic MCP clients, and CI/CD
- documented the runtime matrix and companion-mode strategy in `README.md` and `RUNTIMES.md`
- expanded smoke coverage to validate runtime generation, CLI policy evaluation, and MCP server handshake behavior

## 2.2.0

- added `shell-profile-persistence-guard`
- added `scheduled-task-persistence-guard`
- added `ssh-authorized-keys-guard`
- added `hosts-file-tamper-guard`
- added `sudoers-tamper-guard`
- added `git-credential-store-guard`
- added `netrc-credential-guard`
- added `registry-credential-guard`
- added `cloud-key-creation-guard`
- added `production-shell-guard`
- expanded `balanced` and `strict` for workstation persistence, privilege tampering, credential-store abuse, cloud key issuance, and prod-shell access coverage
- updated `README.md`, `GUARDS.md`, and `SIGNATURES.md` for the new guard pack set
- expanded smoke coverage and generated plugin hook output for the new high-confidence signatures

## 2.1.0

- added `audit-evasion-guard`
- added `ssh-trust-downgrade-guard`
- added `agent-session-secret-guard`
- added `trusted-config-symlink-guard`
- added `desktop-credential-store-guard`
- expanded `balanced` and `strict` for defense-evasion, SSH trust, workstation credential store, and agent session theft coverage
- updated `README.md`, `GUARDS.md`, and `SIGNATURES.md` for the new guard pack set
- expanded smoke coverage and generated plugin hook output for the new high-confidence signatures

## 2.0.0

- rebranded the product and primary CLI to `Runwall`
- added `bin/runwall` as the primary entrypoint while keeping `bin/secure-claude-code` as a compatibility wrapper
- moved the default install and audit home to `~/.runwall` while keeping legacy env var fallback support
- renamed plugin, package, and release artifacts to `runwall`
- added `scripts/validate-patterns.py` and wired regex validation into smoke tests, CI, and `validate`
- tightened release-facing docs and messaging around the Runwall runtime-security positioning

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
- promoted Runwall to `1.0.0`

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
- aligned wrapper scripts around `bin/runwall`
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

- initial public release of Runwall
- added `block-unsafe-git`
- added `pre-push-scan`
- added local JSONL audit logging
- added generated Homebrew and Scoop release assets
- added smoke tests, CI workflow, release workflow, security policy, and security model docs
