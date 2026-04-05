# Guard Registry

Runwall is organized like a local YARA-style rule engine:

- one guard pack equals one focused signature set
- profiles enable groups of packs without changing code
- plain-text regex and config files keep tuning simple
- hooks stay small and composable instead of becoming one giant script

For the plain-English deep dive on every implemented signature, see [SIGNATURES.md](SIGNATURES.md).

## Implemented Guards

- `abuse-chain-defense`: remote instruction writes, rule-override text, and secret-plus-transfer chains
- `agent-session-secret-guard`: direct reads and exports of local auth, token, and session stores used by coding agents
- `archive-and-upload-guard`: archive-plus-transfer chains involving secret or high-value material
- `audit-evasion-guard`: shell history, event log, and Runwall audit trail clearing behavior
- `binary-payload-guard`: downloaded or decoded executable payload staging
- `block-dangerous-commands`: high-confidence dangerous shell patterns
- `block-unsafe-git`: hook bypasses, force-pushes, and hard resets on protected branches
- `browser-cookie-guard`: browser cookie, login, and session-store access
- `browser-profile-export-guard`: copying or archiving full browser profiles with live sessions and saved credentials
- `cloud-key-creation-guard`: creation of long-lived cloud access keys and service-account credentials
- `cloud-credential-assume-guard`: cloud role assumption, token minting, and service-account impersonation flows that can widen access
- `ci-secret-release-guard`: CI and release changes that widen secret exposure or release power
- `clipboard-exfiltration-guard`: clipboard-based secret movement
- `config-tamper-guard`: bypass-oriented weakening of Claude, MCP, and CI control files
- `config-secret-inline-guard`: live tokens, private keys, and secret literals pasted directly into app, deploy, or workflow config
- `container-escape-guard`: privileged container runs, host namespace joins, and root filesystem mounts that break isolation boundaries
- `docker-build-secret-leak-guard`: build-time secret leaks through `docker build`, `podman build`, or `nerdctl build` args and secret mounts
- `container-socket-guard`: direct access to Docker, containerd, CRI-O, and Podman sockets
- `credential-export-guard`: export of live credential material into files, clipboard, or transfers
- `dangerous-migration-guard`: destructive schema and data-loss migration patterns
- `devcontainer-trust-guard`: risky devcontainer isolation weakening and remote setup injection
- `dependency-script-guard`: install-time and build-time dependency script abuse
- `desktop-credential-store-guard`: direct access to OS-backed desktop credential stores such as Keychain, libsecret, and Windows Credential Manager
- `dns-exfiltration-guard`: DNS lookups and queries carrying encoded or sensitive material
- `git-credential-store-guard`: plaintext git credential stores and credential-helper downgrade behavior
- `git-history-rewrite-guard`: broad git history surgery and purge flows that destroy provenance
- `hosts-file-tamper-guard`: hosts-file remaps for high-trust vendor and registry domains
- `indirect-prompt-injection-guard`: scans tool output for hidden prompt injection, jailbreak text, obfuscation, and instruction smuggling
- `instruction-source-dropper-guard`: remote content written directly into AGENTS, CLAUDE, skills, or Claude command files
- `mcp-permission-guard`: wildcard or high-risk MCP permission grants
- `mcp-upstream-swap-guard`: gateway upstream registry entries that switch to remote, sideloaded, or scratch-path server sources
- `mcp-tool-impersonation-guard`: upstream MCP tools that spoof trusted Runwall or control-plane tool names
- `mcp-tool-schema-widening-guard`: sensitive MCP tools that suddenly widen into free-form schemas
- `mcp-parameter-smuggling-guard`: MCP tool arguments that hide prompt overrides, encoded blobs, or execution chains
- `mcp-bulk-read-exfil-guard`: multi-target secret-like MCP reads that should pause for review
- `mcp-egress-private-network-guard`: private IP, localhost, and link-local outbound MCP destinations
- `mcp-egress-destination-class-guard`: webhook, paste, gist-like, and blob-style outbound MCP destinations
- `mcp-egress-policy-guard`: per-profile allowlist or denylist enforcement for outbound MCP destinations
- `mcp-secret-env-guard`: high-value secret environment variables forwarded into MCP server definitions
- `mcp-server-command-chain-guard`: dangerous execution chains embedded in MCP server definitions
- `mcp-response-secret-leak-guard`: upstream MCP responses that contain live secret or credential material
- `mcp-response-prompt-smuggling-guard`: upstream MCP responses that contain hidden prompt injection or policy-override text
- `mcp-binary-dropper-guard`: upstream MCP responses that look like executable, archive, or staged payload material
- `mcp-response-suspicious-url-guard`: upstream MCP responses that contain risky outbound URLs and should pause for review
- `mcp-response-shell-snippet-guard`: upstream MCP responses that contain fetch-and-execute or staged shell snippets
- `mcp-install-source-allowlist`: unreviewed MCP and plugin marketplace install sources
- `kube-secret-guard`: direct reads and edits of live Kubernetes secrets
- `local-webhook-guard`: webhook-style outbound exfiltration of secrets, archives, and repo material
- `log-poisoning-guard`: forged Runwall markers, secret dumps, and poisoned evidence written into logs, SARIF, or incident reports
- `mass-delete-guard`: broad destructive deletes outside common generated-file cleanup lanes
- `network-exfiltration`: suspicious outbound transfers with sensitive material
- `netrc-credential-guard`: direct reads and exports of `.netrc` credential files
- `oauth-device-flow-guard`: browserless and device-code OAuth logins that mint delegated user sessions
- `artifact-poisoning-guard`: direct tampering with release artifacts, checksums, and signature material
- `package-publish-guard`: publish and release commands that leave the local review boundary
- `plugin-exec-chain-guard`: dangerous download-and-execute or inline interpreter chains inside plugin commands
- `plugin-hook-origin-guard`: plugin hook commands that jump outside the plugin trust boundary
- `plugin-manifest-guard`: risky plugin and extension manifest source edits
- `plugin-update-source-swap-guard`: plugin update metadata that swaps reviewed release sources to raw, remote, or scratch locations
- `plugin-surface-expansion-guard`: suspicious plugin hook coverage expansion onto sensitive lifecycle events or broad mutation-plus-shell combinations
- `plugin-trust-boundary-tamper-guard`: plugin attempts to weaken Claude, MCP, or Runwall control files
- `post-edit-quality-reminder`: post-edit lint/test reminders
- `pre-push-scan`: push-time secret, internal-host, and connection-string scanning
- `production-shell-guard`: interactive shells into production-like workloads and containers
- `prod-target-guard`: direct mutating commands against production-like targets
- `prod-db-shell-guard`: direct shells into production-like databases, caches, and data stores
- `protect-secrets-read`: local secret file access
- `protect-sensitive-files`: risky file-category edits
- `protect-tests`: test weakening and quality suppression patterns
- `remote-script-dropper-guard`: remote content dropped into executable or script paths
- `repo-mass-harvest-guard`: bulk repo packing and enumeration for export
- `registry-target-guard`: publish and login flows that target unexpected registries
- `secret-manager-abuse-guard`: agent-driven pulls from Vault, 1Password, and cloud secret-manager backends
- `registry-credential-guard`: direct reads and exports of package and container registry credentials
- `release-key-guard`: reads and exports of release-signing and provenance key material
- `scheduled-task-persistence-guard`: cron, launchd, systemd, and scheduled-task persistence
- `shell-profile-persistence-guard`: suspicious downloader or execution payloads added to shell profiles
- `sideloaded-extension-guard`: local plugin archives, unpacked extensions, and sideload paths outside reviewed sources
- `ssh-agent-abuse-guard`: agent forwarding and key-agent extraction patterns
- `ssh-authorized-keys-guard`: agent-driven writes to SSH authorized keys and login trust material
- `ssh-trust-downgrade-guard`: host verification and known-host trust downgrades in SSH commands or config
- `signed-commit-bypass-guard`: commit-signing and tag-signing bypass changes
- `skill-exec-chain-guard`: dangerous download-and-execute or inline interpreter chains embedded in skill and Claude command files
- `skill-install-source-guard`: unreviewed raw, temp, or sideloaded skill install sources
- `skill-multi-stage-dropper-guard`: trusted skill or instruction docs that embed fetch-save-execute or decode-then-run chains
- `skill-trust-boundary-tamper-guard`: prompt-override and guard-bypass language added to trusted skill and command files
- `test-fixture-secret-guard`: live secrets written into tests, fixtures, and snapshots
- `token-paste-guard`: live API token and private-key paste detection
- `tool-origin-guard`: risky MCP or tool origins in config files
- `tool-capability-escalation-guard`: MCP tool definitions that combine broad shell, file, and network reach in one widened surface
- `instruction-override-bridge-guard`: trusted instruction files that tell the runtime to bypass Runwall or trust tool output over local policy
- `trusted-config-symlink-guard`: symlink redirection of trusted policy, plugin, MCP, and instruction files
- `sudoers-tamper-guard`: edits that weaken sudo password and privilege policy
- `terraform-destroy-guard`: destructive Terraform, OpenTofu, Terragrunt, and Pulumi teardown flows
- `unexpected-registry-login-guard`: package and container logins or registry rewrites that target hosts outside the reviewed set
- `workspace-boundary-guard`: system-path and deep-parent boundary escapes

## FFU Pipeline A

- `mcp-secret-scope-guard`: block MCP configs that request secret scope outside declared need
- `secret-diff-guard`: block secrets at edit time before they ever reach pre-push
- `token-broker-guard`: block local token broker and cached SSO helper abuse outside reviewed flows

## FFU Pipeline B

- `local-tunnel-guard`: block ngrok, serveo, and localtunnel exposure paths
- `oauth-token-exchange-guard`: block token exchange and delegated session minting flows
- `secret-redaction-guard`: require redacted examples instead of live secret examples in docs and fixtures
- `credential-helper-downgrade-guard`: block package and registry auth changes that fall back to plaintext helpers or files
