# Guard Registry

Secure Claude Code is organized like a local YARA-style rule engine:

- one guard pack equals one focused signature set
- profiles enable groups of packs without changing code
- plain-text regex and config files keep tuning simple
- hooks stay small and composable instead of becoming one giant script

For the plain-English deep dive on every implemented signature, see [SIGNATURES.md](SIGNATURES.md).

## Implemented Guards

- `abuse-chain-defense`: remote instruction writes, rule-override text, and secret-plus-transfer chains
- `archive-and-upload-guard`: archive-plus-transfer chains involving secret or high-value material
- `binary-payload-guard`: downloaded or decoded executable payload staging
- `block-dangerous-commands`: high-confidence dangerous shell patterns
- `block-unsafe-git`: hook bypasses, force-pushes, and hard resets on protected branches
- `browser-cookie-guard`: browser cookie, login, and session-store access
- `ci-secret-release-guard`: CI and release changes that widen secret exposure or release power
- `clipboard-exfiltration-guard`: clipboard-based secret movement
- `config-tamper-guard`: bypass-oriented weakening of Claude, MCP, and CI control files
- `container-socket-guard`: direct access to Docker, containerd, CRI-O, and Podman sockets
- `credential-export-guard`: export of live credential material into files, clipboard, or transfers
- `dangerous-migration-guard`: destructive schema and data-loss migration patterns
- `devcontainer-trust-guard`: risky devcontainer isolation weakening and remote setup injection
- `dependency-script-guard`: install-time and build-time dependency script abuse
- `dns-exfiltration-guard`: DNS lookups and queries carrying encoded or sensitive material
- `mcp-permission-guard`: wildcard or high-risk MCP permission grants
- `kube-secret-guard`: direct reads and edits of live Kubernetes secrets
- `local-webhook-guard`: webhook-style outbound exfiltration of secrets, archives, and repo material
- `mass-delete-guard`: broad destructive deletes outside common generated-file cleanup lanes
- `network-exfiltration`: suspicious outbound transfers with sensitive material
- `artifact-poisoning-guard`: direct tampering with release artifacts, checksums, and signature material
- `package-publish-guard`: publish and release commands that leave the local review boundary
- `post-edit-quality-reminder`: post-edit lint/test reminders
- `pre-push-scan`: push-time secret, internal-host, and connection-string scanning
- `prod-target-guard`: direct mutating commands against production-like targets
- `protect-secrets-read`: local secret file access
- `protect-sensitive-files`: risky file-category edits
- `protect-tests`: test weakening and quality suppression patterns
- `remote-script-dropper-guard`: remote content dropped into executable or script paths
- `repo-mass-harvest-guard`: bulk repo packing and enumeration for export
- `registry-target-guard`: publish and login flows that target unexpected registries
- `ssh-agent-abuse-guard`: agent forwarding and key-agent extraction patterns
- `signed-commit-bypass-guard`: commit-signing and tag-signing bypass changes
- `test-fixture-secret-guard`: live secrets written into tests, fixtures, and snapshots
- `token-paste-guard`: live API token and private-key paste detection
- `tool-origin-guard`: risky MCP or tool origins in config files
- `workspace-boundary-guard`: system-path and deep-parent boundary escapes

## FFU Pipeline A

- `mcp-tool-impersonation-guard`: block tool names that spoof trusted providers
- `mcp-secret-scope-guard`: block MCP configs that request secret scope outside declared need
- `cloud-credential-assume-guard`: block risky cloud role assumption and impersonation flows
- `secret-diff-guard`: block secrets at edit time before they ever reach pre-push
- `log-poisoning-guard`: block secret writes and forged entries in logs or reports
- `oauth-device-flow-guard`: block abusive device-code and delegated auth flows

## FFU Pipeline B

- `plugin-manifest-guard`: block risky extension and plugin manifest edits
- `mcp-install-source-allowlist`: allow only reviewed MCP install sources
- `local-tunnel-guard`: block ngrok, serveo, and localtunnel exposure paths
- `browser-profile-export-guard`: block copying full browser profiles or profile archives
- `terraform-destroy-guard`: block destructive Terraform and OpenTofu flows
- `git-history-rewrite-guard`: block broad reflog cleanup and repo-history destruction
- `release-key-guard`: block release-signing and package-signing key export
- `sideloaded-extension-guard`: block unreviewed local extension load paths
- `container-escape-guard`: block host-mount and privileged container escape patterns
- `oauth-token-exchange-guard`: block token exchange and delegated session minting flows
- `desktop-credential-store-guard`: block reads of macOS Keychain, Windows Credential Manager, and libsecret stores
- `secret-redaction-guard`: require redacted examples instead of live secret examples in docs and fixtures
- `unexpected-registry-login-guard`: block logins to unapproved package and container registries
