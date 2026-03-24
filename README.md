# Secure Claude Code

![CI](https://img.shields.io/github/actions/workflow/status/efij/secure-claude-code/ci.yml?branch=main&label=smoke)
![Release](https://img.shields.io/github/v/release/efij/secure-claude-code)
![Stars](https://img.shields.io/github/stars/efij/secure-claude-code?style=social)
![License](https://img.shields.io/github/license/efij/secure-claude-code)

Hard-stop security guardrails for Claude Code.

Secure Claude Code helps stop the dumb, dangerous, or hijacked actions an AI coding agent should not make on your machine or repo.

It is built for normal Claude Code users too, not only security people.

If Claude Code can run shell, edit files, use git, call MCP tools, or touch the network, this repo adds a local-first safety layer in front of those actions.

## Why People Install It

- stop secret leaks before they leave your machine
- stop bad git actions before history gets wrecked
- stop risky MCP or tool setup before trust gets widened
- stop CI, release, and prod mistakes before they go live
- stop prompt-injection or exfiltration chains before they spread

Works well with Claude Code sandbox mode too: sandboxing contains damage, and Secure Claude Code adds local guard rules on top.

## In One Line

Secure Claude Code works like a modular YARA-style rule pack system for Claude Code actions.

- one guard pack = one attack family
- profiles turn packs on fast
- plain-text regex files make tuning easy
- no dashboard or cloud account required

## Who It Is For

Use it if:
- you use Claude Code with shell, git, file, or network access
- you use MCP tools or cowork-style agent workflows
- you want local-first security without enterprise policy software

It is less relevant if:
- you only use normal Claude chat
- Claude never gets tool access

## Why It Feels Different

- local-first: no cloud dashboard needed for core protection
- simple install: curl, PowerShell, or local checkout
- modular guards: each pack focuses on one attack family
- readable rules: plain-text regex and small hook files
- friendly defaults: `balanced` is made for everyday use

## What It Blocks

- unsafe git actions on protected branches
- secret reads from `.env`, cloud creds, SSH keys, and kube config
- push-time secrets and connection strings
- suspicious uploads, archive-and-upload chains, and repo harvest patterns
- risky MCP permission grants, risky tool origins, and malicious tool/provider setup
- prompt-injection style control-file abuse
- sandbox escape patterns and sandbox-policy weakening
- reverse tunnels, metadata grabs, git-hook persistence, and common sandbox-bypass patterns
- dependency script abuse, destructive migrations, and prod-target commands
- test weakening, test deletion, and secrets in fixtures

## Fast Install

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/efij/secure-claude-code/main/scripts/bootstrap.sh | bash -s -- --repo efij/secure-claude-code --ref main --profile balanced
```

### Windows

```powershell
irm https://raw.githubusercontent.com/efij/secure-claude-code/main/scripts/bootstrap.ps1 | iex; Install-SecureClaudeCode -Repo "efij/secure-claude-code" -Ref "main" -Profile "balanced"
```

### Local Checkout

```bash
git clone https://github.com/efij/secure-claude-code.git
cd secure-claude-code
bash install.sh
```

## Core Commands

```bash
./bin/secure-claude-code install balanced
./bin/secure-claude-code update
./bin/secure-claude-code validate
./bin/secure-claude-code doctor
./bin/secure-claude-code doctor --fix balanced
./bin/secure-claude-code list protections
./bin/secure-claude-code logs 20
./bin/secure-claude-code uninstall
```

## Profiles

- `minimal`: light baseline
- `balanced`: recommended default
- `strict`: more aggressive protection

## Guard Packs

Implemented now:

- `abuse-chain-defense`
- `archive-and-upload-guard`
- `binary-payload-guard`
- `block-dangerous-commands`
- `block-unsafe-git`
- `ci-secret-release-guard`
- `clipboard-exfiltration-guard`
- `cloud-metadata-guard`
- `config-tamper-guard`
- `credential-export-guard`
- `dangerous-migration-guard`
- `dependency-script-guard`
- `git-hook-persistence-guard`
- `mcp-permission-guard`
- `network-exfiltration`
- `package-publish-guard`
- `post-edit-quality-reminder`
- `pre-push-scan`
- `prod-target-guard`
- `protect-secrets-read`
- `protect-sensitive-files`
- `protect-tests`
- `remote-script-dropper-guard`
- `repo-mass-harvest-guard`
- `sandbox-escape-guard`
- `sandbox-policy-tamper-guard`
- `ssh-agent-abuse-guard`
- `test-fixture-secret-guard`
- `token-paste-guard`
- `tool-origin-guard`
- `tunnel-beacon-guard`
- `workspace-boundary-guard`

Full implemented + future guard registry:
- [GUARDS.md](GUARDS.md)

Deep dive for every implemented signature:
- [SIGNATURES.md](SIGNATURES.md)

## Why It Feels Like YARA

- each module is a focused signature pack
- profiles group packs without changing code
- config files under `config/` act like easy local rule sources
- hooks stay small and composable

That means it is easy to:
- add a new guard
- disable a noisy guard
- tune patterns without rewriting the whole tool

## Audit Log

Secure Claude Code writes local JSONL audit events for warnings and blocks.

```bash
./bin/secure-claude-code logs
./bin/secure-claude-code logs 50 --json
./bin/secure-claude-code logs 50 --decision block --since-hours 24
```

Defaults:
- path: `~/.secure-claude-code/state/audit.jsonl`
- mode: `alerts`

Env vars:
- `SECURE_CLAUDE_CODE_AUDIT_MODE=alerts|all|off`
- `SECURE_CLAUDE_CODE_AUDIT_FILE=/custom/path/audit.jsonl`

## Package and Release Paths

Current best install paths:
- GitHub release assets
- bootstrap installer
- Homebrew formula
- Scoop manifest

GitHub Packages is possible later if you wrap this project as an OCI or npm package, but today the cleanest fit is GitHub Releases plus Homebrew and Scoop.

## Platform Support

- macOS: supported
- Linux: supported
- Windows: supported through Git Bash or WSL

## Verify

```bash
bash tests/smoke.sh
```

CI runs the smoke suite on Linux, macOS, and Windows.

## Docs

- [GUARDS.md](GUARDS.md)
- [SIGNATURES.md](SIGNATURES.md)
- [SECURITY.md](SECURITY.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
