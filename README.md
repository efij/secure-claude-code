# Secure Claude Code

> Local-first security for Claude Code. Protect shell, git, MCP, secrets, and risky agent actions without dragging in heavy enterprise tooling.

Secure Claude Code adds a practical security layer around Claude Code to reduce prompt injection fallout, secret leakage, unsafe command execution, dangerous git operations, and risky MCP or tool configurations.

It is built for solo builders, startups, security-minded teams, and larger orgs that want safer defaults around AI coding workflows.

<p align="left">
  <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/efij/secure-claude-code/ci.yml?branch=main&label=smoke">
  <img alt="Release" src="https://img.shields.io/github/v/release/efij/secure-claude-code">
  <img alt="License" src="https://img.shields.io/github/license/efij/secure-claude-code">
  <img alt="Stars" src="https://img.shields.io/github/stars/efij/secure-claude-code">
  <img alt="Issues" src="https://img.shields.io/github/issues/efij/secure-claude-code">
  <img alt="Last Commit" src="https://img.shields.io/github/last-commit/efij/secure-claude-code">
</p>

## Why Secure Claude Code?

Claude Code is useful because it can read files, run shell commands, use git, and work with MCP tools.

That is also exactly why it needs guardrails.

Secure Claude Code helps reduce real-world risk around:

- secret leakage
- prompt injection and exfiltration paths
- indirect prompt injection hidden in files, web pages, shell output, and MCP responses
- unsafe shell execution
- dangerous git and repo actions
- risky MCP and tool trust boundaries
- weak local defaults in agent workflows

It is local-first, practical, and built for real developer environments.

## What It Does

Secure Claude Code helps you:

- block high-confidence risky actions before they run
- warn when tool output itself contains hidden prompt injection or jailbreak bait
- protect secrets, keys, tokens, and sensitive files
- reduce dangerous shell, git, and repo behavior
- tighten MCP and tool trust boundaries
- apply a safer default profile quickly
- keep security useful without turning the workflow into sludge

It works well on top of Claude Code sandbox mode too. Sandboxing helps contain damage. Secure Claude Code adds guard logic on top of that containment layer.

## Who It Is For

- solo developers who want safer local AI coding
- startups moving fast but trying not to leak secrets or wreck repos
- security engineers and AppSec teams reviewing agent risk
- DevSecOps teams adopting MCP-based tools
- larger orgs that need a cleaner baseline before enterprise policy layers come later

It is much less relevant for plain Claude chat-only usage where no tools, shell, git, or file actions are involved.

## Fast Install

The cleanest install path now is the Claude Code plugin flow. It gives you the recommended balanced baseline in one install.

### Claude Code Plugin

```text
/plugin marketplace add efij/secure-claude-code
/plugin install secure-claude-code@secure-claude-code
```

Use the plugin path when you want fast setup and low friction.

Use the CLI path when you want profile switching, update, uninstall, doctor repair, or a separate local install home.

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
./bin/secure-claude-code install balanced
```

`install.sh`, `update.sh`, and `uninstall.sh` still exist, but they are only thin compatibility wrappers around the main CLI.

## Quick Start

### Apply a safer baseline

```bash
./bin/secure-claude-code install balanced
```

### Validate the setup

```bash
./bin/secure-claude-code doctor
./bin/secure-claude-code validate
```

### Review active protections

```bash
./bin/secure-claude-code list protections
```

### Inspect recent blocks and warnings

```bash
./bin/secure-claude-code logs 20
./bin/secure-claude-code logs 50 --json
```

## Security Coverage

Secure Claude Code focuses on the practical execution surface around Claude Code.

### Shell

- dangerous command execution
- remote script and payload staging
- sandbox escape and trust-boundary abuse

### Secrets

- local secret file reads
- token paste and fixture leaks
- browser session and cluster secret access

### Git and Repo Actions

- destructive git operations
- signing bypasses
- mass deletion and repo harvest patterns

### MCP and Tools

- risky MCP permission grants
- risky marketplace or install sources
- sideloaded plugin and extension paths
- untrusted tool origins
- risky plugin manifest edits
- malicious plugin hook origins and execution chains
- plugin trust-boundary tampering
- weak local trust boundaries

### Exfiltration and Agent Abuse

- prompt-injection style control-file abuse
- indirect prompt injection scanning across read, web, shell, grep, task, and MCP output
- webhook, DNS, clipboard, and upload exfil paths
- unsafe action chaining across tools and files
- browser profile export and release-key theft patterns

## Profiles

### `minimal`

Tight baseline for solo hacking and lightweight local hardening.

### `balanced`

Recommended default for most users. Good protection without too much friction.

### `strict`

Stronger controls for sensitive repos, shared environments, and security-heavy teams.

## Why People Keep It Installed

- local-first with no cloud control plane required for core protection
- modular guard packs instead of one opaque policy blob
- plain-text regex and config files that are easy to tune
- good fit for solo work, startup speed, and more controlled org setups
- practical enforcement around the place risk actually happens: tool execution

The architecture is intentionally YARA-like in spirit:

- one guard pack maps to one attack family
- profiles group packs quickly
- config files stay editable
- hooks stay small and composable

## Audit and Transparency

Secure Claude Code writes local JSONL audit events for warnings and blocks.

Defaults:

- path: `~/.secure-claude-code/state/audit.jsonl`
- mode: `alerts`

Useful commands:

```bash
./bin/secure-claude-code logs
./bin/secure-claude-code logs 50 --decision block --since-hours 24
```

If you want the deep dive:

- [GUARDS.md](GUARDS.md): implemented guards and future pipeline
- [SIGNATURES.md](SIGNATURES.md): plain-English explanation for every implemented signature

## Platform Support

- macOS: supported
- Linux: supported
- Windows: supported through Git Bash or WSL

## Package and Release Paths

Current clean distribution paths:

- Claude Code plugin marketplace
- GitHub Releases
- bootstrap installer
- Homebrew formula
- Scoop manifest

GitHub Packages can be added later if this gets wrapped as an OCI or npm package, but it is not the primary path today.

## Contributing

Contributions are welcome, especially around:

- new high-signal signatures
- false-positive reduction
- MCP and tool abuse detection
- exfiltration and prompt-injection patterns, especially indirect prompt injection and output smuggling
- better developer UX without losing security value

Good places to start:

- [GUARDS.md](GUARDS.md)
- [SIGNATURES.md](SIGNATURES.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)

## Security Note

Secure Claude Code reduces risk. It does not eliminate risk.

You should still treat Claude Code, MCP tools, shell access, secrets, and repository operations as real security boundaries. This project is the local enforcement layer, not the whole security program.

## License

See [LICENSE](LICENSE).
