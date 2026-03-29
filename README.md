# Runwall

> Runtime security for Claude Code, Codex, and MCP-native coding clients. Protect shell, git, MCP, secrets, plugins, skills, and risky agent actions before they turn into damage.

Runwall adds a practical security layer around coding-agent runtimes to reduce prompt injection fallout, secret leakage, unsafe command execution, dangerous git operations, and risky MCP, plugin, or skill configurations.

It now does both:

- audit mode for scanning agent configs, hooks, MCP servers, skills, plugins, and instruction files
- runtime mode for inline enforcement, prompting, blocking, and redaction

It is built for solo builders, startups, security-minded teams, and larger orgs that want safer defaults around AI coding workflows.

<p align="left">
  <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/efij/secure-claude-code/ci.yml?branch=main&label=smoke">
  <img alt="Release" src="https://img.shields.io/github/v/release/efij/secure-claude-code">
  <img alt="License" src="https://img.shields.io/github/license/efij/secure-claude-code">
  <img alt="Stars" src="https://img.shields.io/github/stars/efij/secure-claude-code">
  <img alt="Issues" src="https://img.shields.io/github/issues/efij/secure-claude-code">
  <img alt="Last Commit" src="https://img.shields.io/github/last-commit/efij/secure-claude-code">
</p>

## Why Runwall?

Coding agents are useful because they can read files, run shell commands, use git, connect to MCP tools, and increasingly work across more than one runtime.

That is also exactly why they need guardrails.

Runwall helps reduce real-world risk around:

- secret leakage
- agent session theft and desktop credential store access
- prompt injection and exfiltration paths
- indirect prompt injection hidden in files, web pages, shell output, and MCP responses
- unsafe shell execution
- dangerous git and repo actions
- SSH trust downgrades and audit evasion
- shell-profile, scheduled-task, and SSH-key persistence
- hosts-file and sudo-policy tampering
- plaintext git, netrc, and registry credential stores
- risky MCP and tool trust boundaries
- malicious skill, command, and instruction-doc poisoning
- cloud key creation and direct production shell access
- weak local defaults in agent workflows

It is practical, transparent, and built for real developer environments.

Runwall now supports four integration styles:

- native runtime adapters where hooks exist today, starting with Claude Code
- plugin or bundle installs for Codex and OpenClaw
- inline MCP gateway mode for Cursor, Windsurf, Claude Desktop, Claude Cowork, Codex fallback, and other MCP-capable clients
- CLI evaluation for pipeline and automation gates

## What It Does

Runwall helps you:

- scan agent/runtime config and produce a scored report before you install anything
- block high-confidence risky actions before they run
- enforce MCP tool calls inline before they reach upstream servers
- redact secret or prompt-smuggling content out of upstream tool responses
- require local review for suspicious multi-target MCP requests
- warn when tool output itself contains hidden prompt injection or jailbreak bait
- protect secrets, keys, tokens, and sensitive files
- block persistence through shell profiles, launch items, cron, systemd, and SSH authorized keys
- protect trusted config and instruction files from symlink hijack or stealth cleanup
- reduce dangerous shell, git, and repo behavior
- stop local trust-boundary tampering such as hosts-file remaps and sudoers weakening
- keep plaintext git, netrc, and registry credentials out of agent reach
- tighten MCP, plugin, skill, and tool trust boundaries
- block cloud key creation and direct prod-shell break-glass behavior
- apply a safer default profile quickly
- keep security useful without turning the workflow into sludge

It works well on top of Claude Code sandbox mode too. Sandboxing helps contain damage. Runwall adds guard logic on top of that containment layer.

## Who It Is For

- solo developers who want safer local AI coding
- startups moving fast but trying not to leak secrets or wreck repos
- security engineers and AppSec teams reviewing agent risk
- DevSecOps teams adopting MCP-based tools
- larger orgs that need a cleaner baseline before enterprise policy layers come later

It is much less relevant for plain chat-only usage where no tools, shell, git, or file actions are involved.

## Fast Install

The cleanest install path is now the plugin or bundle path for the runtime you already use.

### Claude Code Plugin

```text
/plugin marketplace add efij/secure-claude-code
/plugin install runwall@runwall
```

### Codex Plugin Bundle

This repo now ships a Codex bundle manifest in [`.codex-plugin/plugin.json`](/Users/efi.jeremiah/projects/secure-claude-code/.codex-plugin/plugin.json) and a shared MCP definition in [`.mcp.json`](/Users/efi.jeremiah/projects/secure-claude-code/.mcp.json).

If your Codex supports local plugin or bundle install, install this repo directly as `runwall` and restart Codex.

If you want the manual fallback:

```bash
./bin/runwall generate-runtime-config codex balanced
```

### OpenClaw Plugin Bundle

OpenClaw can install this repo directly as a compatible bundle because it detects Claude and Codex bundle markers and imports supported skills and MCP tools.

```bash
openclaw plugins install ./secure-claude-code
openclaw plugins list
openclaw plugins inspect runwall
openclaw gateway restart
```

Use the CLI path when you want profile switching, update, uninstall, doctor repair, runtime config generation, or a separate local install home.

### Cursor

Generate a Cursor-ready `mcp.json`:

```bash
./bin/runwall generate-runtime-config cursor balanced
```

Then place that output in the MCP config file Cursor expects on your machine.
It now points at the inline Runwall gateway instead of the older helper-only companion server.

### Windsurf

Generate a Windsurf-ready `mcp_config.json`:

```bash
./bin/runwall generate-runtime-config windsurf balanced
```

Then place that output in the MCP config file Windsurf expects on your machine.
It now points at the inline Runwall gateway instead of the older helper-only companion server.

### Claude Desktop

Generate a Claude Desktop-ready `claude_desktop_config.json`:

```bash
./bin/runwall generate-runtime-config claude-desktop balanced
```

Then merge that output into your Claude Desktop MCP config.
It now points at the inline Runwall gateway instead of the older helper-only companion server.

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/efij/secure-claude-code/main/scripts/bootstrap.sh | bash -s -- --repo efij/secure-claude-code --ref main --profile balanced
```

### Windows

```powershell
irm https://raw.githubusercontent.com/efij/secure-claude-code/main/scripts/bootstrap.ps1 | iex; Install-Runwall -Repo "efij/secure-claude-code" -Ref "main" -Profile "balanced"
```

### Local Checkout

```bash
git clone https://github.com/efij/secure-claude-code.git
cd secure-claude-code
./bin/runwall install balanced
```

`install.sh`, `update.sh`, and `uninstall.sh` still exist, but they are only thin compatibility wrappers around the main CLI.

## Quick Start

### Apply a safer baseline

```bash
./bin/runwall install balanced
```

### Run an audit first

```bash
./bin/runwall audit .
./bin/runwall audit . --format html --output runwall-audit.html
./bin/runwall audit . --format sarif --output runwall-audit.sarif --fail-on high
```

### Validate the setup

```bash
./bin/runwall doctor
./bin/runwall validate
```

### Review active protections

```bash
./bin/runwall list protections
```

### Review supported runtimes

```bash
./bin/runwall list runtimes
```

### Inspect recent blocks and warnings

```bash
./bin/runwall logs 20
./bin/runwall logs 50 --json
```

### Start the inline gateway and dashboard

```bash
./bin/runwall gateway serve strict --config ./config/gateway.json --api-port 9470
```

Then open `http://127.0.0.1:9470` to inspect events, redactions, and pending approvals.

### Generate a baseline CI workflow

```bash
./bin/runwall init .
```

That creates:

- `.runwall/audit-baseline.json`
- `.github/workflows/runwall-audit.yml`

## Multi-Runtime Support

Runwall is now structured around runtime adapters, bundle installs, and the inline MCP gateway:

- `Claude Code`: native hook mode with direct pre-tool and post-tool enforcement
- `Codex`: plugin bundle plus inline gateway fallback mode
- `OpenClaw`: compatible bundle install that maps Runwall skills and MCP tools into OpenClaw
- `Cursor`: generated `mcp.json` gateway config
- `Windsurf`: generated `mcp_config.json` gateway config
- `Claude Desktop`: generated `claude_desktop_config.json` gateway config
- `Generic MCP clients`: shared inline gateway mode for Claude Cowork and similar clients
- `CI/CD`: generated GitHub Actions snippet plus CLI policy evaluation for high-risk commands

The strategy is:

1. native enforcement where the runtime exposes hooks
2. plugin or bundle install where the runtime can consume Runwall directly
3. Inline MCP gateway mode where the runtime speaks MCP but does not expose equivalent hooks
4. CLI evaluation for pipeline and automation gates

For the runtime matrix and integration notes, see [RUNTIMES.md](RUNTIMES.md).

### Codex

```bash
./bin/runwall generate-runtime-config codex balanced
```

This prints:

- a `~/.codex/config.toml` inline gateway block
- a matching `AGENTS.md` snippet that tells Codex when to consult Runwall

If your Codex install supports local plugins, prefer the plugin or bundle path first and keep the generated config as the fallback.

### OpenClaw

```bash
openclaw plugins install ./secure-claude-code
```

OpenClaw detects this repo as a compatible Claude or Codex bundle and maps supported skills and MCP tools automatically.

### Cursor

```bash
./bin/runwall generate-runtime-config cursor balanced
```

### Windsurf

```bash
./bin/runwall generate-runtime-config windsurf balanced
```

### Claude Desktop

```bash
./bin/runwall generate-runtime-config claude-desktop balanced
```

### Generic MCP Clients

```bash
./bin/runwall generate-runtime-config generic-mcp balanced
```

Use the generic output for:

- Claude Cowork
- other MCP-native clients that accept a standard stdio MCP server block

### Inline MCP Gateway

```bash
./bin/runwall gateway serve strict --config ./config/gateway.json --api-port 9470
```

Gateway mode adds:

- multi-upstream MCP proxying
- `tools/list` interception
- `tools/call` interception
- request inspection before upstream execution
- response inspection after upstream execution
- actions: `allow`, `block`, `prompt`, `redact`
- local API and dashboard for health, live events, pending prompts, and approvals

### CI/CD

```bash
./bin/runwall generate-runtime-config ci strict
./bin/runwall evaluate PreToolUse Bash "kubectl --context prod apply -f deploy.yaml" --profile strict --json
```

### Local MCP Server

```bash
./bin/runwall mcp serve balanced
```

This starts the local Runwall MCP gateway with the default gateway config.

## Security Coverage

Runwall focuses on the practical execution surface around Claude Code.

### Shell

- dangerous command execution
- remote script and payload staging
- sandbox escape and trust-boundary abuse

### Secrets

- local secret file reads
- local agent session and desktop credential store access
- token paste and fixture leaks
- browser session and cluster secret access

### Git and Repo Actions

- destructive git operations
- audit evasion and stealth cleanup
- signing bypasses
- mass deletion and repo harvest patterns
- shell-profile, cron, launch-agent, systemd, and SSH authorized-key persistence
- hosts-file and sudo policy tampering

### MCP and Tools

- risky MCP permission grants
- risky MCP upstream source swaps
- MCP tool impersonation and schema widening
- MCP parameter smuggling and bulk sensitive read staging
- dangerous MCP server command chains
- secret env forwarding into MCP servers
- secret leaks, prompt smuggling, and binary payloads in MCP responses
- risky marketplace or install sources
- sideloaded plugin and extension paths
- untrusted tool origins

### Identity and Credential Material

- git credential stores and `.netrc`
- registry auth material in `.npmrc`, `.pypirc`, `.docker/config.json`, and similar files
- long-lived cloud key creation paths
- desktop credential stores and local agent session caches
- malicious skill install sources
- poisoned skill and Claude command docs
- multi-stage dropper chains hidden in trusted skill docs
- risky plugin manifest edits
- risky plugin update source swaps
- malicious plugin hook origins and execution chains
- plugin trust-boundary tampering
- weak local trust boundaries
- instruction bridges that tell the runtime to bypass Runwall or trust tool output over local policy
- trusted-config symlink redirection

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

- runtime security that stays close to the agent execution layer
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

Runwall writes local JSONL audit events for warnings and blocks.

Defaults:

- path: `~/.runwall/state/audit.jsonl`
- mode: `alerts`

Useful commands:

```bash
./bin/runwall logs
./bin/runwall logs 50 --decision block --since-hours 24
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
- skill poisoning and trusted-instruction abuse detection
- exfiltration and prompt-injection patterns, especially indirect prompt injection and output smuggling
- better developer UX without losing security value

Good places to start:

- [GUARDS.md](GUARDS.md)
- [SIGNATURES.md](SIGNATURES.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)

## Security Note

Runwall reduces risk. It does not eliminate risk.

You should still treat Claude Code, MCP tools, shell access, secrets, and repository operations as real security boundaries. This project is the local enforcement layer, not the whole security program.

## License

See [LICENSE](LICENSE).
