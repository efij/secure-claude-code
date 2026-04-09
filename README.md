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
- delegated OAuth logins, cloud impersonation, and secret-manager abuse
- agent session theft and desktop credential store access
- browser remote-debugging exposure and local trust-store tampering
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
- inline config secret pastes, poisoned reports, unexpected registry logins, and direct prod database shells
- git remote rewires, package source swaps, self-hosted CI runner exposure, and SSH command-hook abuse
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
- scan MCP tool responses before they reach the runtime
- redact secret or prompt-smuggling content out of upstream tool responses while keeping JSON valid where possible
- block staged shell snippets and risky response payloads before they turn into follow-on execution
- fingerprint trusted MCP servers and tools over time instead of trusting same-name metadata forever
- detect server drift, schema drift, capability expansion, and same-name tool collisions before trust quietly widens
- fingerprint executed CLI tools and local scripts so raw command execution gets a trust plane too, not just MCP traffic
- catch trusted-name shadowing, temp/download execution, first-seen unreviewed PATH tools, and tool drift over time
- require local review for suspicious multi-target MCP requests
- enforce outbound destination policy for private IPs, metadata endpoints, webhooks, paste sites, raw gist-style hosts, and non-allowlisted egress
- warn when tool output itself contains hidden prompt injection or jailbreak bait
- protect secrets, keys, tokens, and sensitive files
- block persistence through shell profiles, launch items, cron, systemd, and SSH authorized keys
- stop delegated cloud login and role-assumption flows from silently minting broader access
- catch secret-manager pulls, inline config secret drops, and build-time container secret leaks
- catch browser session exposure through remote debugging, package auth secrets in config, and secret-bearing files entering public artifacts
- protect trusted config and instruction files from symlink hijack or stealth cleanup
- reduce dangerous shell, git, and repo behavior
- stop local trust-boundary tampering such as hosts-file remaps and sudoers weakening
- pause git remote rewires, package source swaps, and local CA trust changes before trust silently widens
- keep plaintext git, netrc, and registry credentials out of agent reach
- flag unreviewed registry logins and block direct prod-database shell access
- tighten MCP, plugin, skill, and tool trust boundaries
- block cloud key creation, destructive Terraform flows, privileged container escape, prod-shell break-glass behavior, risky prod `kubectl exec`, and direct production data dumps
- explain every runtime decision with masked previews, evidence, confidence, and a safer alternative
- export masked incident bundles for review, triage, and post-incident handoff
- apply a safer default profile quickly
- keep security useful without turning the workflow into sludge

It works well on top of Claude Code sandbox mode too. Sandboxing helps contain damage. Runwall adds guard logic on top of that containment layer.

## Tool Trust Plane

Runwall now treats executed CLIs as a second trust plane beside MCP.

That matters because a lot of modern agent power flows through local tools, generated CLIs, wrapper scripts, and PATH-injected helpers that never show up as MCP servers.

The built-in tool trust layer fingerprints executed tools, stores local trust state in Runwall state files, typically `~/.runwall/state/tools.json` when installed, and intervenes on a few high-confidence cases:

- trusted-name shadowing like fake `git`, `gh`, `kubectl`, `terraform`, `claude`, or `codex`
- PATH-prepend hijacks where a local tool intercepts a trusted system command before the reviewed binary in `PATH`
- execution from temp, cache, or download paths
- first-seen unreviewed PATH tools
- newly generated local executables that appear and run before they have been reviewed
- tool drift where a previously approved command changes path, hash, or wrapper shape
- shell alias and function hijacks for trusted tool names
- risky one-shot package runners such as `npx`, `pnpm dlx`, `yarn dlx`, `uvx`, `pipx run`, and `bunx` when they point at mutable or remote sources
- symlinked tool swaps where the same local command name silently points somewhere else

You can inspect and manage that local trust state with:

```bash
./bin/runwall tools list
./bin/runwall tools list --json
./bin/runwall tools approve <name-or-path>
./bin/runwall tools forget <name-or-path>
```

## Hook Trust Plane

Runwall now treats piggyback hooks as a third trust plane beside MCP and raw tool execution.

That matters because a lot of quiet hijack paths do not look like “new malware.” They look like small edits to normal workflow triggers:

- git hooks
- package install scripts like `preinstall` and `prepare`
- plugin hook manifests
- shell startup files
- CI and editor task glue

The built-in hook trust layer keeps a local registry in Runwall state files, typically `~/.runwall/state/hooks.json` when installed, and intervenes on a few high-confidence cases:

- first-seen review for hook-bearing surfaces that can execute during normal workflows
- hook drift after a previously reviewed hook changes its body
- hook origins that jump to temp, download, cache, or remote execution paths
- hook bodies that read local secret stores, cloud credentials, SSH material, or agent auth state
- hook bodies that tamper with Runwall, MCP, plugin, or instruction control files
- hook bodies that archive local data and immediately upload it out
- hook bodies that embed production break-glass access like `kubectl exec`, prod database shells or dumps, and destructive infra commands
- hook bodies that carry `--no-verify`, hook-disabling flags, or review-bypass language
- hook wrapper escalation through inline `bash -c`, `python -c`, `node -e`, or encoded PowerShell
- hook fanout that adds outbound network, upload, or tunnel behavior to an implicit trigger
- stealthy background or delayed persistence hidden inside hooks

You can inspect and manage that local trust state with:

```bash
./bin/runwall hooks list
./bin/runwall hooks list --json
./bin/runwall hooks diff <path-or-key>
./bin/runwall hooks approve <path-or-key>
./bin/runwall hooks forget <path-or-key>
```

## Sensitive Flow, Services, Browser, and Agent Graph

Runwall now adds four more native trust planes on top of tools and hooks:

- `Sensitive Data Flow`: tracks when a session touches secrets or production data, then blocks exports, clipboard bridges, archive prep, public-artifact writes, browser-session uploads, and cross-agent laundering later in the same session
- `Local Service Trust`: treats local sockets, localhost admin APIs, browser debug ports, Docker APIs, DBus, metadata endpoints, local databases, and kube control-plane targets as trust targets instead of invisible localhost traffic
- `Browser Session Defense`: prompts or blocks browser automation against sensitive logged-in domains, especially when the flow exports cookies, screenshots, DOM dumps, bulk captures, or executable downloads
- `Agent Graph & Isolation`: records parent/subagent relationships, lets you isolate risky agents, blocks cross-agent secret or browser-export laundering, and prompts when a session fans out across too many agents before outbound actions
- `Memory Trust`: treats persistent agent and project memory stores as reviewed trust surfaces instead of letting poisoned memory silently persist across sessions
- `Knowledge / RAG Trust`: treats vaults, Obsidian-style notes, RAG caches, mirrored issues, and imported knowledge docs as a separate trust plane with quarantine and drift controls
- `SaaS Action Trust`: prompts or blocks only on high-risk authenticated control-plane actions such as token minting, secret admin, role grants, prod deploys, webhook changes, and destructive deletes
- `Approval Integrity`: narrows risky exceptions so one-shot approvals cannot be replayed, approvals do not drift silently across runtimes or repos, and broad wildcard approvals are surfaced before they turn into policy bypass
- `Safety-Control Trust`: protects the things attackers disable first: audit trails, rollback scripts, backups, monitoring, alert sinks, incident bundles, and release safety checks
- `Fileless / Inline Execution Trust`: blocks remote fetch-and-exec, encoded loaders, env-driven payloads, inline persistence, and policy-bypass chains that try to avoid leaving a normal executable on disk
- `Remote Content Promotion Trust`: blocks remote or pasted content from being promoted directly into trusted memory, knowledge, hook, policy, script, and agent-instruction surfaces
- `Local Data Store Trust`: prompts or blocks on local SQLite, Redis, PostgreSQL, browser storage, vector-store, and app-cache export paths before they silently turn into data-extraction flows
- `Local IPC / Helper Trust`: treats local helper sockets, sidecars, local LLM endpoints, IDE backends, credential helpers, and named pipes as first-class trust boundaries
- `Publish / Release Intent Trust`: prompts or blocks on package publishes, image pushes, binary release uploads, registry retargeting, signing bypass, and manifest-level release target drift
- `Destructive Intent Trust`: blocks or prompts on broad deletes, infra teardown, repo wipes, state destruction, bulk disable loops, and other obvious high-blast-radius actions

Runwall also now has scoped approvals so these planes stay usable without turning the default policy into mush:

```bash
./bin/runwall approvals list --json
./bin/runwall approvals create --kind service --target browser-debug --value http://127.0.0.1:9222 --once
./bin/runwall approvals revoke <id-or-value>
./bin/runwall approvals prune
./bin/runwall approvals diff <id-or-value>
./bin/runwall approvals explain <id-or-value>

./bin/runwall services list --json
./bin/runwall services approve <target>
./bin/runwall services diff <target>

./bin/runwall data list --json
./bin/runwall data approve <target>
./bin/runwall data diff <target>

./bin/runwall release list --json
./bin/runwall release approve <target> --once
./bin/runwall release diff <target>
./bin/runwall release policy --json

./bin/runwall ipc list --json
./bin/runwall ipc approve <target>
./bin/runwall ipc diff <target>

./bin/runwall destructive list --json
./bin/runwall destructive explain <event-id>
./bin/runwall destructive policy --json

./bin/runwall browser sessions --json
./bin/runwall browser allow github.com
./bin/runwall browser policy --json

./bin/runwall flow list --json
./bin/runwall flow explain <session-id>
./bin/runwall flow clear [session-id]

./bin/runwall agents graph --json
./bin/runwall agents explain <session-id>
./bin/runwall agents isolate <agent-id>
./bin/runwall agents unisolate <agent-id>

./bin/runwall memory list --json
./bin/runwall memory trust <path>
./bin/runwall memory quarantine <path>
./bin/runwall memory diff <path>

./bin/runwall exec list --json
./bin/runwall exec explain <event-id-or-module>
./bin/runwall exec policy --json

./bin/runwall knowledge list --json
./bin/runwall knowledge trust <path>
./bin/runwall knowledge quarantine <path>
./bin/runwall knowledge diff <path>

./bin/runwall promotion list --json
./bin/runwall promotion trust <path>
./bin/runwall promotion quarantine <path>
./bin/runwall promotion diff <path>

./bin/runwall apps list --json
./bin/runwall apps explain <event-id>
./bin/runwall apps policy --json

./bin/runwall safety list --json
./bin/runwall safety diff <path-or-surface>
./bin/runwall safety forget <path-or-surface>
```

High-signal built-ins in these planes now include:

- `clipboard-secret-flow-guard`
- `secret-archive-prep-guard`
- `browser-session-upload-guard`
- `cross-agent-browser-export-guard`
- `metadata-endpoint-service-guard`
- `local-kube-admin-guard`
- `database-admin-service-guard`
- `browser-session-cookie-guard`
- `browser-bulk-capture-guard`
- `browser-download-dropper-guard`
- `isolated-parent-bridge-guard`
- `agent-fanout-guard`
- `memory-source-review-guard`
- `memory-drift-guard`
- `memory-remote-ingest-guard`
- `memory-prompt-smuggling-guard`
- `memory-policy-override-guard`
- `memory-secret-harvest-instruction-guard`
- `memory-exfil-instruction-guard`
- `memory-hidden-encoding-guard`
- `memory-tool-trust-override-guard`
- `memory-quarantine-bypass-guard`
- `knowledge-source-review-guard`
- `knowledge-drift-guard`
- `knowledge-remote-ingest-guard`
- `knowledge-prompt-smuggling-guard`
- `knowledge-policy-override-guard`
- `knowledge-secret-harvest-instruction-guard`
- `knowledge-exfil-instruction-guard`
- `knowledge-hidden-encoding-guard`
- `knowledge-rag-cache-dropper-guard`
- `knowledge-tool-install-bridge-guard`
- `knowledge-quarantine-bypass-guard`
- `app-token-mint-guard`
- `app-secret-admin-guard`
- `app-role-grant-guard`
- `app-prod-deploy-guard`
- `app-bulk-export-guard`
- `app-protection-disable-guard`
- `app-destroy-action-guard`
- `app-webhook-admin-guard`
- `app-member-invite-guard`
- `app-admin-browser-mutation-guard`
- `inline-fetch-exec-guard`
- `inline-encoded-loader-guard`
- `inline-env-payload-guard`
- `inline-policy-bypass-guard`
- `remote-to-memory-promotion-guard`
- `remote-to-knowledge-promotion-guard`
- `remote-to-hook-promotion-guard`
- `remote-to-policy-promotion-guard`
- `remote-to-script-promotion-guard`
- `raw-host-promotion-guard`
- `sqlite-dump-guard`
- `postgres-local-dump-guard`
- `browser-indexeddb-export-guard`
- `vector-store-export-guard`
- `credential-helper-ipc-guard`
- `local-llm-socket-guard`
- `ide-backend-ipc-guard`
- `ipc-wrapper-bridge-guard`
- `ipc-export-bridge-guard`

## Protection Families

Runwall now groups signatures into stable families so the product reads like a real signature engine instead of a flat list:

- `Secrets & Identity`: tokens, sessions, credential stores, secret managers, and delegated auth flows
- `Supply Chain & Dependencies`: registries, CI, artifacts, release paths, and provider trust
- `Git & Source Control`: remotes, provenance, history safety, and hook-based repo abuse
- `MCP, Plugins & Skills`: MCP servers, tools, plugins, skills, instruction files, and prompt-smuggling paths
- `Runtime, Network & Egress`: droppers, tunnels, exfiltration, metadata, and outbound control
- `Infra & Production Access`: clusters, databases, infrastructure tooling, and production break-glass behavior
- `Trust, Persistence & Evasion`: persistence, trust downgrades, audit wiping, symlink hijack, and boundary tampering
- `Quality & Workflow`: workflow integrity, context policy, test suppression, and destructive cleanup
- `Memory & Knowledge`: persistent memory, imported notes, vaults, RAG caches, and mirrored knowledge surfaces
- `SaaS & Control Planes`: authenticated control-plane actions against GitHub, Vercel, Stripe, Supabase, cloud consoles, and similar admin surfaces
- `Fileless & Inline Execution`: inline shells, interpreter one-liners, process substitution, heredoc loaders, and other fileless execution shapes
- `Remote Content Promotion`: remote or pasted content being promoted into trusted local authority surfaces such as memory, hooks, policy, scripts, and agent docs
- `Local Data Stores`: local databases, browser storage, vector indexes, app caches, and export paths that can leak sensitive workstation state
- `Local IPC & Helpers`: sidecars, IDE backends, local model endpoints, credential helpers, and named-pipe or socket control paths
- `Publish, Release & Supply Chain`: release edges, registries, manifests, image pushes, artifact uploads, and signing or provenance bypass
- `Destructive Actions & Blast Radius`: obvious high-impact teardown, wipe, revoke, or delete paths that need narrow review

You can inspect the active registry by family with:

```bash
./bin/runwall list protections
```

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

The output is grouped by guard family, then by guard id and action type.

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

The dashboard now makes three flows explicit:

- request-side blocks and prompts before upstream execution
- response-side redaction, prompts, and blocks before tool output reaches the runtime
- outbound destination decisions for metadata endpoints, private IPs, webhooks, paste sites, gist-like hosts, and non-allowlisted egress

It also shows:

- tool and server identity drift with baseline-vs-current diffs
- masked request and response previews by default
- exportable incident bundles for a single event, drift review, or runtime investigation

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
- tool and server fingerprinting with first-sight review, server drift, schema drift, capability expansion, and same-name collision detection
- deterministic response scanning for secrets, prompt smuggling, suspicious outbound URLs, and staged shell snippets
- per-profile outbound policy for private IPs, metadata endpoints, webhooks, paste sites, gist-like hosts, blob storage, and non-allowlisted destinations
- local API and dashboard for health, live events, pending prompts, approvals, diff views, masked previews, and incident bundle export

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
