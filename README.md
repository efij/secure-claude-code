# Stallion

Runtime security guardrails for Claude Code, Codex, and MCP-based coding setups.

Stallion sits between the agent and risky actions so you can:

- block obvious bad shell, git, MCP, and exfiltration flows
- scan a repo or runtime setup before enabling it
- keep a practical security baseline without turning normal coding into sludge

<p align="left">
  <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/efij/stallion/ci.yml?branch=main&label=smoke">
  <img alt="Release" src="https://img.shields.io/github/v/release/efij/stallion">
  <img alt="License" src="https://img.shields.io/github/license/efij/stallion">
</p>

## Why Use It

Coding agents can:

- run shell commands
- edit files
- push git changes
- call MCP tools
- touch secrets, browsers, databases, and local services

That is useful, but it is also enough to leak data or damage a machine fast.

Stallion helps reduce that risk with:

- preflight checks before risky actions run
- output inspection after tools return untrusted content
- local trust tracking for tools, hooks, data stores, IPC targets, and approvals
- installable profiles: `minimal`, `balanced`, and `strict`

## Fast Start

### Claude Code

```bash
claude plugin marketplace add efij/stallion
claude plugin install stallion@stallion
claude plugin list
```

Expected result:

- `stallion@stallion`
- `Status: enabled`

### Codex

If your Codex supports local bundle install, install this repo as a plugin bundle.

Fallback:

```bash
./bin/stallion generate-runtime-config codex balanced
```

### Local CLI Install

```bash
git clone https://github.com/efij/stallion.git
cd stallion
./bin/stallion install balanced
./bin/stallion doctor
```

## Profiles

- `minimal`: lowest friction
- `balanced`: sensible default
- `strict`: strongest blocking and review prompts

## What It Protects

- shell execution
- git and repo actions
- MCP requests and responses
- plugin and skill trust boundaries
- secrets and local credential stores
- local services, IPC, and browser sessions
- destructive actions and production access

<details>
<summary><strong>Protection families</strong></summary>

- `Secrets & Identity`
- `Supply Chain & Dependencies`
- `Git & Source Control`
- `MCP, Plugins & Skills`
- `Runtime, Network & Egress`
- `Infra & Production Access`
- `Trust, Persistence & Evasion`
- `Quality & Workflow`
- `Memory & Knowledge`
- `SaaS & Control Planes`
- `Fileless & Inline Execution`
- `Remote Content Promotion`
- `Local Data Stores`
- `Local IPC & Helpers`
- `Publish, Release & Supply Chain`
- `Destructive Actions & Blast Radius`

Full guard inventory: `GUARDS.md`
</details>

## Common Commands

```bash
./bin/stallion install balanced
./bin/stallion doctor
./bin/stallion audit .
./bin/stallion list protections
./bin/stallion list runtimes
./bin/stallion wrap list-packs
./bin/stallion wrap add postgres-dev --command uvx --arg mcp-server-postgres --pack postgres --context-file ./db-context.md --runtime generic-mcp
./bin/stallion client status --json
./bin/stallion generate-runtime-config codex balanced
./bin/stallion generate-runtime-config cursor balanced
./bin/stallion generate-runtime-config windsurf balanced
./bin/stallion generate-runtime-config claude-desktop balanced
```

## Stallion Managed Client

This OSS plugin can run as a Stallion-managed client. The private Stallion server/admin repo owns policy authoring, RBAC, audit warehousing, and organization governance; this repo only consumes signed or cached policy and enforces it locally.

Client-side support includes:

- managed MCP server and tool allow/deny policy
- required-route blocking when a capability must use an approved MCP instead of direct CLI/API access
- plugin and skill positive authorization
- prompt and policy-decision telemetry queueing when a runtime exposes the prompt/event
- offline policy cache with optional fail-closed behavior

Local commands:

```bash
./bin/stallion client status --json
./bin/stallion client policy --json
./bin/stallion client record-prompt --runtime codex --agent-id parent-1 "user prompt text"
./bin/stallion client flush
```

Default config is disabled at `config/stallion-client.json`; managed deployments should provision the server URL, policy cache, verification mode, and fail-closed posture.

## MCP Wrap Flow

Use the inline gateway when you want to front an upstream MCP server with Stallion policy, context injection, and read-only SQL guardrails.

```bash
./bin/stallion wrap list-packs
./bin/stallion wrap add postgres-dev \
  --command uvx \
  --arg mcp-server-postgres \
  --pack postgres \
  --context-file ./db-context.md \
  --sqlite-schema ./local-dev.sqlite3 \
  --runtime generic-mcp
./bin/stallion gateway serve strict --config ./config/gateway.json --api-port 9470
./bin/stallion generate-runtime-config generic-mcp balanced
```

What this adds:

- built-in service packs for common MCP surfaces like `postgres`, `supabase`, `github`, and `filesystem`
- schema or operator context injected into matching tool descriptions during `tools/list`
- read-only SQL enforcement for configured MCP query tools before the request reaches the upstream server

<details>
<summary><strong>Advanced trust-plane commands</strong></summary>

```bash
./bin/stallion tools list --json
./bin/stallion tools approve <name-or-path>
./bin/stallion hooks list --json
./bin/stallion hooks diff <path-or-key>
./bin/stallion approvals list --json
./bin/stallion services list --json
./bin/stallion data list --json
./bin/stallion ipc list --json
./bin/stallion browser sessions --json
./bin/stallion flow list --json
./bin/stallion agents graph --json
./bin/stallion memory list --json
./bin/stallion knowledge list --json
./bin/stallion review list --json
./bin/stallion artifacts list --json
./bin/stallion release list --json
./bin/stallion destructive list --json
./bin/stallion handoff graph --json
./bin/stallion auth list --json
./bin/stallion apps list --json
./bin/stallion safety list --json
```
</details>

## Supported Runtimes

| Runtime | Status | How |
| --- | --- | --- |
| Claude Code | First-class | native plugin hooks |
| Codex | Supported | plugin bundle or generated MCP config |
| Cursor | Supported | generated `mcp.json` |
| Windsurf | Supported | generated `mcp_config.json` |
| Claude Desktop | Supported | generated `claude_desktop_config.json` |
| Generic MCP clients | Supported | inline MCP gateway |
| CI | Supported | CLI policy checks |

More detail: `RUNTIMES.md`

## Audit First

If you want to inspect before enabling:

```bash
./bin/stallion audit .
./bin/stallion audit . --format html --output stallion-audit.html
./bin/stallion audit . --format sarif --output stallion-audit.sarif
```

## Troubleshooting

### Claude plugin says `failed to load`

Run:

```bash
claude plugin uninstall stallion@stallion
claude plugin marketplace remove stallion
claude plugin marketplace add efij/stallion
claude plugin install stallion@stallion
claude plugin list
```

You want:

- `Status: enabled`

If GitHub still serves an older broken marketplace state, install from a local checkout until the fix is pushed:

```bash
cd ..
git clone https://github.com/efij/stallion.git
claude plugin marketplace add ./stallion
claude plugin install stallion@stallion
```

### CI is failing

Run the local smoke checks:

```bash
bash tests/smoke.sh
```

If you only want the quick sanity path:

```bash
bash -n bin/shield install.sh update.sh uninstall.sh hooks/lib/patterns.sh tests/smoke.sh
python3 -m py_compile scripts/stallion_tools.py
./bin/stallion generate-plugin-hooks balanced /tmp/stallion-hooks.json
claude plugin validate .
```

## Install Methods

<details>
<summary><strong>More install options</strong></summary>

### macOS / Linux bootstrap

```bash
curl -fsSL https://raw.githubusercontent.com/efij/stallion/main/scripts/bootstrap.sh | bash -s -- --repo efij/stallion --ref main --profile balanced
```

### Windows bootstrap

```powershell
irm https://raw.githubusercontent.com/efij/stallion/main/scripts/bootstrap.ps1 | iex; Install-Stallion -Repo "efij/stallion" -Ref "main" -Profile "balanced"
```

### Thin compatibility wrappers

- `install.sh`
- `update.sh`
- `uninstall.sh`

They forward to `./bin/stallion`.
</details>

## Project Docs

- `GUARDS.md`: guard inventory
- `RUNTIMES.md`: runtime adapters
- `SECURITY_MODEL.md`: model and assumptions
- `CHANGELOG.md`: release notes
- `CONTRIBUTING.md`: contributor notes

## License

MIT
