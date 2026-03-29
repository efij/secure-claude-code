# Runtime Support

Runwall is now organized around runtime adapters instead of assuming Claude Code is the only surface.

## Support Matrix

| Runtime | Mode | Status | Notes |
| --- | --- | --- | --- |
| Claude Code | Native hooks | First-class | Direct pre-tool and post-tool enforcement |
| Codex | Plugin bundle + inline gateway fallback | Supported | `.codex-plugin/plugin.json` plus generated fallback config |
| OpenClaw | Compatible bundle install | Supported | Installs this repo as a Claude/Codex bundle and maps skills + MCP |
| Cursor | Inline MCP gateway | First-class | Generated `mcp.json` config |
| Windsurf | Inline MCP gateway | First-class | Generated `mcp_config.json` config |
| Claude Desktop | Inline MCP gateway | First-class | Generated `claude_desktop_config.json` config |
| Claude Cowork | Inline MCP gateway | Generic path | Use `generic-mcp` where MCP config import is available |
| Generic MCP clients | Inline MCP gateway | Supported | Use the generated generic MCP config |
| CI/CD | CLI policy gate | Supported | Use `generate-runtime-config ci` plus `runwall evaluate` |

## Architecture

Runwall now has four layers:

1. Native adapters
   Claude Code remains the strongest integration because it exposes direct hook points.

2. Plugin and bundle adapters
   Codex and OpenClaw can consume this repo as a plugin or compatible bundle surface.

3. Inline MCP gateway mode
   Cursor, Windsurf, Claude Desktop, Codex fallback mode, and other MCP-native clients can run Runwall as a local inline gateway that:
   - fronts multiple upstream MCP servers
   - intercepts `tools/list`
   - intercepts `tools/call`
   - evaluates requests before upstream execution
   - evaluates responses before they reach the client
   - supports `allow`, `block`, `prompt`, and `redact`
   - applies per-profile outbound destination policy before risky egress leaves the runtime
   - exposes response redaction, response prompt, and egress decisions through the local API and dashboard

   It also keeps the policy helper tools:
   - `preflight_bash`
   - `preflight_read`
   - `preflight_write`
   - `inspect_output`

4. CLI policy evaluation
   CI systems and local automation can call `./bin/runwall evaluate ...` to gate high-risk commands or content without a full interactive runtime.

## Commands

```bash
./bin/runwall list runtimes
./bin/runwall generate-runtime-config codex balanced
./bin/runwall generate-runtime-config cursor balanced
./bin/runwall generate-runtime-config windsurf balanced
./bin/runwall generate-runtime-config claude-desktop balanced
./bin/runwall generate-runtime-config generic-mcp balanced
./bin/runwall generate-runtime-config ci strict
./bin/runwall gateway serve strict --config ./config/gateway.json --api-port 9470
./bin/runwall mcp serve balanced
./bin/runwall evaluate PreToolUse Bash "git push --force origin main" --profile strict --json
openclaw plugins install ./secure-claude-code
```

## Positioning

Runwall is no longer just a Claude Code hardening repo.

It is:

- Claude Code first
- Codex plugin bundle next
- OpenClaw compatible bundle install
- Cursor, Windsurf, and Claude Desktop as first-class inline gateway targets
- generic MCP client mode after that
- CI/CD policy gate mode on top

That keeps the strongest adapter where hooks exist today while opening the product up to multi-runtime adoption instead of capping it to a single client.
