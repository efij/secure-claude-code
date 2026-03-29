# Runtime Support

Runwall is now organized around runtime adapters instead of assuming Claude Code is the only surface.

## Support Matrix

| Runtime | Mode | Status | Notes |
| --- | --- | --- | --- |
| Claude Code | Native hooks | First-class | Direct pre-tool and post-tool enforcement |
| Codex | Plugin bundle + MCP companion | Supported | `.codex-plugin/plugin.json` plus generated fallback config |
| OpenClaw | Compatible bundle install | Supported | Installs this repo as a Claude/Codex bundle and maps skills + MCP |
| Cursor | MCP companion | Supported via generic mode | Uses the shared MCP server block |
| Windsurf | MCP companion | Supported via generic mode | Uses the shared MCP server block |
| Claude Desktop | MCP companion | Supported via generic mode | Uses the shared MCP server block |
| Claude Cowork | MCP companion | Supported via generic mode | Uses the shared MCP server block |
| Generic MCP clients | MCP companion | Supported | Use the generated generic MCP config |
| CI/CD | CLI policy gate | Supported | Use `generate-runtime-config ci` plus `runwall evaluate` |

## Architecture

Runwall now has three layers:

1. Native adapters
   Claude Code remains the strongest integration because it exposes direct hook points.

2. Plugin and bundle adapters
   Codex and OpenClaw can consume this repo as a plugin or compatible bundle surface.

3. Companion MCP mode
   For Codex and other MCP-native clients, Runwall can also run as a local MCP server and expose policy tools such as:
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
./bin/runwall generate-runtime-config generic-mcp balanced
./bin/runwall generate-runtime-config ci strict
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
- generic MCP client mode after that
- CI/CD policy gate mode on top

That keeps the strongest adapter where hooks exist today while opening the product up to multi-runtime adoption instead of capping it to a single client.
