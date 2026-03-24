# Contributing

Secure Claude Code is meant to feel like antivirus for Claude Code: small install, obvious value, low noise.

## Product Rules

- local-first beats cloud-first
- high-confidence blocks beat noisy heuristics
- safe install beats clever install
- plain-text config beats hidden magic
- one focused protection pack beats one giant script

## Add A New Protection Pack

1. Create `modules/<pack-id>/module.json`
2. Add the hook script in `hooks/<pack-id>.sh`
3. Add any plain-text defaults in `config/` if needed
4. Add the pack to one or more profiles in `profiles/*.txt`
5. Update `README.md` and `ROADMAP.md` if the pack changes product positioning
6. If the change affects onboarding, update the PowerShell wrappers or platform docs too

## Pack Checklist

- the pack solves one clear risk
- the block or warning is understandable in one glance
- the message explains `reason` and `next`
- the config can be tuned without editing the hook when possible
- the behavior is safe to reinstall and easy to remove
- the pack keeps macOS, Linux, and Windows users in mind

## Pack Template

```json
{
  "id": "protect-tests",
  "name": "Test Integrity Pack",
  "description": "Warns or blocks when tests are removed or disabled.",
  "category": "quality",
  "kind": "warn",
  "default_profiles": ["strict"],
  "rules": [
    "workflow.md",
    "review-checklist.md"
  ],
  "hook": {
    "event": "PostToolUse",
    "matcher": "Write|Edit|MultiEdit",
    "type": "command",
    "command": "bash ~/.secure-claude-code/hooks/protect-tests.sh \"$TOOL_INPUT\""
  }
}
```

## Validation

Before opening a PR, run:

```bash
bash -n bin/shield bin/secure-claude-code install.sh uninstall.sh update.sh scripts/*.sh hooks/*.sh
./bin/secure-claude-code list protections
./bin/secure-claude-code generate-config balanced
```

If you add install behavior, also do a temp-home smoke test.
