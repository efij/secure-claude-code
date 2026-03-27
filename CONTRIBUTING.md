# Contributing

Runwall is designed around small, reviewable protection packs instead of a single growing script.

## Contribution Principles

- prefer high-confidence protections over noisy heuristics
- keep install, update, and uninstall boring and reliable
- keep configuration editable in plain text when possible
- design packs so they can be enabled or disabled cleanly by profile
- favor narrow, explainable behavior over broad magic

## Adding A Protection Pack

1. Create `modules/<pack-id>/module.json`.
2. Add the hook implementation in `hooks/`.
3. Add any default config in `config/` when tuning should stay user-editable.
4. Add the pack to one or more profiles in `profiles/*.txt`.
5. Update `README.md` if the pack changes default coverage or install guidance.
6. Update `ROADMAP.md` if the pack closes or changes a planned area.

## Pack Quality Bar

- the pack addresses one clear risk
- the message is understandable at a glance
- the output explains `reason` and `next`
- the behavior is safe to reinstall
- the behavior is easy to remove
- the design works for macOS, Linux, and shell-based Windows paths

## Example Manifest

```json
{
  "id": "protect-tests",
  "name": "Test Integrity Pack",
  "description": "Warns or blocks when tests are removed or weakened.",
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
    "command": "bash ~/.runwall/hooks/protect-tests.sh \"$TOOL_INPUT\""
  }
}
```

## Validation

Run before opening a PR:

```bash
bash -n bin/shield bin/runwall install.sh uninstall.sh update.sh scripts/*.sh hooks/*.sh
./bin/runwall list protections
./bin/runwall generate-config balanced
bash tests/smoke.sh
```
