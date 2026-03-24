# Roadmap

Secure Claude Code should stay small at the core and grow through modular protection packs.

## Current Core

- one-command install, update, uninstall
- profile-based setup: `minimal`, `balanced`, `strict`
- safe `settings.json` merge with backup and dedupe
- local-first protections with no required account
- validation, doctor mode, and health score
- real-world protection packs for git abuse, secret pushes, secret-file access, outbound exfiltration, sensitive files, and test-integrity warnings

## Near-Term Packs

- `protect-prod-config`: stricter deploy and infra file handling
- `prompt-injection-redflags`: warn on obviously suspicious retrieval/instruction patterns
- `test-deletion-guard`: block `git rm` or shell deletes that target test files
- `safe-branch-workflow`: optional branch auto-suggestion and PR-first workflow hints

## Nice Next Steps

- plugin marketplace packaging
- Cursor-compatible install target
- project-local policy overlay files
- richer health report with per-pack status
- signed release artifacts
- native Windows hook path without relying on bash-compatible shells

## Contribution Shape

Secure Claude Code grows by adding new packs, not by making the installer more complex.

Good contributions:

- one focused protection pack
- one new profile if it is broadly useful
- one config file that keeps policy editable without touching code
- one validator check that helps users trust the install

Avoid:

- cloud-only features as the default path
- invasive dependencies for a single pack
- giant “kitchen sink” scripts that mix several concerns
