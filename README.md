# Secure Claude Code

![Local First](https://img.shields.io/badge/local--first-yes-1f883d)
![No Cloud Required](https://img.shields.io/badge/cloud-required--for--core-no-1f883d)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows%20(WSL%2FGit%20Bash)-0366d6)
![License](https://img.shields.io/badge/license-MIT-blue)

**Antivirus for Claude Code.**

Secure Claude Code is a local-first guardrail toolkit that blocks high-confidence AI-agent mistakes before they turn into leaks, broken history, or silent quality regressions.

It is designed to be the **must-install first security layer** for Claude Code:

- one-command install
- one-command uninstall
- low-noise defaults
- clear block reasons
- modular protection packs
- no account required
- smoke-tested locally
- CI-ready for GitHub publish

## Why This Repo Exists

Claude Code can move fast enough to:

- push secrets or live connection strings
- read `.env`, SSH keys, or cloud credentials
- force-push or hard-reset the wrong branch
- upload sensitive files through shell commands
- weaken tests by adding skip or focus markers
- casually touch deploy, auth, or infra files

Secure Claude Code aims for the sharp middle between tiny hook bundles and heavyweight governance products:

**real protection, small install, zero required cloud.**

## Quick Start

### macOS / Linux

```bash
git clone https://github.com/your-org/secure-claude-code.git
cd secure-claude-code
bash install.sh
```

### Windows

Use **Git Bash** or **WSL**:

```bash
git clone https://github.com/your-org/secure-claude-code.git
cd secure-claude-code
bash install.sh
```

Or from PowerShell if `bash` is available on your `PATH`:

```powershell
.\install.ps1
```

## Core Commands

```bash
./bin/secure-claude-code install balanced
./bin/secure-claude-code update
./bin/secure-claude-code validate
./bin/secure-claude-code doctor
./bin/secure-claude-code list protections
./bin/secure-claude-code logs 20
./bin/secure-claude-code logs 50 --json
./bin/secure-claude-code uninstall
```

## Verification

Local:

```bash
bash tests/smoke.sh
```

GitHub Actions CI runs the smoke suite on:

- Linux
- macOS
- Windows runners using `bash`

See [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Release Packaging

Build release assets and package manifests:

```bash
bash scripts/package-release.sh your-org/secure-claude-code 0.1.0
```

That generates:

- release tarball
- release zip
- SHA256 checksums
- Homebrew formula
- Scoop manifest

## Audit Log

Secure Claude Code writes local JSONL audit events for warnings and blocks by default.

- default path: `~/.secure-claude-code/state/audit.jsonl`
- default mode: `alerts`
- other modes: `all`, `off`

Examples:

```bash
./bin/secure-claude-code logs
./bin/secure-claude-code logs 50 --json
```

Environment variables:

- `SECURE_CLAUDE_CODE_AUDIT_MODE=alerts|all|off`
- `SECURE_CLAUDE_CODE_AUDIT_FILE=/custom/path/audit.jsonl`

## Profiles

- `minimal`: the tightest low-friction baseline
- `balanced`: the recommended default for most teams
- `strict`: adds stronger shell protections for higher-risk repos

## The Killer Features

### Easy install, easy update, easy removal

- [install.sh](install.sh)
- [update.sh](update.sh)
- [uninstall.sh](uninstall.sh)
- [install.ps1](install.ps1)
- [update.ps1](update.ps1)
- [uninstall.ps1](uninstall.ps1)

Secure Claude Code backs up and merges `settings.json` instead of telling users to hand-edit JSON.

### Protection packs instead of a giant script

Each protection is its own pack with its own manifest, hook, and default profile targeting.

Current packs:

- `abuse-chain-defense`
- `block-unsafe-git`
- `pre-push-scan`
- `protect-secrets-read`
- `network-exfiltration`
- `block-dangerous-commands`
- `protect-sensitive-files`
- `protect-tests`
- `post-edit-quality-reminder`

### Human-readable blocking

Every high-confidence block explains:

- what was blocked
- why it was risky
- what to do next

### Local JSON audit trail

- structured JSONL logs
- local-only by default
- useful for debugging, security review, and proving what got blocked

### Local-first health score

`./bin/secure-claude-code validate` reports:

- active profile
- registered packs
- pass/fail/warn counts
- health score out of 100
- overall posture

### Plain-text tuning

No hidden policy DSL required.

Tune behavior with:

- [config/protected-branches.txt](config/protected-branches.txt)
- [config/protected-paths.regex](config/protected-paths.regex)
- [config/secret-allowlist.regex](config/secret-allowlist.regex)
- [config/secret-paths.regex](config/secret-paths.regex)
- [config/test-paths.regex](config/test-paths.regex)

## Real-World Attack Coverage

### 1. Git sabotage and shortcut abuse

- blocks `--no-verify`
- blocks `--no-gpg-sign`
- blocks force-push on protected branches
- blocks `git reset --hard` on protected branches

### 2. Push-time leakage

- scans for likely secrets
- scans for internal IPs and internal hostnames
- scans for inline database and service connection strings

### 3. Secret-file targeting

- blocks direct reads of `.env`
- blocks reads of `.aws`, `.ssh`, kube config, key files, and credential files
- allows examples and templates to stay low-noise through allowlists

### 4. Outbound exfiltration attempts

- blocks suspicious `scp`, `rsync`, `curl`, `wget`, `aws s3 cp`, `gsutil cp`, `nc`, and similar transfer patterns
- only triggers when the command appears to include secret files, keys, databases, or dump/archive material

### 5. Dangerous shell behavior

- blocks `curl | bash`
- blocks `wget | sh`
- blocks recursive `chmod 777`
- blocks destructive deletes of very sensitive paths

### 6. Sensitive file awareness

Warns when the agent edits:

- env files
- lockfiles and package manifests
- workflows
- Docker and infra files
- cloud and SSH config

### 7. Test-integrity protection

Warns when the agent:

- edits test files
- introduces `.skip`, `.only`, `xdescribe`, `xit`, `pytest.mark.skip`, or similar markers
- introduces `eslint-disable`, `noqa`, `nolint`, `@ts-ignore`, coverage-ignore, or similar suppression markers

### 8. Abuse-chain and prompt-injection defense

- blocks remote writes into `CLAUDE.md`, `.claude/settings.json`, `.claude/hooks`, `.claude/rules`, and similar control files
- blocks classic rule-override or jailbreak language when it is being written into control files
- blocks secret-plus-encode/archive/transfer command chains

## Why This Is Different

| Area | Hook bundles | Governance products | Secure Claude Code |
|---|---|---|---|
| Easy install | yes | mixed | yes |
| Easy uninstall | mixed | mixed | yes |
| Local-first core | yes | mixed | yes |
| No account required | yes | often no | yes |
| Clear block guidance | mixed | mixed | yes |
| Modular packs | mixed | yes | yes |
| KISS defaults | mixed | rarely | yes |
| Windows path for users | mixed | mixed | yes |

**Secure Claude Code is the easiest serious hardening layer for Claude Code.**

## Platform Support

- macOS: supported
- Linux: supported
- Windows: supported through Git Bash or WSL

Secure Claude Code uses shell hooks, so the smoothest Windows experience today is Git Bash or WSL. The repo includes PowerShell wrappers for install, update, and uninstall.

## Project Layout

```text
secure-claude-code/
├── bin/secure-claude-code
├── hooks/
├── modules/
├── profiles/
├── config/
├── rules/common/
├── install.sh
├── update.sh
├── uninstall.sh
├── install.ps1
├── update.ps1
├── uninstall.ps1
├── ROADMAP.md
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

## Publish Checklist

- open source license: [LICENSE](LICENSE)
- security policy: [SECURITY.md](SECURITY.md)
- security model: [SECURITY_MODEL.md](SECURITY_MODEL.md)
- contributor guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- modular roadmap: [ROADMAP.md](ROADMAP.md)
- release workflow: [.github/workflows/release.yml](.github/workflows/release.yml)
- smoke test: [tests/smoke.sh](tests/smoke.sh)

## Must-Have Before GitHub Launch

- clear install/update/uninstall path
- smoke tests
- CI
- license
- security policy
- release packaging workflow
- real-world threat coverage docs

This repo now includes those.

## Must-Have Before Serious Pro Adoption

- strong local audit trail
- abuse-chain defense
- test deletion and check-suppression protection
- package distribution path
- versioned releases

This repo now includes the local-first version of those. Centralized governance, team policy layering, and enterprise controls stay out of scope for this edition.

## Roadmap

Secure Claude Code grows by adding focused packs, not by bloating the installer.

See [ROADMAP.md](ROADMAP.md).

## Inspiration

This project takes inspiration from:

- [renefichtmueller/claude-code-hardened](https://github.com/renefichtmueller/claude-code-hardened)
- [rulebricks/claude-code-guardrails](https://github.com/rulebricks/claude-code-guardrails)
- [wangbooth/Claude-Code-Guardrails](https://github.com/wangbooth/Claude-Code-Guardrails)
- [karanb192/claude-code-hooks](https://github.com/karanb192/claude-code-hooks)

The goal is not to clone them. The goal is to combine the best ideas:

- easy install
- obvious value
- real-world protection
- low-noise defaults
- modular growth

and turn that into the clearest first security install for Claude Code.
