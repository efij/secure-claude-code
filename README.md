# Secure Claude Code

![Local First](https://img.shields.io/badge/local--first-yes-1f883d)
![No Cloud Required](https://img.shields.io/badge/cloud-required--for--core-no-1f883d)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows%20(WSL%2FGit%20Bash)-0366d6)
![License](https://img.shields.io/badge/license-MIT-blue)

Local guardrails for Claude Code.

Secure Claude Code installs a focused set of hook-based protections around Claude Code so risky actions are blocked before they become leaked secrets, damaged git history, or silent quality regressions.

## What It Protects

- unsafe git actions on protected branches
- push-time secrets and live connection strings
- direct reads of local secret material such as `.env`, cloud credentials, SSH keys, and kube config
- suspicious outbound transfers involving sensitive files or dump material
- remote-content writes into Claude control files
- prompt-injection style rule override attempts written into control files
- test deletion, skip/focus markers, and common quality-check suppression patterns

## Quick Start

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/your-org/secure-claude-code/main/scripts/bootstrap.sh | bash -s -- --repo your-org/secure-claude-code --ref main --profile balanced
```

Or install from a local checkout:

```bash
git clone https://github.com/your-org/secure-claude-code.git
cd secure-claude-code
bash install.sh
```

### Windows

PowerShell bootstrap:

```powershell
irm https://raw.githubusercontent.com/your-org/secure-claude-code/main/scripts/bootstrap.ps1 | iex; Install-SecureClaudeCode -Repo "your-org/secure-claude-code" -Ref "main" -Profile "balanced"
```

Git Bash or WSL:

```bash
git clone https://github.com/your-org/secure-claude-code.git
cd secure-claude-code
bash install.sh
```

Or run from PowerShell when `bash` is on `PATH`:

```powershell
.\install.ps1
```

## Core Commands

```bash
./bin/secure-claude-code install balanced
./bin/secure-claude-code update
./bin/secure-claude-code validate
./bin/secure-claude-code doctor
./bin/secure-claude-code doctor --fix balanced
./bin/secure-claude-code list protections
./bin/secure-claude-code logs 20
./bin/secure-claude-code logs 50 --json --module block-dangerous-commands --decision block --since-hours 24
./bin/secure-claude-code uninstall
```

## Profiles

- `minimal`: low-friction baseline
- `balanced`: recommended default
- `strict`: stronger shell and file protections

## Protection Packs

- `abuse-chain-defense`
- `block-dangerous-commands`
- `block-unsafe-git`
- `network-exfiltration`
- `post-edit-quality-reminder`
- `pre-push-scan`
- `protect-secrets-read`
- `protect-sensitive-files`
- `protect-tests`

Each pack is independent, profile-driven, and backed by plain-text config under [`config/`](config/).

## Audit Log

Secure Claude Code writes local JSONL audit events for warnings and blocks.

- default path: `~/.secure-claude-code/state/audit.jsonl`
- default mode: `alerts`
- env vars:
  - `SECURE_CLAUDE_CODE_AUDIT_MODE=alerts|all|off`
  - `SECURE_CLAUDE_CODE_AUDIT_FILE=/custom/path/audit.jsonl`

Examples:

```bash
./bin/secure-claude-code logs
./bin/secure-claude-code logs 50 --json
./bin/secure-claude-code logs 50 --json --module protect-tests
./bin/secure-claude-code logs 50 --decision block --since-hours 24
```

Use `doctor --fix` to repair a broken or missing install from the current checkout.

## Real-World Coverage

### Git abuse

- blocks `--no-verify`
- blocks `--no-gpg-sign`
- blocks force-push on protected branches
- blocks `git reset --hard` on protected branches

### Secret leakage

- scans for likely secrets before push
- scans for internal IPs, internal hostnames, and live connection strings
- blocks direct access to local secret files

### Exfiltration patterns

- blocks suspicious `scp`, `rsync`, `curl`, `wget`, `aws s3 cp`, `gsutil cp`, and `nc` patterns when sensitive material is involved
- blocks `curl | bash`, `wget | sh`, and a small set of high-confidence dangerous shell behaviors

### Claude control-file abuse

- blocks remote writes into `CLAUDE.md`, `.claude/settings.json`, `.claude/hooks`, `.claude/rules`, and related control files
- blocks obvious rule-override language when it is being written into control files

### Test and quality tampering

- warns on test edits
- blocks common test deletion commands
- warns on `.skip`, `.only`, `xdescribe`, `xit`, `pytest.mark.skip`, and similar markers
- warns on `eslint-disable`, `noqa`, `nolint`, `@ts-ignore`, and coverage suppression markers

## Platform Support

- macOS: supported
- Linux: supported
- Windows: supported through Git Bash or WSL

The current hook runtime is shell-based. PowerShell wrappers are included for install, update, and uninstall, but the smooth Windows path today is Git Bash or WSL.

## Package Manager Paths

Homebrew and Scoop manifests are generated as part of the release flow.

After you publish them in your tap or bucket:

```bash
brew install your-org/tap/secure-claude-code
```

```powershell
scoop bucket add secure-claude-code https://github.com/your-org/scoop-secure-claude-code
scoop install secure-claude-code/secure-claude-code
```

## Validation

Local verification:

```bash
bash tests/smoke.sh
```

CI runs the smoke suite on Linux, macOS, and Windows runners via [`ci.yml`](.github/workflows/ci.yml).

## Releases

Build release artifacts and package manifests:

```bash
bash scripts/package-release.sh your-org/secure-claude-code "$(cat VERSION)"
```

This produces:

- release tarball
- release zip
- SHA256 checksums
- Homebrew formula
- Scoop manifest

## Project Layout

```text
secure-claude-code/
├── bin/
├── hooks/
├── modules/
├── profiles/
├── config/
├── rules/common/
├── tests/
├── install.sh
├── update.sh
├── uninstall.sh
├── install.ps1
├── update.ps1
├── uninstall.ps1
└── scripts/package-release.sh
```

## Docs

- [SECURITY.md](SECURITY.md)
- [SECURITY_MODEL.md](SECURITY_MODEL.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
