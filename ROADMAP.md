# Roadmap

Secure Claude Code should stay focused: strong local protections, simple installation, and modular growth.

## Current Scope

- profile-based install with `minimal`, `balanced`, and `strict`
- safe `settings.json` merge and cleanup
- local JSONL audit logging
- protection packs for git abuse, secret leakage, sensitive file access, outbound exfiltration, Claude control-file abuse, and test integrity
- release packaging for tarball, zip, Homebrew formula, and Scoop manifest generation

## Next Areas

- stricter deploy and infrastructure protections
- richer per-pack validation output
- signed release artifacts
- first-class package manager distribution after public release
- native Windows hook execution without relying on Git Bash or WSL

## Contribution Shape

Strong contributions usually look like:

- one focused protection pack
- one config file when policy needs to stay editable
- one validator improvement that increases trust in the install
- one documentation update that explains user-visible behavior

Avoid:

- cloud-only defaults
- heavy dependencies for one pack
- large mixed-purpose scripts
- features that make uninstall or recovery harder
