# Security Policy

## Supported Versions

Secure Claude Code is currently maintained on the default branch and the latest tagged release.

## Reporting A Vulnerability

Please do not open public issues for sensitive vulnerabilities.

Instead:

1. Share the impact, affected version, and reproduction details privately.
2. Include whether the issue is local-only, hook-bypass related, or data-exfiltration related.
3. If possible, include the exact tool invocation or hook payload that triggered the issue.

Until a dedicated security inbox exists for your published repo, use private GitHub security advisories or the maintainers' private contact channel.

## Scope

Secure Claude Code is a local-first hardening layer for Claude Code. It reduces risk, but it does not replace:

- OS sandboxing
- branch protection on your Git host
- CI secret scanning
- code review
- least-privilege credentials

Defense in depth still matters.

