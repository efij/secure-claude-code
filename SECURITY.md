# Security Policy

## Supported Versions

Security fixes are applied to the default branch and the latest tagged release.

## Reporting A Vulnerability

Do not open public issues for sensitive security reports.

Please include:

1. affected version or commit
2. impact and practical attack path
3. reproduction details, including the triggering tool input or hook payload when possible

Use GitHub Security Advisories or the maintainer's private contact channel for initial disclosure.

## Scope

Runwall is a local hardening layer for Claude Code. It helps reduce risk, but it does not replace:

- OS sandboxing
- branch protection on the Git host
- CI secret scanning
- code review
- least-privilege credentials
