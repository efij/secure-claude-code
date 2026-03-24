# Change Safety

- If a change touches build, deploy, auth, infra, or dependency metadata, explain the blast radius before shipping it.
- Use the smallest edit that solves the problem. Avoid opportunistic rewrites in sensitive files.
- When a file changes generated output, lockfiles, or configuration boundaries, verify both the diff and the resulting behavior.
- Be extra skeptical of edits to workflows, package manifests, Docker files, and infrastructure directories.

