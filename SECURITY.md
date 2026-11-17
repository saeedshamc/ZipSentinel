# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security vulnerabilities. Report
them privately to the repository maintainers via GitHub's private
vulnerability reporting ("Report a vulnerability" on the Security tab) or by
contacting the maintainer directly.

Include: affected version/commit, reproduction steps, impact assessment, and
any suggested mitigation.

## Scope

ZipSentinel processes **untrusted archives**. The security-relevant surface
includes:

- the structural parser (`zipsentinel-parser`),
- measured decompression (`zipsentinel-detector`),
- secure extraction (`zipsentinel-extractor`),
- resource-limit enforcement (`zipsentinel-guard`).

Vulnerabilities in these paths — memory-safety issues, limit bypasses,
path-escape bugs, panic-on-malformed-input — are in scope.

## Supported versions

Only the latest release on the default branch is supported.

## Secure-use notes

- Always run extraction through `zipsentinel extract` (or the extractor
  crate) — it enforces limits by default.
- Use `--strict` for untrusted or internet-sourced archives.
- Detection results are risk *indicators*, not proof of malice; `MEASURED`
  findings are stronger evidence than `ESTIMATED` ones.
