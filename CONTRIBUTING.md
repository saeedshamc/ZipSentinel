# Contributing to ZipSentinel

Thanks for your interest. ZipSentinel is a security tool: correctness and
fail-closed behavior matter more than features.

## Ground rules

- **Never weaken a security limit to make a test pass.** If a limit fires,
  the correct fix is usually in the caller, not the limit.
- All external input (archive bytes, paths, metadata) is untrusted. Validate
  everything; prefer structured errors over panics.
- Use checked arithmetic for sizes. No `unsafe` without a documented,
  reviewed justification.
- Keep dependencies minimal and prefer versions published at least 7 days.

## Workflow

1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. Open a PR with a clear description and test evidence.

## Adding a detection indicator

Indicators live in `zipsentinel-detector`. Each finding needs:

- a stable `code` (SCREAMING_SNAKE_CASE),
- a `Severity`,
- `Confidence::Measured` (verified against real bytes/decompression) or
  `Confidence::Estimated` (inferred from metadata),
- measured/threshold values where applicable.

Risk classification is a weighted aggregate — do not add single-heuristic
"malicious" verdicts.

## Adding a generator profile

Profiles must route all payload sizes through `ResourceGuard` budgets and
remain deterministic for a given seed.
