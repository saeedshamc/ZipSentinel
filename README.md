# ZipSentinel

> فارسی: [README.fa.md](README.fa.md) | راهنمای build فارسی: [docs/build-guide.fa.md](docs/build-guide.fa.md)

**Archive Security & Research Toolkit** — a Rust workspace for generating
controlled ZIP test samples, analyzing archive structure, detecting potential
ZIP bombs, and extracting untrusted archives under strict resource limits.

ZipSentinel is built for defensive security research, detection engineering,
and controlled laboratory experimentation. It is not a general-purpose
archiver.

## Features

- **Controlled generation** — deterministic, seedable test archives
  (standard, high-compression, many-files, nested, corrupted, empty profiles)
  with hard limits on size, entries, depth, and runtime.
- **Structural analysis** — bounds-checked central directory parsing with
  ZIP64 support, local-header cross-checks, duplicate/unsafe-name detection,
  encryption and unsupported-method indicators.
- **Bomb detection** — multi-indicator risk scoring that combines declared
  metadata with *measured* decompression behavior and recursive nested-archive
  scanning. Findings distinguish `MEASURED` from `ESTIMATED` values.
- **Secure extraction** — ZIP Slip / absolute-path / symlink / duplicate-name
  protections, per-entry and total size budgets, entry/depth/time limits,
  atomic temp-file writes, and cleanup on failure.
- **Resource guard** — centralized budgets for memory, output bytes,
  uncompressed bytes, entries, depth, and wall-clock time.
- **Reporting** — JSON (round-trippable), human terminal, and standalone HTML
  reports.
- **Benchmarks** — Criterion microbenchmarks for parsing and detection.

## Install

```sh
cargo install --path crates/zipsentinel-cli
# or build from source:
cargo build --release -p zipsentinel-cli
```

The binary is named `zipsentinel`.

## Usage

```sh
# Quick risk scan
zipsentinel scan archive.zip
zipsentinel scan archive.zip --json

# Detailed analysis (+ optional HTML report)
zipsentinel analyze archive.zip --html report.html

# Generate test samples
zipsentinel generate --profile high-compression --size 1MB --output bomb.zip
zipsentinel generate --profile nested --depth 3 --output nested.zip
zipsentinel generate --profile corrupted --corruption truncated --output bad.zip

# Safe extraction
zipsentinel extract archive.zip --output ./safe-output --recursive

# Benchmark a directory of archives
zipsentinel benchmark ./fixtures/ --json

# Re-render a saved JSON report
zipsentinel report scan-result.json --html out.html

# Show effective limits/thresholds
zipsentinel config show
```

### Exit codes

| Code | Meaning                                   |
|------|-------------------------------------------|
| 0    | SAFE or LOW RISK                          |
| 1    | MEDIUM RISK                               |
| 2    | HIGH RISK                                 |
| 3    | BLOCKED                                   |
| 4    | Operational error (I/O, parse, limits)    |

### Resource limits

`--strict` selects conservative limits (64 MiB per-entry, 256 MiB total,
10k entries, depth 2, 60 s). Defaults are more permissive (512 MiB per-entry,
2 GiB total, 100k entries, depth 4, 300 s). Limits are never silently
ignored — exceeding them produces a controlled `LimitExceeded` error.

## Architecture

Cargo workspace; dependencies flow one direction:

```
cli → detector → analyzer → parser → core
     extractor → guard → core
     generator → guard → core
     report → core
```

| Crate                  | Responsibility                                        |
|------------------------|-------------------------------------------------------|
| `zipsentinel-core`     | Shared types, limits, findings, errors                |
| `zipsentinel-parser`   | Bounds-checked EOCD/CD/ZIP64 parsing, nested sniffing |
| `zipsentinel-analyzer` | Structural findings, local-header cross-checks        |
| `zipsentinel-detector` | Risk scoring, measured decompression, nested scanning |
| `zipsentinel-generator`| Deterministic bounded test-sample generation          |
| `zipsentinel-extractor`| Secure extraction with path & resource enforcement    |
| `zipsentinel-guard`    | Resource budgets and guarded writer                   |
| `zipsentinel-report`   | JSON / terminal / HTML renderers                      |
| `zipsentinel-cli`      | `zipsentinel` binary                                  |

See [docs/threat-model.md](docs/threat-model.md) for the security model.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench -p zipsentinel-detector
```

Tests are colocated per crate (`crates/*/tests/`) plus end-to-end CLI tests
in `crates/zipsentinel-cli/tests/`. Parser robustness is covered by a
proptest mutation suite; all fixtures are generated in temporary directories
— no destructive host-filesystem tests.

## License

MIT — see [LICENSE](LICENSE).
