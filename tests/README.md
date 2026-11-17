# Tests

ZipSentinel's test suites live next to the code they cover:

- `crates/zipsentinel-parser/tests/` — structural parsing, truncation,
  non-ZIP rejection, ZIP64 paths, nested detection, and a proptest mutation
  suite proving malformed input never panics.
- `crates/zipsentinel-generator/tests/` — profile generation, determinism,
  and resource-limit enforcement.
- `crates/zipsentinel-detector/tests/` — risk classification across profiles,
  nested-depth reporting, metadata-only mode.
- `crates/zipsentinel-extractor/tests/` — normal extraction, ZIP Slip,
  absolute paths, duplicates, size limits (hostile archives are crafted
  byte-by-byte where `zip::ZipWriter` refuses to emit them).
- `crates/zipsentinel-cli/tests/` — end-to-end CLI tests using
  `CARGO_BIN_EXE_zipsentinel`.

All tests use `tempfile` directories; nothing touches the host filesystem
destructively.
