# Threat Model

## Assets

- Host filesystem integrity (no writes outside the chosen output directory).
- Host availability (CPU, memory, disk) while processing hostile archives.
- Integrity of analysis results (no silent truncation or misclassification).
- Confidentiality is out of scope: ZipSentinel does not decrypt archives.

## Adversary capabilities

The adversary controls archive bytes completely: malformed/truncated
structures, forged central directories, extreme compression ratios, deep
nesting, path-traversal and symlink entries, duplicate names, huge declared
sizes, and CRC/metadata inconsistencies.

## Trust boundaries

1. **Untrusted bytes → parser.** All reads are bounds-checked; malformed
   input yields `ZSError::Malformed`, never a panic or OOB access.
2. **Declared metadata → detector.** Declared sizes are treated as claims;
   measured decompression verifies them where enabled.
3. **Archive entries → filesystem.** Entry names are validated against a
   path policy, `enclosed_name` semantics, deduplication, and symlink
   rejection before any byte is written.
4. **Processing → resources.** `ResourceGuard` budgets bound output bytes,
   uncompressed bytes, entries, depth, memory (parse buffers the whole file
   under `max_memory_bytes`), and wall-clock time.

## Attack surfaces & mitigations

| Attack                        | Mitigation                                                        |
|------------------------------- |-------------------------------------------------------------------|
| ZIP bomb (ratio/total)         | Ratio + total-expansion indicators; measured decompression caps    |
| Nested "matryoshka" archives   | Depth-limited recursive scan/extract; per-level budgets            |
| ZIP Slip (`../`, absolute)     | `unsafe_name_reason` + `enclosed_name` + component re-validation   |
| Symlink escape                 | `unix_mode` symlink-bit rejection                                  |
| Duplicate-name overwrite       | Normalized-path dedup; first entry wins                            |
| Decompression-bomb mid-stream  | Per-chunk `consume_uncompressed`; abort on limit                   |
| Malformed/truncated archives   | Bounds-checked parser; fuzz/proptest coverage                      |
| Integer overflow in sizes      | `checked_add`/`checked_mul` everywhere sizes are summed            |
| TOCTOU on output paths         | Paths constructed once; temp-file + atomic rename in same dir      |
| Encrypted entries              | Detected and reported; decryption unsupported (fail closed)        |
| Resource exhaustion            | `ResourceLimits` (default & strict profiles); `LimitExceeded`      |

## Known limitations

- The parser buffers the whole archive in memory, bounded by
  `max_memory_bytes` (256 MiB default). Larger archives are rejected rather
  than streamed — a deliberate fail-closed trade-off.
- Multi-disk/spanned archives are not supported.
- Strong encryption is unsupported; encrypted entries are flagged, not
  decrypted.
- `MEASURED` decompression covers at most `max_measure_entries` entries per
  archive; the remainder is reported as `PARTIAL_MEASUREMENT`.
