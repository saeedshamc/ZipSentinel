//! Multi-indicator ZIP bomb / archive-abuse detection engine.
//!
//! Combines metadata-derived indicators (declared ratios, sizes, counts,
//! nesting) with *measured* decompression behavior when enabled. Risk is a
//! weighted aggregate of findings — never a single heuristic — and every
//! finding records whether its value was measured or estimated.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use zipsentinel_analyzer::analyze;
use zipsentinel_core::{
    AnalysisResult, ArchiveMetadata, Confidence, EntryInfo, Finding, ResourceLimits, RiskLevel,
    Severity, ZSError,
};
use zipsentinel_guard::ResourceGuard;
use zipsentinel_parser::{ParsedArchive, parse_archive, parse_bytes};

/// Tunable detection thresholds.
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    pub limits: ResourceLimits,
    /// Per-entry declared compression ratio that triggers a finding.
    pub per_entry_ratio_threshold: f64,
    /// Archive-wide declared ratio that triggers a finding.
    pub overall_ratio_threshold: f64,
    /// Declared uncompressed size per entry considered suspicious.
    pub soft_entry_uncompressed: u64,
    /// Declared total uncompressed size considered suspicious.
    pub soft_total_uncompressed: u64,
    /// Entry count considered suspicious.
    pub soft_entry_count: u64,
    /// Actually decompress entries to measure real expansion (bounded).
    pub measure_decompression: bool,
    /// Maximum entries to measure per archive.
    pub max_measure_entries: u64,
    /// Recursively inspect nested archives (requires decompression).
    pub scan_nested: bool,
    /// Maximum recursion depth for nested scanning.
    pub max_nested_scan_depth: u32,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            limits: ResourceLimits::default(),
            per_entry_ratio_threshold: 100.0,
            overall_ratio_threshold: 50.0,
            soft_entry_uncompressed: 256 * 1024 * 1024,
            soft_total_uncompressed: 1024 * 1024 * 1024,
            soft_entry_count: 50_000,
            measure_decompression: true,
            max_measure_entries: 64,
            scan_nested: true,
            max_nested_scan_depth: 8,
        }
    }
}

fn severity_weight(s: Severity) -> f64 {
    match s {
        Severity::Info => 1.0,
        Severity::Low => 4.0,
        Severity::Medium => 12.0,
        Severity::High => 30.0,
        Severity::Critical => 60.0,
    }
}

fn score_to_risk(score: f64, findings: &[Finding]) -> RiskLevel {
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        return RiskLevel::Blocked;
    }
    if score >= 70.0 {
        RiskLevel::High
    } else if score >= 35.0 {
        RiskLevel::Medium
    } else if score >= 10.0 {
        RiskLevel::Low
    } else {
        RiskLevel::Safe
    }
}

/// Metadata-only detection pass.
fn metadata_findings(metadata: &ArchiveMetadata, cfg: &DetectorConfig) -> Vec<Finding> {
    let mut out = Vec::new();

    if let Some(ratio) = metadata.overall_ratio() {
        if ratio > cfg.overall_ratio_threshold {
            out.push(
                Finding::new(
                    "OVERALL_COMPRESSION_RATIO",
                    Severity::High,
                    Confidence::Estimated,
                    format!(
                        "declared overall compression ratio {:.1}x exceeds threshold {:.1}x",
                        ratio, cfg.overall_ratio_threshold
                    ),
                )
                .measured_value(ratio, cfg.overall_ratio_threshold),
            );
        }
    }

    for entry in &metadata.entries {
        if let Some(ratio) = entry.compression_ratio {
            if ratio > cfg.per_entry_ratio_threshold {
                out.push(
                    Finding::new(
                        "HIGH_ENTRY_COMPRESSION_RATIO",
                        Severity::High,
                        Confidence::Estimated,
                        format!("entry declares {:.1}x compression ratio", ratio),
                    )
                    .measured_value(ratio, cfg.per_entry_ratio_threshold)
                    .for_entry(entry.name.clone()),
                );
            }
        }
        if entry.uncompressed_size > cfg.limits.max_entry_uncompressed {
            out.push(
                Finding::new(
                    "ENTRY_EXCEEDS_UNCOMPRESSED_LIMIT",
                    Severity::Critical,
                    Confidence::Measured,
                    "entry declares more uncompressed bytes than the configured hard limit",
                )
                .measured_value(
                    entry.uncompressed_size as f64,
                    cfg.limits.max_entry_uncompressed as f64,
                )
                .for_entry(entry.name.clone()),
            );
        } else if entry.uncompressed_size > cfg.soft_entry_uncompressed {
            out.push(
                Finding::new(
                    "LARGE_ENTRY_EXPANSION",
                    Severity::Medium,
                    Confidence::Estimated,
                    "entry declares a very large uncompressed size",
                )
                .measured_value(
                    entry.uncompressed_size as f64,
                    cfg.soft_entry_uncompressed as f64,
                )
                .for_entry(entry.name.clone()),
            );
        }
    }

    if metadata.total_uncompressed > cfg.limits.max_uncompressed_total {
        out.push(
            Finding::new(
                "TOTAL_EXPANSION_EXCEEDS_LIMIT",
                Severity::Critical,
                Confidence::Measured,
                "declared total uncompressed size exceeds the configured hard limit",
            )
            .measured_value(
                metadata.total_uncompressed as f64,
                cfg.limits.max_uncompressed_total as f64,
            ),
        );
    } else if metadata.total_uncompressed > cfg.soft_total_uncompressed {
        out.push(
            Finding::new(
                "LARGE_TOTAL_EXPANSION",
                Severity::Medium,
                Confidence::Estimated,
                "archive declares a very large total uncompressed size",
            )
            .measured_value(
                metadata.total_uncompressed as f64,
                cfg.soft_total_uncompressed as f64,
            ),
        );
    }

    if metadata.entry_count > cfg.soft_entry_count {
        out.push(
            Finding::new(
                "HIGH_ENTRY_COUNT",
                Severity::Medium,
                Confidence::Measured,
                "archive contains an unusually large number of entries",
            )
            .measured_value(metadata.entry_count as f64, cfg.soft_entry_count as f64),
        );
    }
    if metadata.entry_count > cfg.limits.max_entries {
        out.push(
            Finding::new(
                "ENTRY_COUNT_EXCEEDS_LIMIT",
                Severity::Critical,
                Confidence::Measured,
                "entry count exceeds the configured hard limit",
            )
            .measured_value(metadata.entry_count as f64, cfg.limits.max_entries as f64),
        );
    }
    out
}

struct MeasureStats {
    actual_total: u64,
    measured_entries: u64,
}

/// Streams each entry through the `zip` reader, counting real decompressed
/// bytes against the guard. Detects CRC failures and size misreports.
fn measure_entries(
    path: &Path,
    metadata: &ArchiveMetadata,
    cfg: &DetectorConfig,
    guard: &mut ResourceGuard,
    findings: &mut Vec<Finding>,
) -> io::Result<MeasureStats> {
    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let mut actual_total = 0u64;
    let mut measured = 0u64;
    let to_measure = metadata.entries.len().min(cfg.max_measure_entries as usize);

    for i in 0..to_measure {
        guard
            .check_time()
            .map_err(|e| io::Error::other(e.to_string()))?;
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(err) => {
                findings.push(
                    Finding::new(
                        "ENTRY_READ_FAILURE",
                        Severity::Medium,
                        Confidence::Measured,
                        format!("entry could not be opened for measurement: {err}"),
                    )
                    .for_entry(metadata.entries[i].name.clone()),
                );
                continue;
            }
        };
        let declared = metadata.entries[i].uncompressed_size;
        guard
            .check_entry_size(declared)
            .map_err(|e| io::Error::other(e.to_string()))?;

        let mut buf = vec![0u8; 128 * 1024];
        let mut entry_actual = 0u64;
        loop {
            match entry.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    entry_actual += n as u64;
                    actual_total += n as u64;
                    guard
                        .consume_uncompressed(n as u64)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    if entry_actual > declared.saturating_add(1024) {
                        findings.push(
                            Finding::new(
                                "ACTUAL_EXCEEDS_DECLARED",
                                Severity::Critical,
                                Confidence::Measured,
                                "decompressed size exceeds the declared uncompressed size",
                            )
                            .for_entry(metadata.entries[i].name.clone()),
                        );
                        break;
                    }
                }
                Err(err) => {
                    findings.push(
                        Finding::new(
                            "DECOMPRESSION_OR_CRC_FAILURE",
                            Severity::High,
                            Confidence::Measured,
                            format!("streaming decompression failed: {err}"),
                        )
                        .for_entry(metadata.entries[i].name.clone()),
                    );
                    break;
                }
            }
        }
        measured += 1;
        if entry_actual < declared {
            findings.push(
                Finding::new(
                    "DECLARED_SIZE_MISMATCH",
                    Severity::Medium,
                    Confidence::Measured,
                    format!(
                        "declared uncompressed size {} but decompressed {} bytes",
                        declared, entry_actual
                    ),
                )
                .for_entry(metadata.entries[i].name.clone()),
            );
        }
    }
    Ok(MeasureStats {
        actual_total,
        measured_entries: measured,
    })
}

/// Recursively scans nested archives found inside `parsed`, returning the
/// maximum nesting depth and number of nested archives seen.
fn scan_nested(
    parsed: &ParsedArchive,
    cfg: &DetectorConfig,
    guard: &mut ResourceGuard,
    depth: u32,
    findings: &mut Vec<Finding>,
) -> Result<(u32, u64), ZSError> {
    if depth >= cfg.max_nested_scan_depth || depth > cfg.limits.max_depth {
        findings.push(Finding::new(
            "NESTED_DEPTH_LIMIT",
            Severity::Medium,
            Confidence::Measured,
            "nested archive depth reached the configured scan limit",
        ));
        return Ok((depth, 0));
    }

    // Read from the in-memory bytes so nested archives (which have no real
    // file path) work identically to top-level ones.
    let cursor = std::io::Cursor::new(parsed.bytes.as_slice());
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| ZSError::parse(format!("nested scan: cannot open archive: {e}")))?;

    let mut max_depth = depth;
    let mut count = 0u64;
    for i in 0..archive.len() {
        guard.check_time()?;
        let entry: &EntryInfo = match parsed.metadata.entries.get(i) {
            Some(e) => e,
            None => break,
        };
        if !entry.nested_archive {
            continue;
        }
        // Bound the nested payload we buffer.
        let cap = cfg
            .limits
            .max_memory_bytes
            .min(entry.uncompressed_size.max(1));
        if entry.uncompressed_size > cap {
            findings.push(
                Finding::new(
                    "NESTED_ARCHIVE_TOO_LARGE",
                    Severity::Medium,
                    Confidence::Estimated,
                    "nested archive exceeds the in-memory scan budget",
                )
                .for_entry(entry.name.clone()),
            );
            continue;
        }
        let mut nested_bytes = Vec::with_capacity(entry.uncompressed_size.min(cap) as usize);
        {
            let mut zf = archive
                .by_index(i)
                .map_err(|e| ZSError::parse(format!("nested entry open failed: {e}")))?;
            let mut limited = zf.by_ref().take(cap);
            limited
                .read_to_end(&mut nested_bytes)
                .map_err(|e| ZSError::parse(format!("nested entry read failed: {e}")))?;
        }
        guard.consume_uncompressed(nested_bytes.len() as u64)?;
        let nested_parsed = match parse_bytes(Path::new(&entry.name), &nested_bytes, &cfg.limits) {
            Ok(p) => p,
            Err(_) => continue, // not actually a zip; extension false-positive
        };
        count += 1;
        let (child_depth, child_count) =
            scan_nested(&nested_parsed, cfg, guard, depth + 1, findings)?;
        count += child_count;
        max_depth = max_depth.max(child_depth);
    }
    Ok((max_depth.max(depth), count))
}

/// Runs the full detection pipeline over an archive file.
pub fn detect(path: &Path, cfg: &DetectorConfig) -> Result<AnalysisResult, ZSError> {
    let parsed = parse_archive(path, &cfg.limits)?;
    detect_parsed(&parsed, cfg)
}

/// Runs detection over an already-parsed archive.
pub fn detect_parsed(
    parsed: &ParsedArchive,
    cfg: &DetectorConfig,
) -> Result<AnalysisResult, ZSError> {
    let mut findings = analyze(parsed, cfg.limits.max_entries);
    findings.extend(metadata_findings(&parsed.metadata, cfg));

    let mut guard = ResourceGuard::new(cfg.limits.clone());
    let mut max_nested_depth = 0u32;
    let mut nested_count = 0u64;

    if cfg.measure_decompression {
        match measure_entries(
            &parsed.path,
            &parsed.metadata,
            cfg,
            &mut guard,
            &mut findings,
        ) {
            Ok(stats) => {
                if stats.actual_total > parsed.metadata.total_uncompressed {
                    findings.push(
                        Finding::new(
                            "MEASURED_EXCEEDS_DECLARED_TOTAL",
                            Severity::Critical,
                            Confidence::Measured,
                            "measured decompressed bytes exceed the declared total",
                        )
                        .measured_value(
                            stats.actual_total as f64,
                            parsed.metadata.total_uncompressed as f64,
                        ),
                    );
                }
                if stats.measured_entries > 0
                    && stats.measured_entries < parsed.metadata.entry_count
                {
                    findings.push(Finding::new(
                        "PARTIAL_MEASUREMENT",
                        Severity::Info,
                        Confidence::Measured,
                        format!(
                            "measured {}/{} entries due to measurement caps",
                            stats.measured_entries, parsed.metadata.entry_count
                        ),
                    ));
                }
            }
            Err(e) => {
                // Guard/IO failures during measurement become findings rather
                // than aborting the whole analysis where possible.
                findings.push(Finding::new(
                    "MEASUREMENT_ABORTED",
                    Severity::Medium,
                    Confidence::Measured,
                    format!("decompression measurement stopped early: {e}"),
                ));
            }
        }
    }

    if cfg.scan_nested {
        match scan_nested(parsed, cfg, &mut guard, 0, &mut findings) {
            Ok((depth, count)) => {
                max_nested_depth = depth;
                nested_count = count;
            }
            Err(e) => {
                findings.push(Finding::new(
                    "NESTED_SCAN_ABORTED",
                    Severity::Medium,
                    Confidence::Measured,
                    format!("nested archive scan stopped early: {e}"),
                ));
            }
        }
    } else {
        nested_count = parsed
            .metadata
            .entries
            .iter()
            .filter(|e| e.nested_archive)
            .count() as u64;
    }

    if nested_count > 0 {
        findings.push(
            Finding::new(
                "NESTED_ARCHIVE_COUNT",
                Severity::Info,
                Confidence::Measured,
                format!("{nested_count} nested archive(s) detected"),
            )
            .measured_value(nested_count as f64, 0.0),
        );
    }

    let score: f64 = findings
        .iter()
        .map(|f| severity_weight(f.severity))
        .sum::<f64>()
        .min(100.0);
    let risk = score_to_risk(score, &findings);

    Ok(AnalysisResult {
        path: parsed.path.clone(),
        risk,
        score,
        findings,
        max_nested_depth,
        nested_archive_count: nested_count,
        metadata: parsed.metadata.clone(),
    })
}
