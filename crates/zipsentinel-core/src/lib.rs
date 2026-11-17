//! Shared data types, resource limits, and error model for ZipSentinel.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// Top-level error type shared across crates.
#[derive(Debug, thiserror::Error)]
pub enum ZSError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("archive parse error: {0}")]
    Parse(String),
    #[error("resource limit exceeded: {limit} (observed: {observed})")]
    LimitExceeded { limit: String, observed: String },
    #[error("unsafe path rejected: {0}")]
    UnsafePath(PathBuf),
    #[error("archive is malformed or truncated: {0}")]
    Malformed(String),
    #[error("unsupported operation: {0}")]
    Unsupported(String),
    #[error("archive is encrypted; decryption is not supported")]
    Encrypted,
    #[error("timeout exceeded while processing archive")]
    Timeout,
    #[error("{0}")]
    Other(String),
}

impl ZSError {
    pub fn parse(msg: impl Into<String>) -> Self {
        ZSError::Parse(msg.into())
    }
    pub fn malformed(msg: impl Into<String>) -> Self {
        ZSError::Malformed(msg.into())
    }
}

/// Classification produced by the detection engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Blocked = 4,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::Safe => "SAFE",
            RiskLevel::Low => "LOW RISK",
            RiskLevel::Medium => "MEDIUM RISK",
            RiskLevel::High => "HIGH RISK",
            RiskLevel::Blocked => "BLOCKED",
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Severity of an individual finding/indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Whether a value was measured from the archive or estimated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    /// Directly measured from archive bytes or decompression output.
    Measured,
    /// Inferred from metadata without performing decompression.
    Estimated,
}

/// A single detection finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable machine-readable code, e.g. `HIGH_COMPRESSION_RATIO`.
    pub code: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    /// Measured numeric value when applicable.
    pub measured: Option<f64>,
    /// Threshold or reference value when applicable.
    pub threshold: Option<f64>,
    /// Entry name this finding relates to, if any.
    pub entry: Option<String>,
}

impl Finding {
    pub fn new(
        code: &str,
        severity: Severity,
        confidence: Confidence,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.to_string(),
            severity,
            confidence,
            message: message.into(),
            measured: None,
            threshold: None,
            entry: None,
        }
    }

    pub fn measured_value(mut self, measured: f64, threshold: f64) -> Self {
        self.measured = Some(measured);
        self.threshold = Some(threshold);
        self
    }

    pub fn for_entry(mut self, name: impl Into<String>) -> Self {
        self.entry = Some(name.into());
        self
    }
}

/// Metadata describing a single ZIP entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryInfo {
    pub name: String,
    /// Numeric ZIP compression method id (0 = stored, 8 = deflate, ...).
    pub compression_method: u16,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub crc32: u32,
    /// True when the general-purpose bit 0 (encryption) is set.
    pub encrypted: bool,
    /// True when bit 3 (data descriptor) is set.
    pub data_descriptor: bool,
    /// True when bit 11 (UTF-8 names) is set.
    pub utf8_names: bool,
    /// Offset of the local file header within the archive.
    pub local_header_offset: u64,
    /// Compression ratio `uncompressed / compressed`; `None` when not meaningful.
    pub compression_ratio: Option<f64>,
    /// True when the entry name or content signature suggests a nested archive.
    pub nested_archive: bool,
}

impl EntryInfo {
    pub fn compression_ratio(&self) -> Option<f64> {
        if self.compressed_size == 0 {
            None
        } else {
            Some(self.uncompressed_size as f64 / self.compressed_size as f64)
        }
    }
}

/// Structural metadata extracted from an archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveMetadata {
    pub path: PathBuf,
    /// Total size of the archive file on disk, in bytes.
    pub file_size: u64,
    /// Number of entries in the central directory.
    pub entry_count: u64,
    /// Offset of the End Of Central Directory record.
    pub eocd_offset: u64,
    /// Whether the archive carries a ZIP64 EOCD locator/record.
    pub zip64: bool,
    /// Total declared uncompressed size across all entries.
    pub total_uncompressed: u64,
    /// Total declared compressed size across all entries.
    pub total_compressed: u64,
    pub entries: Vec<EntryInfo>,
}

impl ArchiveMetadata {
    pub fn overall_ratio(&self) -> Option<f64> {
        if self.total_compressed == 0 {
            None
        } else {
            Some(self.total_uncompressed as f64 / self.total_compressed as f64)
        }
    }
}

/// Hard resource limits enforced by generator, guard, and extractor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum total uncompressed bytes produced during processing.
    pub max_uncompressed_total: u64,
    /// Maximum uncompressed size of a single entry.
    pub max_entry_uncompressed: u64,
    /// Maximum number of entries processed.
    pub max_entries: u64,
    /// Maximum archive nesting depth (0 = top-level only).
    pub max_depth: u32,
    /// Wall-clock time budget for a single operation.
    pub max_time: Duration,
    /// Maximum bytes written to disk during generation/extraction.
    pub max_output_bytes: u64,
    /// Maximum memory budget for buffering operations.
    pub max_memory_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_uncompressed_total: 2 * 1024 * 1024 * 1024, // 2 GiB
            max_entry_uncompressed: 512 * 1024 * 1024,      // 512 MiB
            max_entries: 100_000,
            max_depth: 4,
            max_time: Duration::from_secs(300),
            max_output_bytes: 4 * 1024 * 1024 * 1024, // 4 GiB
            max_memory_bytes: 256 * 1024 * 1024,      // 256 MiB
        }
    }
}

impl ResourceLimits {
    /// Conservative limits suitable for CI / untrusted input.
    pub fn strict() -> Self {
        Self {
            max_uncompressed_total: 256 * 1024 * 1024,
            max_entry_uncompressed: 64 * 1024 * 1024,
            max_entries: 10_000,
            max_depth: 2,
            max_time: Duration::from_secs(60),
            max_output_bytes: 512 * 1024 * 1024,
            max_memory_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Result of running the detection engine over an archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub path: PathBuf,
    pub risk: RiskLevel,
    /// Aggregate score in `[0.0, 100.0]`.
    pub score: f64,
    pub findings: Vec<Finding>,
    /// Whether nested archives were detected and how deep.
    pub max_nested_depth: u32,
    /// Number of nested archives found.
    pub nested_archive_count: u64,
    pub metadata: ArchiveMetadata,
}

/// Outcome of a secure extraction run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionReport {
    pub archive: PathBuf,
    pub output_dir: PathBuf,
    pub entries_extracted: u64,
    pub bytes_written: u64,
    pub skipped_entries: u64,
    pub findings: Vec<String>,
}
