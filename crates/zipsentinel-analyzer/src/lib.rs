//! Structural analysis of parsed ZIP archives.
//!
//! Produces [`Finding`]s describing anomalies visible purely from metadata:
//! duplicate names, unsafe paths, unsupported methods, encrypted entries,
//! and inconsistencies between central directory records and local file
//! headers. Risk classification lives in `zipsentinel-detector`.

use std::collections::HashSet;
use std::path::Path;
use zipsentinel_core::{ArchiveMetadata, Confidence, Finding, Severity};
use zipsentinel_parser::ParsedArchive;

/// Compression methods we consider supported for measurement/extraction.
pub const SUPPORTED_METHODS: &[u16] = &[0, 8]; // stored, deflate

fn is_unsafe_name(name: &str) -> Option<&'static str> {
    if name.contains('\0') {
        return Some("contains NUL byte");
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Some("absolute path");
    }
    // Windows drive-letter or UNC prefix.
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Some("drive-letter path");
    }
    if name.starts_with("//") || name.starts_with("\\\\") {
        return Some("UNC path");
    }
    let mut depth = 0i32;
    for comp in name.split(['/', '\\']) {
        match comp {
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return Some("path traversal");
                }
            }
            "." | "" => {}
            _ => depth += 1,
        }
    }
    if name.len() > 4096 {
        return Some("excessively long name");
    }
    None
}

/// Analyzes metadata only (no decompression, no raw byte access).
pub fn analyze_metadata(metadata: &ArchiveMetadata) -> Vec<Finding> {
    let mut findings = Vec::new();

    if metadata.entry_count == 0 {
        findings.push(Finding::new(
            "EMPTY_ARCHIVE",
            Severity::Info,
            Confidence::Measured,
            "archive contains no entries",
        ));
    }

    let mut names = HashSet::with_capacity(metadata.entries.len());
    let mut duplicates = 0u64;
    let mut dirs = 0u64;
    let mut encrypted = 0u64;
    let mut unsupported = 0u64;
    let mut nested = 0u64;
    let mut unsafe_named = 0u64;

    for entry in &metadata.entries {
        if !names.insert(entry.name.as_str()) {
            duplicates += 1;
            findings.push(
                Finding::new(
                    "DUPLICATE_ENTRY_NAME",
                    Severity::Medium,
                    Confidence::Measured,
                    format!("duplicate entry name: {:?}", entry.name),
                )
                .for_entry(entry.name.clone()),
            );
        }
        if entry.name.ends_with('/') {
            dirs += 1;
        }
        if entry.encrypted {
            encrypted += 1;
            findings.push(
                Finding::new(
                    "ENCRYPTED_ENTRY",
                    Severity::Medium,
                    Confidence::Measured,
                    "entry is flagged as encrypted",
                )
                .for_entry(entry.name.clone()),
            );
        }
        if !SUPPORTED_METHODS.contains(&entry.compression_method) {
            unsupported += 1;
            findings.push(
                Finding::new(
                    "UNSUPPORTED_COMPRESSION_METHOD",
                    Severity::High,
                    Confidence::Measured,
                    format!("compression method {} is not supported", entry.compression_method),
                )
                .for_entry(entry.name.clone()),
            );
        }
        if entry.nested_archive {
            nested += 1;
            findings.push(
                Finding::new(
                    "NESTED_ARCHIVE",
                    Severity::Info,
                    Confidence::Estimated,
                    "entry appears to be a nested archive",
                )
                .for_entry(entry.name.clone()),
            );
        }
        if let Some(reason) = is_unsafe_name(&entry.name) {
            unsafe_named += 1;
            findings.push(
                Finding::new(
                    "UNSAFE_ENTRY_NAME",
                    Severity::High,
                    Confidence::Measured,
                    format!("entry name rejected by path policy: {reason}"),
                )
                .for_entry(entry.name.clone()),
            );
        }
    }

    if duplicates > 0 {
        findings.push(
            Finding::new(
                "DUPLICATE_NAME_COUNT",
                Severity::Low,
                Confidence::Measured,
                format!("{duplicates} duplicate entry names detected"),
            )
            .measured_value(duplicates as f64, 0.0),
        );
    }
    if unsupported > 0 {
        findings.push(
            Finding::new(
                "UNSUPPORTED_METHOD_COUNT",
                Severity::Medium,
                Confidence::Measured,
                format!("{unsupported} entries use unsupported compression methods"),
            )
            .measured_value(unsupported as f64, 0.0),
        );
    }
    if metadata.zip64 {
        findings.push(Finding::new(
            "ZIP64_ARCHIVE",
            Severity::Info,
            Confidence::Measured,
            "archive uses ZIP64 extensions",
        ));
    }
    if dirs > 0 && dirs as usize == metadata.entries.len() {
        findings.push(Finding::new(
            "DIRECTORY_ONLY_ARCHIVE",
            Severity::Info,
            Confidence::Measured,
            "archive contains only directory entries",
        ));
    }

    // Drop the per-entry NESTED_ARCHIVE findings noise when there are many;
    // keep them, the detector aggregates anyway.
    let _ = (encrypted, unsafe_named, nested);
    findings
}

/// Parses the local file header for `entry` and compares fields against the
/// central directory record. Returns a finding on inconsistency.
fn check_local_header(parsed: &ParsedArchive, entry: &zipsentinel_core::EntryInfo) -> Option<Finding> {
    let bytes = &parsed.bytes;
    let off = usize::try_from(entry.local_header_offset).ok()?;
    if off + 30 > bytes.len() {
        return Some(
            Finding::new(
                "LOCAL_HEADER_OUT_OF_BOUNDS",
                Severity::High,
                Confidence::Measured,
                "local header offset points outside the file",
            )
            .for_entry(entry.name.clone()),
        );
    }
    let sig = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    if sig != 0x0403_4b50 {
        return Some(
            Finding::new(
                "LOCAL_HEADER_BAD_SIGNATURE",
                Severity::High,
                Confidence::Measured,
                "local file header signature mismatch",
            )
            .for_entry(entry.name.clone()),
        );
    }
    let rd16 = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
    let rd32 = |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
    let lfh_method = rd16(off + 8);
    let lfh_flags = rd16(off + 6);
    let lfh_crc = rd32(off + 14);
    let lfh_comp = u64::from(rd32(off + 18));
    let lfh_uncomp = u64::from(rd32(off + 22));

    // When the data-descriptor flag is clear, LFH sizes should match the CD.
    if !entry.data_descriptor && !entry.encrypted {
        if lfh_method != entry.compression_method {
            return Some(
                Finding::new(
                    "METADATA_INCONSISTENCY",
                    Severity::High,
                    Confidence::Measured,
                    format!(
                        "local header method {} != central directory method {}",
                        lfh_method, entry.compression_method
                    ),
                )
                .for_entry(entry.name.clone()),
            );
        }
        if lfh_crc != entry.crc32
            || lfh_comp != entry.compressed_size
            || lfh_uncomp != entry.uncompressed_size
        {
            return Some(
                Finding::new(
                    "METADATA_INCONSISTENCY",
                    Severity::Medium,
                    Confidence::Measured,
                    "local header CRC/sizes disagree with central directory",
                )
                .for_entry(entry.name.clone()),
            );
        }
    }
    // Flag-set comparison (only the bits we model).
    let cd_enc = entry.encrypted as u32;
    let lfh_enc = (lfh_flags & 0x1) as u32;
    if cd_enc != lfh_enc {
        return Some(
            Finding::new(
                "METADATA_INCONSISTENCY",
                Severity::Medium,
                Confidence::Measured,
                "encryption flag differs between local and central headers",
            )
            .for_entry(entry.name.clone()),
        );
    }
    None
}

/// Full structural analysis: metadata findings plus local-header cross-checks.
/// Bounded by `max_entries` to keep pathological archives cheap to analyze.
pub fn analyze(parsed: &ParsedArchive, max_entries: u64) -> Vec<Finding> {
    let mut findings = analyze_metadata(&parsed.metadata);
    for entry in parsed.metadata.entries.iter().take(max_entries as usize) {
        if let Some(f) = check_local_header(parsed, entry) {
            findings.push(f);
        }
    }
    findings
}

/// Convenience wrapper for callers holding only metadata.
pub fn analyze_path(path: &Path, limits: &zipsentinel_core::ResourceLimits) -> Result<Vec<Finding>, zipsentinel_core::ZSError> {
    let parsed = zipsentinel_parser::parse_archive(path, limits)?;
    Ok(analyze(&parsed, limits.max_entries))
}
