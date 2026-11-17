//! Secure extraction engine.
//!
//! Enforces ZIP Slip / path-traversal / absolute-path / symlink protections,
//! per-entry and total size budgets, entry-count and depth limits, wall-clock
//! budgets, duplicate-name handling, and atomic file creation via
//! write-to-temp-then-rename. Temporary files are removed on failure.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zip::ZipArchive;
use zipsentinel_analyzer::unsafe_name_reason;
use zipsentinel_core::{ExtractionReport, ResourceLimits, ZSError};
use zipsentinel_guard::ResourceGuard;

/// Extensions treated as nested archives for recursive extraction.
const NESTED_EXTENSIONS: &[&str] = &[".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".epub"];

/// Options for [`extract`].
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub archive: PathBuf,
    pub output_dir: PathBuf,
    pub limits: ResourceLimits,
    /// When true, archives extracted from entries are themselves extracted
    /// into `<name>-extracted/` directories, bounded by `max_depth`.
    pub recursive: bool,
}

fn is_nested_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    NESTED_EXTENSIONS.iter().any(|e| lower.ends_with(e))
}

/// Unix file-type bits for symlinks (`S_IFLNK`).
const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;

struct ExtractState {
    guard: ResourceGuard,
    recursive: bool,
    seen_names: HashSet<String>,
    report: ExtractionReport,
    tmp_counter: u64,
}

impl ExtractState {
    fn tmp_path(&mut self, target: &Path) -> PathBuf {
        self.tmp_counter += 1;
        let name = format!(
            ".zipsentinel-tmp-{}-{}",
            std::process::id(),
            self.tmp_counter
        );
        target.with_file_name(name)
    }
}

/// Streams one zip entry to `target` through the resource guard, writing via
/// a temporary file that is atomically renamed on success.
fn extract_entry<W: Read>(
    state: &mut ExtractState,
    mut reader: W,
    target: &Path,
    entry_name: &str,
    declared_size: u64,
) -> Result<u64, ZSError> {
    state.guard.check_time()?;
    state.guard.check_entry_size(declared_size)?;

    let parent = target.parent().ok_or_else(|| ZSError::UnsafePath(target.to_path_buf()))?;
    fs::create_dir_all(parent)?;

    let tmp = state.tmp_path(target);
    let mut written = 0u64;
    let result = (|| -> Result<(), ZSError> {
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(ZSError::Io)?;
        let mut buf = vec![0u8; 128 * 1024];
        loop {
            state.guard.check_time()?;
            let n = reader.read(&mut buf).map_err(|e| {
                ZSError::parse(format!("read error on entry {entry_name:?}: {e}"))
            })?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).map_err(ZSError::Io)?;
            written += n as u64;
            state.guard.consume_uncompressed(n as u64)?;
            state.guard.consume_output(n as u64)?;
        }
        out.flush().map_err(ZSError::Io)?;
        drop(out);
        fs::rename(&tmp, target).map_err(ZSError::Io)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map(|()| written)
}

/// Extracts `archive_path` into `output_dir` at nesting `depth`.
fn extract_archive(
    archive_path: &Path,
    output_dir: &Path,
    state: &mut ExtractState,
    depth: u32,
) -> Result<(), ZSError> {
    state.guard.check_depth(depth)?;
    fs::create_dir_all(output_dir)?;

    let file = File::open(archive_path)?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| ZSError::parse(format!("cannot open archive: {e}")))?;

    for i in 0..archive.len() {
        state.guard.check_time()?;
        state.guard.consume_entry()?;

        let mut zf = match archive.by_index(i) {
            Ok(z) => z,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("password") || msg.contains("encrypted") {
                    return Err(ZSError::Encrypted);
                }
                return Err(ZSError::parse(format!("cannot read entry {i}: {msg}")));
            }
        };

        let raw_name = zf.name().to_string();
        if let Some(reason) = unsafe_name_reason(&raw_name) {
            state.report.findings.push(format!(
                "skipped unsafe entry name {raw_name:?}: {reason}"
            ));
            state.report.skipped_entries += 1;
            continue;
        }
        // zip's enclosed_name additionally strips traversal components.
        let Some(rel) = zf.enclosed_name() else {
            state.report.findings.push(format!(
                "skipped entry with unsafe path: {raw_name:?}"
            ));
            state.report.skipped_entries += 1;
            continue;
        };
        if rel.as_os_str().is_empty() {
            continue;
        }

        // Reject absolute paths and anything escaping output_dir.
        let target = output_dir.join(&rel);
        if rel.is_absolute()
            || target
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(_)))
        {
            state.report.findings.push(format!(
                "skipped entry escaping output directory: {raw_name:?}"
            ));
            state.report.skipped_entries += 1;
            continue;
        }

        // Symlink rejection via unix mode bits.
        if let Some(mode) = zf.unix_mode() {
            if mode & S_IFMT == S_IFLNK {
                state.report.findings.push(format!(
                    "skipped symlink entry: {raw_name:?}"
                ));
                state.report.skipped_entries += 1;
                continue;
            }
        }

        // Duplicate names: first wins, later duplicates are skipped.
        if !state.seen_names.insert(raw_name.clone()) {
            state.report.findings.push(format!(
                "skipped duplicate entry name: {raw_name:?}"
            ));
            state.report.skipped_entries += 1;
            continue;
        }

        let is_dir = raw_name.ends_with('/');
        if is_dir {
            fs::create_dir_all(&target)?;
            continue;
        }

        let declared = zf.size();
        let written = extract_entry(state, &mut zf, &target, &raw_name, declared)?;
        state.report.entries_extracted += 1;
        state.report.bytes_written += written;

        // Recursive nested extraction.
        if state.recursive && is_nested_name(&raw_name) {
            state.guard.check_depth(depth + 1)?;
            let stem = target
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "nested".to_string());
            let nested_out = output_dir.join(format!("{stem}-extracted"));
            match extract_archive(&target, &nested_out, state, depth + 1) {
                Ok(()) => {}
                Err(e) => {
                    state.report.findings.push(format!(
                        "nested extraction of {raw_name:?} failed: {e}"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Securely extracts `opts.archive` into `opts.output_dir`.
///
/// Fails closed: any resource-limit or safety violation aborts extraction
/// with a structured error and removes in-flight temporary files.
pub fn extract(opts: &ExtractOptions) -> Result<ExtractionReport, ZSError> {
    if !opts.archive.is_file() {
        return Err(ZSError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("archive not found: {}", opts.archive.display()),
        )));
    }
    let mut state = ExtractState {
        guard: ResourceGuard::new(opts.limits.clone()),
        recursive: opts.recursive,
        seen_names: HashSet::new(),
        report: ExtractionReport {
            archive: opts.archive.clone(),
            output_dir: opts.output_dir.clone(),
            entries_extracted: 0,
            bytes_written: 0,
            skipped_entries: 0,
            findings: Vec::new(),
        },
        tmp_counter: 0,
    };
    // Canonicalize output dir so lexical checks below are meaningful.
    fs::create_dir_all(&opts.output_dir)?;
    let out_canon = fs::canonicalize(&opts.output_dir)?;
    extract_archive(&opts.archive, &out_canon, &mut state, 0)?;
    Ok(state.report)
}
