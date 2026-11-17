//! Controlled archive test-sample generator.
//!
//! Every profile produces bounded output: entry counts, uncompressed totals,
//! nesting depth, wall-clock time, and output bytes are all enforced through
//! [`ResourceGuard`]/[`GuardedWriter`]. Generation is deterministic for a
//! given seed.

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::time::Instant;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};
use zipsentinel_core::{ResourceLimits, ZSError};
use zipsentinel_guard::{GuardedWriter, ResourceGuard};

/// Built-in generation profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// A small mixed archive: text, binary, and semi-compressible data.
    Standard,
    /// Few entries of highly compressible data for ratio experiments.
    HighCompression,
    /// Many small entries to stress entry-count handling.
    ManyFiles,
    /// Recursively nested ZIP archives up to a depth limit.
    Nested,
    /// A valid archive that is then deliberately corrupted.
    Corrupted,
    /// A structurally valid archive with zero entries.
    Empty,
}

/// How a corrupted fixture is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptKind {
    /// Truncate the archive to ~60% of its size.
    Truncated,
    /// Zero the local file header signature.
    BadSignature,
    /// Flip a byte inside the file-data region (CRC mismatch on read).
    CorruptData,
    /// Truncate inside the central directory.
    CorruptCentralDirectory,
}

/// Options controlling a generation run.
#[derive(Debug, Clone)]
pub struct GenerateOptions {
    pub profile: Profile,
    pub output: PathBuf,
    pub seed: u64,
    /// Target entry count for `ManyFiles`/`Standard` (bounded by limits).
    pub entries: usize,
    /// Target uncompressed payload size in bytes (bounded by limits).
    pub payload_size: u64,
    /// Nesting depth for `Nested` (bounded by `limits.max_depth`).
    pub nesting_depth: u32,
    pub corruption: Option<CorruptKind>,
    pub limits: ResourceLimits,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            profile: Profile::Standard,
            output: PathBuf::from("sample.zip"),
            seed: 0x5eed,
            entries: 8,
            payload_size: 64 * 1024,
            nesting_depth: 2,
            corruption: None,
            limits: ResourceLimits::default(),
        }
    }
}

/// Summary of a completed generation run.
#[derive(Debug)]
pub struct GenerateReport {
    pub path: PathBuf,
    pub bytes_written: u64,
    pub entries_written: u64,
    pub uncompressed_bytes: u64,
    pub duration_ms: u128,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DataKind {
    Zeros,
    Pattern,
    SemiCompressible,
    Random,
}

/// Generates `size` bytes of the requested kind. Total requested size must be
/// pre-authorized through the guard by the caller.
fn gen_data(rng: &mut StdRng, kind: DataKind, size: usize) -> Vec<u8> {
    match kind {
        DataKind::Zeros => vec![0u8; size],
        DataKind::Pattern => {
            let pat: &[u8] = b"Zipsentinel-pattern-block-";
            let mut out = Vec::with_capacity(size);
            while out.len() < size {
                let take = (size - out.len()).min(pat.len());
                out.extend_from_slice(&pat[..take]);
            }
            out
        }
        DataKind::SemiCompressible => {
            // Repeated "words" with occasional random bytes: moderate ratio.
            let words: [&[u8]; 8] = [
                b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf", b"hotel",
            ];
            let mut out = Vec::with_capacity(size);
            while out.len() < size {
                if rng.next_u32() % 16 == 0 {
                    let b = rng.next_u32() as u8;
                    out.push(b);
                } else {
                    let w = words[(rng.next_u32() as usize) % words.len()];
                    let room = size - out.len();
                    let take = room.min(w.len());
                    out.extend_from_slice(&w[..take]);
                }
            }
            out.truncate(size);
            out
        }
        DataKind::Random => {
            let mut out = vec![0u8; size];
            rng.fill_bytes(&mut out);
            out
        }
    }
}

struct EntrySpec {
    name: String,
    method: CompressionMethod,
    data: Vec<u8>,
}

/// Writes entries to any `Write + Seek` sink under guard enforcement.
fn write_entries<W: Write + std::io::Seek>(
    zw: &mut ZipWriter<W>,
    entries: &[EntrySpec],
    guard: &mut ResourceGuard,
) -> Result<(), ZSError> {
    for e in entries {
        guard.check_time()?;
        guard.check_entry_size(e.data.len() as u64)?;
        guard.consume_uncompressed(e.data.len() as u64)?;
        guard.consume_entry()?;
        let opts = SimpleFileOptions::default()
            .compression_method(e.method)
            .large_file(e.data.len() as u64 > u32::MAX as u64);
        zw.start_file(&e.name, opts)
            .map_err(|e| ZSError::parse(format!("zip start_file failed: {e}")))?;
        zw.write_all(&e.data)
            .map_err(|e| ZSError::parse(format!("zip write failed: {e}")))?;
    }
    Ok(())
}

/// Builds an in-memory ZIP from entry specs, bounded by `limits`.
fn zip_bytes(entries: &[EntrySpec], limits: &ResourceLimits) -> Result<Vec<u8>, ZSError> {
    let mut guard = ResourceGuard::new(limits.clone());
    let cursor = Cursor::new(Vec::new());
    let mut zw = ZipWriter::new(cursor);
    write_entries(&mut zw, entries, &mut guard)?;
    let cursor = zw
        .finish()
        .map_err(|e| ZSError::parse(format!("zip finish failed: {e}")))?;
    Ok(cursor.into_inner())
}

/// Recursively builds nested archive content. `depth` is the remaining
/// nesting budget; the caller must have validated it against `limits.max_depth`.
fn build_nested(
    depth: u32,
    index: usize,
    opts: &GenerateOptions,
    rng: &mut StdRng,
    guard: &mut ResourceGuard,
) -> Result<Vec<u8>, ZSError> {
    let mut entries = Vec::new();
    if depth == 0 {
        entries.push(EntrySpec {
            name: format!("leaf-{index}.txt"),
            method: CompressionMethod::Deflated,
            data: gen_data(rng, DataKind::SemiCompressible, opts.payload_size.min(4096) as usize),
        });
    } else {
        // One nested child plus a leaf sibling.
        let child = build_nested(depth - 1, index + 1, opts, rng, guard)?;
        guard.consume_uncompressed(child.len() as u64)?;
        entries.push(EntrySpec {
            name: format!("level-{depth}-nested-{index}.zip"),
            method: CompressionMethod::Deflated,
            data: child,
        });
        entries.push(EntrySpec {
            name: format!("sibling-{index}.bin"),
            method: CompressionMethod::Stored,
            data: gen_data(rng, DataKind::Random, 256),
        });
    }
    zip_bytes(&entries, &opts.limits)
}

fn standard_entries(opts: &GenerateOptions, rng: &mut StdRng) -> Result<Vec<EntrySpec>, ZSError> {
    let kinds = [
        DataKind::Pattern,
        DataKind::SemiCompressible,
        DataKind::Random,
        DataKind::Zeros,
    ];
    let count = opts.entries.max(1);
    let per = (opts.payload_size / count as u64).max(1) as usize;
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let kind = kinds[i % kinds.len()];
        entries.push(EntrySpec {
            name: format!("file-{i:04}.dat"),
            method: if kind == DataKind::Random {
                CompressionMethod::Stored
            } else {
                CompressionMethod::Deflated
            },
            data: gen_data(rng, kind, per),
        });
    }
    Ok(entries)
}

fn high_compression_entries(opts: &GenerateOptions, rng: &mut StdRng) -> Vec<EntrySpec> {
    // Highly compressible payloads; sizes stay within uncompressed limits.
    let per = (opts.payload_size / 4).max(1024) as usize;
    [DataKind::Zeros, DataKind::Pattern, DataKind::SemiCompressible, DataKind::Zeros]
        .iter()
        .enumerate()
        .map(|(i, &kind)| EntrySpec {
            name: format!("compressible-{i}.bin"),
            method: CompressionMethod::Deflated,
            data: gen_data(rng, kind, per),
        })
        .collect()
}

fn many_files_entries(opts: &GenerateOptions, rng: &mut StdRng) -> Vec<EntrySpec> {
    let count = opts.entries.clamp(1, opts.limits.max_entries as usize);
    (0..count)
        .map(|i| EntrySpec {
            name: format!("bulk/file_{i:06}.txt"),
            method: CompressionMethod::Deflated,
            data: gen_data(rng, DataKind::Pattern, 64),
        })
        .collect()
}

/// Applies a corruption transform to archive bytes.
fn corrupt(bytes: &[u8], kind: CorruptKind) -> Vec<u8> {
    let mut out = bytes.to_vec();
    match kind {
        CorruptKind::Truncated => {
            let keep = out.len() * 6 / 10;
            out.truncate(keep.max(4));
        }
        CorruptKind::BadSignature => {
            for b in out.iter_mut().take(4) {
                *b = 0;
            }
        }
        CorruptKind::CorruptData => {
            // Flip a byte ~25% into the file (inside file data for typical
            // fixtures), producing a CRC mismatch on extraction.
            let pos = out.len() / 4;
            if pos < out.len() {
                out[pos] ^= 0xFF;
            }
        }
        CorruptKind::CorruptCentralDirectory => {
            // Truncate just before the EOCD (last 22+ bytes), leaving a
            // dangling central directory.
            let keep = out.len().saturating_sub(22);
            out.truncate(keep.max(4));
        }
    }
    out
}

/// Runs a generation job described by `opts`.
pub fn generate(opts: &GenerateOptions) -> Result<GenerateReport, ZSError> {
    let started = Instant::now();
    let mut rng = StdRng::seed_from_u64(opts.seed);
    let mut guard = ResourceGuard::new(opts.limits.clone());

    let entries: Vec<EntrySpec> = match opts.profile {
        Profile::Empty => Vec::new(),
        Profile::Standard => standard_entries(opts, &mut rng)?,
        Profile::HighCompression => high_compression_entries(opts, &mut rng),
        Profile::ManyFiles => many_files_entries(opts, &mut rng),
        Profile::Nested => {
            if opts.nesting_depth > opts.limits.max_depth {
                return Err(ZSError::LimitExceeded {
                    limit: format!("max_depth <= {}", opts.limits.max_depth),
                    observed: opts.nesting_depth.to_string(),
                });
            }
            guard.check_depth(opts.nesting_depth)?;
            // The nested payload is itself a complete archive stored as bytes.
            let nested = build_nested(opts.nesting_depth, 0, opts, &mut rng, &mut guard)?;
            guard.check_entry_size(nested.len() as u64)?;
            vec![EntrySpec {
                name: "outer.zip".to_string(),
                method: CompressionMethod::Deflated,
                data: nested,
            }]
        }
        Profile::Corrupted => {
            // Build a small valid archive, then corrupt its bytes.
            let base = standard_entries(opts, &mut rng)?;
            let kind = opts.corruption.unwrap_or(CorruptKind::CorruptData);
            let valid = zip_bytes(&base, &opts.limits)?;
            let corrupted = corrupt(&valid, kind);
            guard.consume_output(corrupted.len() as u64)?;
            if let Some(parent) = opts.output.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(&opts.output, &corrupted)?;
            return Ok(GenerateReport {
                path: opts.output.clone(),
                bytes_written: corrupted.len() as u64,
                entries_written: base.len() as u64,
                uncompressed_bytes: guard.uncompressed_bytes(),
                duration_ms: started.elapsed().as_millis(),
            });
        }
    };

    // Write through a guarded writer so output bytes and time are enforced.
    if let Some(parent) = opts.output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let file = std::fs::File::create(&opts.output)?;
    let guarded = GuardedWriter::new(file, opts.limits.clone());
    let mut zw = ZipWriter::new(guarded);
    write_entries(&mut zw, &entries, &mut guard)?;
    let guarded = zw
        .finish()
        .map_err(|e| ZSError::parse(format!("zip finish failed: {e}")))?;
    let bytes_written = guarded.bytes_written();

    Ok(GenerateReport {
        path: opts.output.clone(),
        bytes_written,
        entries_written: entries.len() as u64,
        uncompressed_bytes: guard.uncompressed_bytes(),
        duration_ms: started.elapsed().as_millis(),
    })
}
