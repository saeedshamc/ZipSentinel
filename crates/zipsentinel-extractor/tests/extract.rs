//! Integration tests for secure extraction.

use std::io::Write;
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};
use zipsentinel_core::ResourceLimits;
use zipsentinel_extractor::{ExtractOptions, extract};
use zipsentinel_generator::{GenerateOptions, Profile, generate};

fn strict() -> ResourceLimits {
    ResourceLimits::strict()
}

fn opts(archive: &Path, out: &Path) -> ExtractOptions {
    ExtractOptions {
        archive: archive.to_path_buf(),
        output_dir: out.to_path_buf(),
        limits: strict(),
        recursive: false,
    }
}

#[test]
fn extracts_normal_archive() {
    let dir = tempfile::tempdir().unwrap();
    let report = generate(&GenerateOptions {
        profile: Profile::Standard,
        output: dir.path().join("std.zip"),
        seed: 1,
        entries: 4,
        payload_size: 4096,
        nesting_depth: 0,
        corruption: None,
        limits: strict(),
    })
    .unwrap();
    let out = dir.path().join("out");
    let res = extract(&opts(&report.path, &out)).unwrap();
    assert_eq!(res.entries_extracted, 4);
    assert!(out.join("file-0000.dat").is_file());
}

/// Crafts a ZIP containing hostile entry names.
fn hostile_zip(path: &Path, names: &[&str]) {
    let file = std::fs::File::create(path).unwrap();
    let mut zw = ZipWriter::new(file);
    for name in names {
        zw.start_file(
            *name,
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
        zw.write_all(b"evil").unwrap();
    }
    zw.finish().unwrap();
}

#[test]
fn zip_slip_is_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("evil.zip");
    hostile_zip(
        &zip_path,
        &["../escape.txt", "..\\win-escape.txt", "safe/ok.txt"],
    );
    let out = dir.path().join("out");
    let res = extract(&opts(&zip_path, &out)).unwrap();

    // Nothing may be written outside the output dir.
    assert!(!dir.path().join("escape.txt").exists());
    assert!(!dir.path().join("win-escape.txt").exists());
    // The safe entry may or may not extract depending on policy; traversal must not.
    assert!(res.skipped_entries >= 1);
}

#[test]
fn absolute_paths_are_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("abs.zip");
    hostile_zip(&zip_path, &["/etc/passwd", "C:/Windows/system32/evil.dll"]);
    let out = dir.path().join("out");
    let res = extract(&opts(&zip_path, &out)).unwrap();
    assert_eq!(res.entries_extracted, 0);
    assert!(res.skipped_entries >= 1);
}

/// IEEE CRC-32 (bitwise, fine for tests).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn le16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Builds a minimal stored-method ZIP by hand so hostile structures (like
/// duplicate names, which `zip::ZipWriter` refuses to emit) can be tested.
fn raw_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let mut out = Vec::new();
    let mut centrals = Vec::new();
    for (name, data) in entries {
        let offset = out.len() as u32;
        let name_b = name.as_bytes();
        let crc = crc32(data);
        let size = data.len() as u32;
        out.extend_from_slice(&le32(0x0403_4b50));
        out.extend_from_slice(&le16(20)); // version needed
        out.extend_from_slice(&le16(0)); // flags
        out.extend_from_slice(&le16(0)); // method: stored
        out.extend_from_slice(&le16(0)); // time
        out.extend_from_slice(&le16(0)); // date
        out.extend_from_slice(&le32(crc));
        out.extend_from_slice(&le32(size));
        out.extend_from_slice(&le32(size));
        out.extend_from_slice(&le16(name_b.len() as u16));
        out.extend_from_slice(&le16(0)); // extra len
        out.extend_from_slice(name_b);
        out.extend_from_slice(data);

        centrals.push((name_b.to_vec(), crc, size, offset));
    }
    let cd_offset = out.len() as u32;
    for (name, crc, size, offset) in &centrals {
        out.extend_from_slice(&le32(0x0201_4b50));
        out.extend_from_slice(&le16(20)); // version made by
        out.extend_from_slice(&le16(20)); // version needed
        out.extend_from_slice(&le16(0));
        out.extend_from_slice(&le16(0));
        out.extend_from_slice(&le16(0));
        out.extend_from_slice(&le16(0));
        out.extend_from_slice(&le32(*crc));
        out.extend_from_slice(&le32(*size));
        out.extend_from_slice(&le32(*size));
        out.extend_from_slice(&le16(name.len() as u16));
        out.extend_from_slice(&le16(0)); // extra
        out.extend_from_slice(&le16(0)); // comment
        out.extend_from_slice(&le16(0)); // disk
        out.extend_from_slice(&le16(0)); // int attrs
        out.extend_from_slice(&le32(0)); // ext attrs
        out.extend_from_slice(&le32(*offset));
        out.extend_from_slice(name);
    }
    let cd_size = out.len() as u32 - cd_offset;
    out.extend_from_slice(&le32(0x0605_4b50));
    out.extend_from_slice(&le16(0));
    out.extend_from_slice(&le16(0));
    out.extend_from_slice(&le16(centrals.len() as u16));
    out.extend_from_slice(&le16(centrals.len() as u16));
    out.extend_from_slice(&le32(cd_size));
    out.extend_from_slice(&le32(cd_offset));
    out.extend_from_slice(&le16(0));
    std::fs::write(path, out).unwrap();
}

#[test]
fn duplicate_names_are_skipped_safely() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("dup.zip");
    // `./same.txt` and `same.txt` are distinct raw names (so the zip reader
    // accepts them) but resolve to the same output path.
    raw_zip(&zip_path, &[("./same.txt", b"v0"), ("same.txt", b"v1")]);

    let out = dir.path().join("out");
    let res = extract(&opts(&zip_path, &out)).unwrap();
    assert_eq!(res.entries_extracted, 1);
    assert_eq!(res.skipped_entries, 1);
    assert_eq!(std::fs::read_to_string(out.join("same.txt")).unwrap(), "v0");
}

#[test]
fn entry_size_limit_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let mut limits = strict();
    limits.max_entry_uncompressed = 100;
    let report = generate(&GenerateOptions {
        profile: Profile::Standard,
        output: dir.path().join("big.zip"),
        seed: 3,
        entries: 2,
        payload_size: 4096, // each entry ~2KiB > 100 byte limit
        nesting_depth: 0,
        corruption: None,
        limits: ResourceLimits::strict(), // generation uses its own limits
    })
    .unwrap();
    let mut o = opts(&report.path, &dir.path().join("out"));
    o.limits = limits;
    let err = extract(&o).unwrap_err();
    assert!(err.to_string().contains("max_entry_uncompressed"));
}

#[test]
fn missing_archive_is_error() {
    let dir = tempfile::tempdir().unwrap();
    let err = extract(&opts(Path::new("nope.zip"), &dir.path().join("out"))).unwrap_err();
    assert!(err.to_string().contains("not found") || err.to_string().contains("No such"));
}
