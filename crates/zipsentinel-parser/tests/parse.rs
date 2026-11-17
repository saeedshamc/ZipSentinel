//! Integration tests for the structural parser.

use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};
use zipsentinel_core::ResourceLimits;
use zipsentinel_parser::{is_zip_file, parse_archive, parse_bytes};

fn limits() -> ResourceLimits {
    ResourceLimits::strict()
}

/// Builds an in-memory ZIP and writes it to a temp file.
fn make_zip(path: &std::path::Path, entries: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).unwrap();
    let mut zw = ZipWriter::new(file);
    for (name, data) in entries {
        zw.start_file(
            *name,
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
        zw.write_all(data).unwrap();
    }
    zw.finish().unwrap();
}

#[test]
fn parses_basic_archive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("basic.zip");
    make_zip(
        &path,
        &[
            ("hello.txt", b"hello world"),
            ("dir/nested.bin", &[1, 2, 3, 4]),
        ],
    );

    let parsed = parse_archive(&path, &limits()).unwrap();
    assert_eq!(parsed.metadata.entry_count, 2);
    assert_eq!(parsed.metadata.entries[0].name, "hello.txt");
    assert_eq!(parsed.metadata.entries[0].uncompressed_size, 11);
    assert_eq!(parsed.metadata.entries[1].name, "dir/nested.bin");
    assert!(is_zip_file(&path));
}

#[test]
fn parses_empty_archive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.zip");
    let file = std::fs::File::create(&path).unwrap();
    ZipWriter::new(file).finish().unwrap();

    let parsed = parse_archive(&path, &limits()).unwrap();
    assert_eq!(parsed.metadata.entry_count, 0);
}

#[test]
fn rejects_non_zip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notzip.bin");
    std::fs::write(&path, b"this is definitely not a zip archive..............").unwrap();
    assert!(parse_archive(&path, &limits()).is_err());
    assert!(!is_zip_file(&path));
}

#[test]
fn rejects_truncated_archive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trunc.zip");
    make_zip(&path, &[("a.txt", b"aaaa")]);
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    assert!(parse_archive(&path, &limits()).is_err());
}

#[test]
fn rejects_tiny_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny.zip");
    std::fs::write(&path, b"PK").unwrap();
    assert!(parse_archive(&path, &limits()).is_err());
}

#[test]
fn parses_from_bytes() {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut cursor);
        zw.start_file("mem.txt", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(b"memory resident").unwrap();
        zw.finish().unwrap();
    }
    let parsed = parse_bytes(std::path::Path::new("mem.zip"), cursor.get_ref(), &limits()).unwrap();
    assert_eq!(parsed.metadata.entry_count, 1);
    assert_eq!(parsed.metadata.entries[0].uncompressed_size, 15);
}

#[test]
fn detects_nested_archive_by_extension() {
    let dir = tempfile::tempdir().unwrap();
    let inner = dir.path().join("inner.zip");
    make_zip(&inner, &[("x.txt", b"x")]);
    let inner_bytes = std::fs::read(&inner).unwrap();

    let outer = dir.path().join("outer.zip");
    let file = std::fs::File::create(&outer).unwrap();
    let mut zw = ZipWriter::new(file);
    zw.start_file(
        "payload.zip",
        SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
    )
    .unwrap();
    zw.write_all(&inner_bytes).unwrap();
    zw.finish().unwrap();

    let parsed = parse_archive(&outer, &limits()).unwrap();
    assert!(parsed.metadata.entries[0].nested_archive);
}

proptest::proptest! {
    /// Fuzz-ish property: mutating a valid archive must never panic the parser.
    #[test]
    fn mutated_archives_never_panic(seed in proptest::num::u64::ANY) {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zw = ZipWriter::new(&mut cursor);
            zw.start_file("f.txt", SimpleFileOptions::default()).unwrap();
            zw.write_all(b"payload payload payload").unwrap();
            zw.finish().unwrap();
        }
        let mut bytes = cursor.into_inner();
        // Deterministic mutation driven by the seed.
        let mut s = seed;
        for _ in 0..16 {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            let pos = (s >> 33) as usize % bytes.len().max(1);
            if pos < bytes.len() {
                bytes[pos] ^= (s & 0xFF) as u8;
            }
        }
        let _ = parse_bytes(std::path::Path::new("fuzz.zip"), &bytes, &ResourceLimits::strict());
    }
}
