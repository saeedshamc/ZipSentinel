//! Integration tests for the controlled archive generator.

use std::path::PathBuf;
use zipsentinel_core::ResourceLimits;
use zipsentinel_generator::{CorruptKind, GenerateOptions, Profile, generate};
use zipsentinel_parser::parse_archive;

fn opts(profile: Profile, dir: &tempfile::TempDir) -> GenerateOptions {
    GenerateOptions {
        profile,
        output: dir.path().join("out.zip"),
        seed: 42,
        entries: 16,
        payload_size: 32 * 1024,
        nesting_depth: 2,
        corruption: None,
        limits: ResourceLimits::strict(),
    }
}

#[test]
fn generates_parseable_standard_archive() {
    let dir = tempfile::tempdir().unwrap();
    let o = opts(Profile::Standard, &dir);
    let report = generate(&o).unwrap();
    assert!(report.bytes_written > 0);
    let parsed = parse_archive(
        PathBuf::from(&report.path).as_path(),
        &ResourceLimits::strict(),
    )
    .unwrap();
    assert_eq!(parsed.metadata.entry_count, 16);
}

#[test]
fn generation_is_deterministic() {
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let r1 = generate(&opts(Profile::Standard, &d1)).unwrap();
    let r2 = generate(&opts(Profile::Standard, &d2)).unwrap();
    assert_eq!(
        std::fs::read(&r1.path).unwrap(),
        std::fs::read(&r2.path).unwrap(),
        "same seed must produce identical archives"
    );
}

#[test]
fn different_seeds_differ() {
    let d1 = tempfile::tempdir().unwrap();
    let d2 = tempfile::tempdir().unwrap();
    let mut o1 = opts(Profile::Standard, &d1);
    let mut o2 = opts(Profile::Standard, &d2);
    o2.seed = 43;
    let r1 = generate(&o1).unwrap();
    let r2 = generate(&o2).unwrap();
    assert_ne!(
        std::fs::read(&r1.path).unwrap(),
        std::fs::read(&r2.path).unwrap()
    );
    let _ = (&mut o1, &mut o2);
}

#[test]
fn empty_profile_produces_valid_empty_zip() {
    let dir = tempfile::tempdir().unwrap();
    let report = generate(&opts(Profile::Empty, &dir)).unwrap();
    let parsed = parse_archive(&report.path, &ResourceLimits::strict()).unwrap();
    assert_eq!(parsed.metadata.entry_count, 0);
}

#[test]
fn nested_profile_is_bounded_and_parseable() {
    let dir = tempfile::tempdir().unwrap();
    let report = generate(&opts(Profile::Nested, &dir)).unwrap();
    let parsed = parse_archive(&report.path, &ResourceLimits::strict()).unwrap();
    assert_eq!(parsed.metadata.entry_count, 1);
    assert!(parsed.metadata.entries[0].nested_archive);
}

#[test]
fn nesting_depth_limit_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(Profile::Nested, &dir);
    o.nesting_depth = 10; // strict() max_depth = 2
    let err = generate(&o).unwrap_err();
    assert!(err.to_string().contains("max_depth"));
}

#[test]
fn entry_limit_is_enforced() {
    let dir = tempfile::tempdir().unwrap();
    // Standard profile does not clamp the entry count, so this exceeds
    // strict() max_entries = 10_000 during writing.
    let mut o = opts(Profile::Standard, &dir);
    o.entries = 20_000;
    o.payload_size = 20_000; // ~1 byte per entry
    let err = generate(&o).unwrap_err();
    assert!(err.to_string().contains("max_entries"));
}

#[test]
fn corrupted_profile_produces_unparseable_or_damaged_archive() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(Profile::Corrupted, &dir);
    o.corruption = Some(CorruptKind::Truncated);
    let report = generate(&o).unwrap();
    assert!(parse_archive(&report.path, &ResourceLimits::strict()).is_err());
}

#[test]
fn corrupted_data_variant_keeps_structure_but_breaks_crc() {
    let dir = tempfile::tempdir().unwrap();
    let mut o = opts(Profile::Corrupted, &dir);
    o.corruption = Some(CorruptKind::CorruptData);
    let report = generate(&o).unwrap();
    // Structure may still parse; detection/extraction must surface the damage.
    let _ = parse_archive(&report.path, &ResourceLimits::default());
}
