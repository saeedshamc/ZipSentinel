//! Integration tests for the detection engine.

use std::path::Path;
use zipsentinel_core::{ResourceLimits, RiskLevel};
use zipsentinel_detector::{DetectorConfig, detect};
use zipsentinel_generator::{GenerateOptions, Profile, generate};

fn cfg() -> DetectorConfig {
    DetectorConfig {
        limits: ResourceLimits::strict(),
        ..DetectorConfig::default()
    }
}

fn gen_fixture(profile: Profile, dir: &tempfile::TempDir) -> std::path::PathBuf {
    let report = generate(&GenerateOptions {
        profile,
        output: dir.path().join("sample.zip"),
        seed: 7,
        entries: 8,
        payload_size: 256 * 1024,
        nesting_depth: 2,
        corruption: None,
        limits: ResourceLimits::strict(),
    })
    .unwrap();
    report.path
}

#[test]
fn standard_archive_is_low_risk() {
    let dir = tempfile::tempdir().unwrap();
    let path = gen_fixture(Profile::Standard, &dir);
    let result = detect(&path, &cfg()).unwrap();
    assert!(
        result.risk <= RiskLevel::Low,
        "expected SAFE/LOW, got {} ({})",
        result.risk,
        result.score
    );
}

#[test]
fn high_compression_is_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let path = gen_fixture(Profile::HighCompression, &dir);
    let result = detect(&path, &cfg()).unwrap();
    assert!(
        result.risk >= RiskLevel::Medium,
        "expected at least MEDIUM, got {}",
        result.risk
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.code.contains("COMPRESSION_RATIO") || f.code.contains("EXPANSION"))
    );
}

#[test]
fn nested_archives_are_counted_with_depth() {
    let dir = tempfile::tempdir().unwrap();
    let path = gen_fixture(Profile::Nested, &dir);
    let result = detect(&path, &cfg()).unwrap();
    assert!(result.nested_archive_count > 0);
    assert!(result.max_nested_depth > 0);
}

#[test]
fn empty_archive_is_safe() {
    let dir = tempfile::tempdir().unwrap();
    let path = gen_fixture(Profile::Empty, &dir);
    let result = detect(&path, &cfg()).unwrap();
    assert_eq!(result.risk, RiskLevel::Safe);
}

#[test]
fn metadata_only_mode_still_detects_ratio() {
    let dir = tempfile::tempdir().unwrap();
    let path = gen_fixture(Profile::HighCompression, &dir);
    let mut c = cfg();
    c.measure_decompression = false;
    c.scan_nested = false;
    let result = detect(&path, &c).unwrap();
    assert!(result.risk >= RiskLevel::Medium);
    // No measured findings should appear.
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.confidence != zipsentinel_core::Confidence::Measured
                || f.code == "EMPTY_ARCHIVE"
                || f.code.starts_with("NESTED"))
    );
}

#[test]
fn missing_file_is_an_error() {
    let err = detect(Path::new("does-not-exist.zip"), &cfg());
    assert!(err.is_err());
}
