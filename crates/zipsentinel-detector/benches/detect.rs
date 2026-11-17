//! Criterion benchmarks for parsing and detection.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::path::PathBuf;
use zipsentinel_core::ResourceLimits;
use zipsentinel_detector::{DetectorConfig, detect_parsed};
use zipsentinel_generator::{GenerateOptions, Profile, generate};
use zipsentinel_parser::parse_archive;

fn fixture(profile: Profile, payload: u64) -> PathBuf {
    let dir = tempfile::tempdir().unwrap();
    // Leak the tempdir intentionally for benchmark lifetime simplicity:
    // benchmarks are short-lived processes.
    let path = dir.path().join("bench.zip");
    let report = generate(&GenerateOptions {
        profile,
        output: path,
        seed: 99,
        entries: 32,
        payload_size: payload,
        nesting_depth: 1,
        corruption: None,
        limits: ResourceLimits::default(),
    })
    .unwrap();
    std::mem::forget(dir);
    report.path
}

fn bench_parse(c: &mut Criterion) {
    let path = fixture(Profile::Standard, 1024 * 1024);
    let limits = ResourceLimits::default();
    c.bench_function("parse_1mib_standard", |b| {
        b.iter(|| parse_archive(black_box(&path), black_box(&limits)).unwrap())
    });
}

fn bench_detect(c: &mut Criterion) {
    let path = fixture(Profile::HighCompression, 4 * 1024 * 1024);
    let limits = ResourceLimits::default();
    let cfg = DetectorConfig {
        limits: limits.clone(),
        ..DetectorConfig::default()
    };
    c.bench_function("detect_4mib_high_compression", |b| {
        b.iter(|| {
            let parsed = parse_archive(black_box(&path), black_box(&limits)).unwrap();
            detect_parsed(black_box(&parsed), black_box(&cfg)).unwrap()
        })
    });
}

fn bench_detect_metadata_only(c: &mut Criterion) {
    let path = fixture(Profile::ManyFiles, 64 * 1024);
    let limits = ResourceLimits::default();
    let cfg = DetectorConfig {
        limits: limits.clone(),
        measure_decompression: false,
        scan_nested: false,
        ..DetectorConfig::default()
    };
    c.bench_function("detect_metadata_only_manyfiles", |b| {
        b.iter(|| {
            let parsed = parse_archive(black_box(&path), black_box(&limits)).unwrap();
            detect_parsed(black_box(&parsed), black_box(&cfg)).unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_parse,
    bench_detect,
    bench_detect_metadata_only
);
criterion_main!(benches);
