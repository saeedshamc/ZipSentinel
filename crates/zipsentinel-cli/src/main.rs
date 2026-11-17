//! ZipSentinel CLI: archive security testing, analysis, and safe extraction.
//!
//! Exit codes:
//!   0 - SAFE or LOW RISK
//!   1 - MEDIUM RISK
//!   2 - HIGH RISK
//!   3 - BLOCKED
//!   4 - operational error

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;
use zipsentinel_core::{AnalysisResult, ResourceLimits, RiskLevel};
use zipsentinel_detector::{detect, DetectorConfig};

#[derive(Parser)]
#[command(
    name = "zipsentinel",
    version,
    about = "Archive security & research toolkit",
    long_about = "ZipSentinel generates controlled archive test samples, analyzes ZIP \
                  structures, detects potential zip bombs, and extracts untrusted \
                  archives under strict resource limits."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose structured logging.
    #[arg(long, global = true, default_value = "warn")]
    log: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Quick risk scan of an archive (summary output).
    Scan {
        archive: PathBuf,
        /// Emit the full JSON report instead of a summary.
        #[arg(long)]
        json: bool,
        /// Skip measured decompression (metadata only).
        #[arg(long)]
        no_measure: bool,
        /// Use strict resource limits.
        #[arg(long)]
        strict: bool,
    },
    /// Detailed structural analysis with findings.
    Analyze {
        archive: PathBuf,
        #[arg(long)]
        json: bool,
        /// Write an HTML report to this path.
        #[arg(long)]
        html: Option<PathBuf>,
        #[arg(long)]
        no_measure: bool,
        #[arg(long)]
        strict: bool,
    },
    /// Generate a controlled test archive.
    Generate {
        /// Generation profile.
        #[arg(long, value_enum, default_value = "standard")]
        profile: ProfileArg,
        /// Output file path.
        #[arg(long)]
        output: PathBuf,
        /// Deterministic seed.
        #[arg(long, default_value_t = 0x5eed)]
        seed: u64,
        /// Entry count for many-files/standard profiles.
        #[arg(long, default_value_t = 8)]
        entries: usize,
        /// Total uncompressed payload size (e.g. 1MB, 512KiB).
        #[arg(long, default_value = "64KiB")]
        size: String,
        /// Nesting depth for the nested profile.
        #[arg(long, default_value_t = 2)]
        depth: u32,
        /// Corruption kind for the corrupted profile.
        #[arg(long, value_enum)]
        corruption: Option<CorruptionArg>,
        #[arg(long)]
        strict: bool,
    },
    /// Securely extract an archive under resource limits.
    Extract {
        archive: PathBuf,
        /// Output directory.
        #[arg(long)]
        output: PathBuf,
        /// Also extract nested archives found inside entries.
        #[arg(long)]
        recursive: bool,
        #[arg(long)]
        strict: bool,
    },
    /// Benchmark parsing and detection over a directory of archives.
    Benchmark {
        dir: PathBuf,
        /// Run measured decompression during detection (slower).
        #[arg(long)]
        deep: bool,
        /// Emit JSON results.
        #[arg(long)]
        json: bool,
        #[arg(long)]
        strict: bool,
    },
    /// Render a previously saved JSON scan result.
    Report {
        /// Path to a JSON report produced by `scan --json`/`analyze --json`.
        input: PathBuf,
        /// Also write an HTML report to this path.
        #[arg(long)]
        html: Option<PathBuf>,
    },
    /// Show effective configuration.
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the default resource limits and detector thresholds.
    Show,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    Standard,
    HighCompression,
    ManyFiles,
    Nested,
    Corrupted,
    Empty,
}

#[derive(Clone, Copy, ValueEnum)]
enum CorruptionArg {
    Truncated,
    BadSignature,
    CorruptData,
    CorruptCentralDirectory,
}

fn limits(strict: bool) -> ResourceLimits {
    if strict {
        ResourceLimits::strict()
    } else {
        ResourceLimits::default()
    }
}

fn detector_config(strict: bool, measure: bool) -> DetectorConfig {
    DetectorConfig {
        limits: limits(strict),
        measure_decompression: measure,
        ..DetectorConfig::default()
    }
}

fn risk_exit_code(risk: RiskLevel) -> u8 {
    match risk {
        RiskLevel::Safe | RiskLevel::Low => 0,
        RiskLevel::Medium => 1,
        RiskLevel::High => 2,
        RiskLevel::Blocked => 3,
    }
}

/// Parses sizes like `512KiB`, `1MB`, `2GB`, or a bare byte count.
fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(p) = s.strip_suffix("KiB") {
        (p, 1024u64)
    } else if let Some(p) = s.strip_suffix("MiB") {
        (p, 1024u64 * 1024)
    } else if let Some(p) = s.strip_suffix("GiB") {
        (p, 1024u64 * 1024 * 1024)
    } else if let Some(p) = s.strip_suffix("KB") {
        (p, 1000u64)
    } else if let Some(p) = s.strip_suffix("MB") {
        (p, 1000u64 * 1000)
    } else if let Some(p) = s.strip_suffix("GB") {
        (p, 1000u64 * 1000 * 1000)
    } else {
        (s, 1u64)
    };
    let base: u64 = num.trim().parse().context("invalid size value")?;
    base.checked_mul(mult)
        .ok_or_else(|| anyhow::anyhow!("size overflow"))
}

#[derive(Serialize)]
struct BenchRow {
    file: String,
    size_bytes: u64,
    parse_ms: f64,
    detect_ms: f64,
    entries: u64,
    risk: String,
    error: Option<String>,
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&cli.log)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::Scan {
            archive,
            json,
            no_measure,
            strict,
        } => {
            let cfg = detector_config(strict, !no_measure);
            let result = detect(&archive, &cfg).context("scan failed")?;
            if json {
                println!("{}", serde_json::to_string_pretty(&zipsentinel_report::to_json(&result))?);
            } else {
                println!(
                    "{}: {} (score {:.1}) — {} entries, {} findings",
                    result.path.display(),
                    result.risk,
                    result.score,
                    result.metadata.entry_count,
                    result.findings.len()
                );
            }
            Ok(risk_exit_code(result.risk))
        }
        Commands::Analyze {
            archive,
            json,
            html,
            no_measure,
            strict,
        } => {
            let cfg = detector_config(strict, !no_measure);
            let result = detect(&archive, &cfg).context("analysis failed")?;
            if let Some(out) = html {
                std::fs::write(&out, zipsentinel_report::render_html(&result))?;
                eprintln!("HTML report written to {}", out.display());
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&zipsentinel_report::to_json(&result))?);
            } else {
                print!("{}", zipsentinel_report::render_terminal(&result));
            }
            Ok(risk_exit_code(result.risk))
        }
        Commands::Generate {
            profile,
            output,
            seed,
            entries,
            size,
            depth,
            corruption,
            strict,
        } => {
            use zipsentinel_generator::{generate, CorruptKind, GenerateOptions, Profile};
            let profile = match profile {
                ProfileArg::Standard => Profile::Standard,
                ProfileArg::HighCompression => Profile::HighCompression,
                ProfileArg::ManyFiles => Profile::ManyFiles,
                ProfileArg::Nested => Profile::Nested,
                ProfileArg::Corrupted => Profile::Corrupted,
                ProfileArg::Empty => Profile::Empty,
            };
            let corruption = corruption.map(|c| match c {
                CorruptionArg::Truncated => CorruptKind::Truncated,
                CorruptionArg::BadSignature => CorruptKind::BadSignature,
                CorruptionArg::CorruptData => CorruptKind::CorruptData,
                CorruptionArg::CorruptCentralDirectory => CorruptKind::CorruptCentralDirectory,
            });
            let opts = GenerateOptions {
                profile,
                output: output.clone(),
                seed,
                entries,
                payload_size: parse_size(&size)?,
                nesting_depth: depth,
                corruption,
                limits: limits(strict),
            };
            let report = generate(&opts)?;
            println!(
                "generated {} ({} bytes, {} entries) in {} ms",
                report.path.display(),
                report.bytes_written,
                report.entries_written,
                report.duration_ms
            );
            Ok(0)
        }
        Commands::Extract {
            archive,
            output,
            recursive,
            strict,
        } => {
            use zipsentinel_extractor::{extract, ExtractOptions};
            let opts = ExtractOptions {
                archive: archive.clone(),
                output_dir: output,
                limits: limits(strict),
                recursive,
            };
            let report = extract(&opts)?;
            print!("{}", zipsentinel_report::render_extraction_terminal(&report));
            Ok(0)
        }
        Commands::Benchmark {
            dir,
            deep,
            json,
            strict,
        } => {
            let mut rows = Vec::new();
            let lim = limits(strict);
            let mut cfg = DetectorConfig {
                limits: lim.clone(),
                measure_decompression: deep,
                scan_nested: deep,
                ..DetectorConfig::default()
            };
            cfg.limits = lim;
            let entries: Vec<PathBuf> = std::fs::read_dir(&dir)
                .with_context(|| format!("cannot read dir {}", dir.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.extension()
                        .map(|x| x.eq_ignore_ascii_case("zip"))
                        .unwrap_or(false)
                })
                .collect();
            if entries.is_empty() {
                bail!("no .zip files found in {}", dir.display());
            }
            for path in &entries {
                let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                let t0 = Instant::now();
                let parse_res = zipsentinel_parser::parse_archive(path, &cfg.limits);
                let parse_ms = t0.elapsed().as_secs_f64() * 1000.0;
                let mut row = BenchRow {
                    file: path.display().to_string(),
                    size_bytes: size,
                    parse_ms,
                    detect_ms: 0.0,
                    entries: 0,
                    risk: "ERROR".to_string(),
                    error: None,
                };
                match parse_res {
                    Ok(parsed) => {
                        row.entries = parsed.metadata.entry_count;
                        let t1 = Instant::now();
                        match zipsentinel_detector::detect_parsed(&parsed, &cfg) {
                            Ok(res) => {
                                row.detect_ms = t1.elapsed().as_secs_f64() * 1000.0;
                                row.risk = res.risk.as_str().to_string();
                            }
                            Err(e) => {
                                row.error = Some(e.to_string());
                            }
                        }
                    }
                    Err(e) => row.error = Some(e.to_string()),
                }
                rows.push(row);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!("{:>10} {:>12} {:>10} {:>10} {:>6}  {}", "parse_ms", "detect_ms", "size", "entries", "risk", "file");
                for r in &rows {
                    println!(
                        "{:>10.2} {:>10.2} {:>12} {:>10} {:>6}  {}",
                        r.parse_ms,
                        r.detect_ms,
                        r.size_bytes,
                        r.entries,
                        r.risk,
                        Path::new(&r.file).file_name().unwrap_or_default().to_string_lossy()
                    );
                }
            }
            Ok(0)
        }
        Commands::Report { input, html } => {
            let text = std::fs::read_to_string(&input)
                .with_context(|| format!("cannot read {}", input.display()))?;
            let value: serde_json::Value = serde_json::from_str(&text)?;
            let result: AnalysisResult = serde_json::from_value(value)
                .context("input is not a ZipSentinel JSON report")?;
            if let Some(out) = html {
                std::fs::write(&out, zipsentinel_report::render_html(&result))?;
                eprintln!("HTML report written to {}", out.display());
            }
            print!("{}", zipsentinel_report::render_terminal(&result));
            Ok(risk_exit_code(result.risk))
        }
        Commands::Config { action } => match action {
            Some(ConfigAction::Show) | None => {
                #[derive(Serialize)]
                struct ConfigView {
                    limits_default: ResourceLimits,
                    limits_strict: ResourceLimits,
                    detector: DetectorConfigView,
                }
                #[derive(Serialize)]
                struct DetectorConfigView {
                    per_entry_ratio_threshold: f64,
                    overall_ratio_threshold: f64,
                    soft_entry_uncompressed: u64,
                    soft_total_uncompressed: u64,
                    soft_entry_count: u64,
                    measure_decompression: bool,
                    max_measure_entries: u64,
                    scan_nested: bool,
                    max_nested_scan_depth: u32,
                }
                let d = DetectorConfig::default();
                let view = ConfigView {
                    limits_default: ResourceLimits::default(),
                    limits_strict: ResourceLimits::strict(),
                    detector: DetectorConfigView {
                        per_entry_ratio_threshold: d.per_entry_ratio_threshold,
                        overall_ratio_threshold: d.overall_ratio_threshold,
                        soft_entry_uncompressed: d.soft_entry_uncompressed,
                        soft_total_uncompressed: d.soft_total_uncompressed,
                        soft_entry_count: d.soft_entry_count,
                        measure_decompression: d.measure_decompression,
                        max_measure_entries: d.max_measure_entries,
                        scan_nested: d.scan_nested,
                        max_nested_scan_depth: d.max_nested_scan_depth,
                    },
                };
                println!("{}", serde_json::to_string_pretty(&view)?);
                Ok(0)
            }
        },
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(4)
        }
    }
}
