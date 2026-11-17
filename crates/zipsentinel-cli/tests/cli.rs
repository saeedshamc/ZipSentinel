//! End-to-end CLI tests driving the compiled `zipsentinel` binary.

use std::path::Path;
use std::process::Command;

fn zipsentinel() -> Command {
    Command::new(env!("CARGO_BIN_EXE_zipsentinel"))
}

fn generate(dir: &tempfile::TempDir, profile: &str, extra: &[&str]) -> std::path::PathBuf {
    let out = dir.path().join(format!("{profile}.zip"));
    let mut cmd = zipsentinel();
    cmd.arg("generate")
        .arg("--profile")
        .arg(profile)
        .arg("--output")
        .arg(&out)
        .args(extra);
    let status = cmd.status().unwrap();
    assert!(status.success(), "generate {profile} failed");
    out
}

#[test]
fn generate_then_scan_high_compression() {
    let dir = tempfile::tempdir().unwrap();
    let zip = generate(&dir, "high-compression", &["--size", "512KiB"]);
    let status = zipsentinel().arg("scan").arg(&zip).status().unwrap();
    // HIGH RISK exits with code 2.
    assert_eq!(status.code(), Some(2));
}

#[test]
fn scan_json_output_is_valid() {
    let dir = tempfile::tempdir().unwrap();
    let zip = generate(&dir, "standard", &[]);
    let output = zipsentinel()
        .arg("scan")
        .arg(&zip)
        .arg("--json")
        .output()
        .unwrap();
    assert!(output.status.success() || output.status.code() == Some(1));
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(v.get("risk").is_some());
    assert!(v.get("findings").is_some());
}

#[test]
fn extract_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let zip = generate(&dir, "standard", &["--entries", "3"]);
    let outdir = dir.path().join("extracted");
    let status = zipsentinel()
        .arg("extract")
        .arg(&zip)
        .arg("--output")
        .arg(&outdir)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(outdir.join("file-0000.dat").is_file());
}

#[test]
fn analyze_writes_html() {
    let dir = tempfile::tempdir().unwrap();
    let zip = generate(&dir, "empty", &[]);
    let html = dir.path().join("report.html");
    let status = zipsentinel()
        .arg("analyze")
        .arg(&zip)
        .arg("--html")
        .arg(&html)
        .status()
        .unwrap();
    assert!(status.success());
    let content = std::fs::read_to_string(&html).unwrap();
    assert!(content.contains("ZipSentinel"));
}

#[test]
fn config_show_outputs_json() {
    let output = zipsentinel().arg("config").arg("show").output().unwrap();
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(v.get("limits_default").is_some());
}

#[test]
fn report_renders_saved_json() {
    let dir = tempfile::tempdir().unwrap();
    let zip = generate(&dir, "standard", &[]);
    let json_path = dir.path().join("scan.json");
    let out = zipsentinel()
        .arg("scan")
        .arg(&zip)
        .arg("--json")
        .output()
        .unwrap();
    std::fs::write(&json_path, &out.stdout).unwrap();
    let status = zipsentinel()
        .arg("report")
        .arg(Path::new(&json_path))
        .status()
        .unwrap();
    assert!(status.success() || status.code() == Some(1));
}
