//! Report rendering: JSON, terminal, and HTML output for analysis results.

use serde_json::{Value, json};
use std::fmt::Write as _;
use zipsentinel_core::{AnalysisResult, ExtractionReport, Finding, Severity};

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

/// Serializes an [`AnalysisResult`] to pretty JSON.
pub fn to_json(result: &AnalysisResult) -> Value {
    json!({
        "path": result.path,
        "risk": result.risk,
        "score": result.score,
        "max_nested_depth": result.max_nested_depth,
        "nested_archive_count": result.nested_archive_count,
        "metadata": {
            "path": result.metadata.path,
            "file_size": result.metadata.file_size,
            "entry_count": result.metadata.entry_count,
            "eocd_offset": result.metadata.eocd_offset,
            "zip64": result.metadata.zip64,
            "total_compressed": result.metadata.total_compressed,
            "total_uncompressed": result.metadata.total_uncompressed,
            "overall_ratio": result.metadata.overall_ratio(),
            "entries": result.metadata.entries.iter().map(|e| json!({
                "name": e.name,
                "compression_method": e.compression_method,
                "compressed_size": e.compressed_size,
                "uncompressed_size": e.uncompressed_size,
                "crc32": e.crc32,
                "encrypted": e.encrypted,
                "data_descriptor": e.data_descriptor,
                "utf8_names": e.utf8_names,
                "compression_ratio": e.compression_ratio,
                "nested_archive": e.nested_archive,
                "local_header_offset": e.local_header_offset,
            })).collect::<Vec<_>>(),
        },
        "findings": result.findings.iter().map(finding_json).collect::<Vec<_>>(),
    })
}

fn finding_json(f: &Finding) -> Value {
    json!({
        "code": f.code,
        "severity": severity_label(f.severity),
        "confidence": match f.confidence {
            zipsentinel_core::Confidence::Measured => "MEASURED",
            zipsentinel_core::Confidence::Estimated => "ESTIMATED",
        },
        "message": f.message,
        "measured": f.measured,
        "threshold": f.threshold,
        "entry": f.entry,
    })
}

/// Human-readable terminal report.
pub fn render_terminal(result: &AnalysisResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "ZipSentinel Analysis Report");
    let _ = writeln!(out, "==========================");
    let _ = writeln!(out, "Archive: {}", result.path.display());
    let _ = writeln!(
        out,
        "Risk:    {} (score {:.1}/100)",
        result.risk, result.score
    );
    let _ = writeln!(out);
    let m = &result.metadata;
    let _ = writeln!(out, "File size:            {} bytes", m.file_size);
    let _ = writeln!(out, "Entries:              {}", m.entry_count);
    let _ = writeln!(out, "ZIP64:                {}", m.zip64);
    let _ = writeln!(out, "Compressed total:     {} bytes", m.total_compressed);
    let _ = writeln!(out, "Uncompressed total:   {} bytes", m.total_uncompressed);
    if let Some(r) = m.overall_ratio() {
        let _ = writeln!(out, "Overall ratio:        {:.2}x (declared)", r);
    }
    let _ = writeln!(
        out,
        "Nested archives:      {} (max depth {})",
        result.nested_archive_count, result.max_nested_depth
    );
    let _ = writeln!(out);
    if result.findings.is_empty() {
        let _ = writeln!(out, "No findings.");
    } else {
        let _ = writeln!(out, "Findings ({}):", result.findings.len());
        for f in &result.findings {
            let conf = match f.confidence {
                zipsentinel_core::Confidence::Measured => "measured",
                zipsentinel_core::Confidence::Estimated => "estimated",
            };
            let entry = f
                .entry
                .as_deref()
                .map(|e| format!(" [{e}]"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "  [{:8}] {:<36} {}{} ({})",
                severity_label(f.severity),
                f.code,
                f.message,
                entry,
                conf
            );
        }
    }
    out
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Self-contained HTML report.
pub fn render_html(result: &AnalysisResult) -> String {
    let mut out = String::new();
    let risk_class = result.risk.as_str().to_lowercase().replace(' ', "-");
    let _ = writeln!(out, "<!DOCTYPE html>");
    let _ = writeln!(
        out,
        "<html><head><meta charset=\"utf-8\"><title>ZipSentinel Report</title>"
    );
    let _ = writeln!(
        out,
        "<style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.3rem .6rem;text-align:left}}.risk-{risk_class}{{font-weight:700}}</style>"
    );
    let _ = writeln!(out, "</head><body>");
    let _ = writeln!(out, "<h1>ZipSentinel Analysis Report</h1>");
    let _ = writeln!(
        out,
        "<p>Archive: <code>{}</code></p>",
        escape_html(&result.path.display().to_string())
    );
    let _ = writeln!(
        out,
        "<p class=\"risk-{risk_class}\">Risk: {} &mdash; score {:.1}/100</p>",
        result.risk, result.score
    );
    let m = &result.metadata;
    let _ = writeln!(out, "<table>");
    let _ = writeln!(
        out,
        "<tr><th>File size</th><td>{} bytes</td></tr>",
        m.file_size
    );
    let _ = writeln!(out, "<tr><th>Entries</th><td>{}</td></tr>", m.entry_count);
    let _ = writeln!(
        out,
        "<tr><th>Compressed total</th><td>{} bytes</td></tr>",
        m.total_compressed
    );
    let _ = writeln!(
        out,
        "<tr><th>Uncompressed total</th><td>{} bytes</td></tr>",
        m.total_uncompressed
    );
    if let Some(r) = m.overall_ratio() {
        let _ = writeln!(
            out,
            "<tr><th>Overall ratio (declared)</th><td>{:.2}x</td></tr>",
            r
        );
    }
    let _ = writeln!(
        out,
        "<tr><th>Nested archives</th><td>{} (max depth {})</td></tr>",
        result.nested_archive_count, result.max_nested_depth
    );
    let _ = writeln!(out, "</table>");

    let _ = writeln!(
        out,
        "<h2>Entries</h2><table><tr><th>Name</th><th>Method</th><th>Compressed</th><th>Uncompressed</th><th>Ratio</th><th>Flags</th></tr>"
    );
    for e in &m.entries {
        let mut flags = Vec::new();
        if e.encrypted {
            flags.push("encrypted");
        }
        if e.nested_archive {
            flags.push("nested");
        }
        let ratio = e
            .compression_ratio
            .map(|r| format!("{r:.1}x"))
            .unwrap_or_else(|| "-".to_string());
        let _ = writeln!(
            out,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&e.name),
            e.compression_method,
            e.compressed_size,
            e.uncompressed_size,
            ratio,
            escape_html(&flags.join(", "))
        );
    }
    let _ = writeln!(out, "</table>");

    let _ = writeln!(
        out,
        "<h2>Findings</h2><table><tr><th>Severity</th><th>Code</th><th>Confidence</th><th>Message</th><th>Entry</th></tr>"
    );
    for f in &result.findings {
        let conf = match f.confidence {
            zipsentinel_core::Confidence::Measured => "MEASURED",
            zipsentinel_core::Confidence::Estimated => "ESTIMATED",
        };
        let _ = writeln!(
            out,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            severity_label(f.severity),
            escape_html(&f.code),
            conf,
            escape_html(&f.message),
            escape_html(f.entry.as_deref().unwrap_or(""))
        );
    }
    let _ = writeln!(out, "</table></body></html>");
    out
}

/// Terminal summary of an extraction run.
pub fn render_extraction_terminal(report: &ExtractionReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Extraction Report");
    let _ = writeln!(out, "==================");
    let _ = writeln!(out, "Archive:   {}", report.archive.display());
    let _ = writeln!(out, "Output:    {}", report.output_dir.display());
    let _ = writeln!(
        out,
        "Extracted: {} entries, {} bytes",
        report.entries_extracted, report.bytes_written
    );
    let _ = writeln!(out, "Skipped:   {} entries", report.skipped_entries);
    if !report.findings.is_empty() {
        let _ = writeln!(out, "Notes:");
        for f in &report.findings {
            let _ = writeln!(out, "  - {f}");
        }
    }
    out
}

/// Serializes an extraction report to JSON.
pub fn extraction_to_json(report: &ExtractionReport) -> Value {
    json!({
        "archive": report.archive,
        "output_dir": report.output_dir,
        "entries_extracted": report.entries_extracted,
        "bytes_written": report.bytes_written,
        "skipped_entries": report.skipped_entries,
        "findings": report.findings,
    })
}
