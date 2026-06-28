use std::{fs, io::Write, path::Path};

use crate::model::Comparison;

pub(crate) fn summary_markdown(result: &Comparison) -> String {
    let baseline = short_ref(&result.baseline_sha, &result.baseline_ref, "baseline");
    let current = short_ref(&result.current_sha, &result.current_ref, "current");
    let status = if result.regression { "REGRESSION" } else { "OK" };
    let mut lines = vec![
        "# BENCHMARK REPORT: blake3-1to1-nonregression".to_string(),
        String::new(),
        "## Blake3 1-to-1 Non-Regression".to_string(),
        String::new(),
        format!("Status: **{status}**"),
        format!("Threshold: `{:.2}%`", result.threshold_pct),
        format!("Primary metric: `{}`", result.primary_metric),
        format!("Baseline: `{baseline}` ({})", fmt_ms(Some(result.baseline_primary_ms))),
        format!("Current: `{current}` ({})", fmt_ms(Some(result.current_primary_ms))),
        format!(
            "Overall delta: `{}` ({})",
            fmt_delta(Some(result.program_delta_ms)),
            fmt_pct(Some(result.program_delta_pct))
        ),
        String::new(),
        "| Metric | Source | Baseline | Current | Delta | Delta % |".to_string(),
        "| --- | --- | ---: | ---: | ---: | ---: |".to_string(),
    ];
    for row in &result.rows {
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} |",
            row.name,
            row.source,
            fmt_ms(Some(row.baseline_ms)),
            fmt_ms(Some(row.current_ms)),
            fmt_delta(Some(row.delta_ms)),
            fmt_pct(Some(row.delta_pct))
        ));
    }
    if !result.top_slowdowns.is_empty() {
        lines.extend([String::new(), "Top slowdowns:".to_string()]);
        for row in &result.top_slowdowns {
            lines.push(format!(
                "- `{}` moved by {} ({}).",
                row.name,
                fmt_delta(Some(row.delta_ms)),
                fmt_pct(Some(row.delta_pct))
            ));
        }
    }
    if !result.missing_in_current.is_empty() || !result.missing_in_baseline.is_empty() {
        lines.extend([String::new(), "Metric set changed:".to_string()]);
        if !result.missing_in_current.is_empty() {
            lines.push(format!("- Missing in current: {}", join_code(&result.missing_in_current)));
        }
        if !result.missing_in_baseline.is_empty() {
            lines
                .push(format!("- Missing in baseline: {}", join_code(&result.missing_in_baseline)));
        }
    }
    lines.push(String::new());
    lines.join("\n")
}

pub(crate) fn write_github_output(
    path: &Path,
    result: &Comparison,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "status={}", result.status)?;
    writeln!(file, "regression={}", result.regression)?;
    writeln!(file, "baseline_sha={}", result.baseline_sha)?;
    writeln!(file, "current_sha={}", result.current_sha)?;
    writeln!(file, "program_delta_ms={:.6}", result.program_delta_ms)?;
    writeln!(file, "program_delta_pct={:.6}", result.program_delta_pct)?;
    Ok(())
}

fn fmt_ms(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |value| format!("{value:.2} ms"))
}

fn fmt_delta(value: Option<f64>) -> String {
    value.map_or_else(
        || "n/a".to_string(),
        |value| format!("{}{value:.2} ms", if value >= 0.0 { "+" } else { "" }),
    )
}

fn fmt_pct(value: Option<f64>) -> String {
    value.map_or_else(
        || "n/a".to_string(),
        |value| format!("{}{value:.2}%", if value >= 0.0 { "+" } else { "" }),
    )
}

fn short_ref(sha: &str, git_ref: &str, fallback: &str) -> String {
    if sha.len() >= 12 {
        sha[..12].to_string()
    } else if !git_ref.is_empty() {
        git_ref.to_string()
    } else {
        fallback.to_string()
    }
}

fn join_code(values: &[String]) -> String {
    values
        .iter()
        .take(10)
        .map(|value| format!("`{value}`"))
        .collect::<Vec<_>>()
        .join(", ")
}
