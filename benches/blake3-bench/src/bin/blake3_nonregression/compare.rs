use std::collections::BTreeSet;

use crate::model::{BenchmarkResult, Comparison, ComparisonRow, Metric};

pub(crate) fn compare_results(
    baseline: &BenchmarkResult,
    current: &BenchmarkResult,
    threshold_pct: f64,
) -> Result<Comparison, Box<dyn std::error::Error>> {
    let primary = current.primary_metric.clone();
    let baseline_primary = baseline
        .metrics
        .get(&primary)
        .and_then(metric_value)
        .ok_or_else(|| format!("baseline is missing primary metric `{primary}`"))?;
    let current_primary = current
        .metrics
        .get(&primary)
        .and_then(metric_value)
        .ok_or_else(|| format!("current is missing primary metric `{primary}`"))?;
    let program_delta_ms = current_primary - baseline_primary;
    let program_delta_pct = percent_delta(current_primary, baseline_primary);

    let shared: BTreeSet<_> =
        baseline.metrics.keys().chain(current.metrics.keys()).cloned().collect();
    let mut rows = Vec::new();
    let mut missing_in_current = Vec::new();
    let mut missing_in_baseline = Vec::new();
    for name in shared {
        match (baseline.metrics.get(&name), current.metrics.get(&name)) {
            (Some(baseline_metric), Some(current_metric)) => {
                if let (Some(baseline_ms), Some(current_ms)) =
                    (metric_value(baseline_metric), metric_value(current_metric))
                {
                    rows.push(ComparisonRow {
                        name,
                        source: current_metric.source.clone(),
                        baseline_ms,
                        current_ms,
                        delta_ms: current_ms - baseline_ms,
                        delta_pct: percent_delta(current_ms, baseline_ms),
                    });
                }
            },
            (Some(_), None) => missing_in_current.push(name),
            (None, Some(_)) => missing_in_baseline.push(name),
            (None, None) => {},
        }
    }
    rows.sort_by(|a, b| b.delta_pct.partial_cmp(&a.delta_pct).unwrap_or(std::cmp::Ordering::Equal));
    let top_slowdowns = rows.iter().filter(|row| row.delta_pct > 0.0).take(5).cloned().collect();
    let regression = rows.iter().any(|row| row.delta_pct > threshold_pct);
    Ok(Comparison {
        status: if regression { "regression" } else { "ok" }.to_string(),
        regression,
        threshold_pct,
        primary_metric: primary,
        baseline_sha: baseline.git_sha.clone(),
        current_sha: current.git_sha.clone(),
        baseline_ref: baseline.git_ref.clone(),
        current_ref: current.git_ref.clone(),
        baseline_primary_ms: baseline_primary,
        current_primary_ms: current_primary,
        program_delta_ms,
        program_delta_pct,
        baseline_bench_build_and_run_wall_ms: baseline.bench_build_and_run_wall_ms,
        current_bench_build_and_run_wall_ms: current.bench_build_and_run_wall_ms,
        rows,
        top_slowdowns,
        missing_in_current,
        missing_in_baseline,
    })
}

fn metric_value(metric: &Metric) -> Option<f64> {
    metric.mean_ms.or(metric.duration_ms)
}

fn percent_delta(current: f64, baseline: f64) -> f64 {
    if baseline == 0.0 {
        0.0
    } else {
        ((current - baseline) / baseline) * 100.0
    }
}
