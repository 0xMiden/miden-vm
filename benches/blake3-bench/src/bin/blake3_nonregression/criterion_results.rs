use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};

use miden_vm_blake3_bench::{BENCH_GROUP, PRIMARY_METRIC, SpanRecord};

use crate::model::{BenchmarkResult, Metric};

pub(crate) fn collect_result(
    repo_root: &Path,
    git_ref: &str,
    bench_build_and_run_wall_ms: Option<f64>,
    span_collection_build_and_run_wall_ms: Option<f64>,
    rayon_num_threads: Option<usize>,
    bench_axes: &str,
    sample_size: Option<usize>,
    light_sample_size: Option<usize>,
    measurement_time_secs: Option<u64>,
    warm_up_time_secs: Option<u64>,
    spans: Vec<SpanRecord>,
) -> Result<BenchmarkResult, Box<dyn std::error::Error>> {
    let mut metrics = collect_criterion_metrics(repo_root)?;
    if let Some(axes) = selected_criterion_axes(bench_axes) {
        metrics.retain(|name, _| axes.contains(name.as_str()));
        if metrics.is_empty() {
            return Err(format!(
                "no Criterion estimates found for selected Blake3 axes: {}",
                axes.into_iter().collect::<Vec<_>>().join(", ")
            )
            .into());
        }
    }
    for (name, metric) in collect_span_metrics(&spans) {
        metrics.entry(name).or_insert(metric);
    }
    Ok(BenchmarkResult {
        repo_root: repo_root.display().to_string(),
        git_ref: git_ref.to_string(),
        git_sha: current_sha(repo_root)?,
        bench_build_and_run_wall_ms,
        span_collection_build_and_run_wall_ms,
        rayon_num_threads,
        bench_axes: split_csv(bench_axes),
        sample_size,
        light_sample_size,
        measurement_time_secs,
        warm_up_time_secs,
        primary_metric: select_primary_metric(&metrics)?.to_string(),
        metrics,
        spans,
    })
}

fn select_primary_metric(
    metrics: &BTreeMap<String, Metric>,
) -> Result<&str, Box<dyn std::error::Error>> {
    [PRIMARY_METRIC, "prove_trace_sync", "build_trace", "execute_trace_inputs_sync"]
        .into_iter()
        .find(|metric| metrics.contains_key(*metric))
        .ok_or_else(|| "no supported primary metric found in benchmark result".into())
}

fn collect_criterion_metrics(
    repo_root: &Path,
) -> Result<BTreeMap<String, Metric>, Box<dyn std::error::Error>> {
    let criterion_root = repo_root.join("target/criterion");
    let mut metrics = BTreeMap::new();
    collect_estimate_paths(&criterion_root, &mut |path| {
        let Some(name) = metric_name_from_estimate_path(&criterion_root, path) else {
            return Ok(());
        };
        let payload: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
        let mean = estimate_ms(&payload, "mean");
        metrics.insert(
            name.clone(),
            Metric {
                name,
                source: "criterion".to_string(),
                mean_ms: mean.map(|estimate| estimate.0),
                median_ms: estimate_ms(&payload, "median").map(|estimate| estimate.0),
                lower_bound_ms: mean.map(|estimate| estimate.1),
                upper_bound_ms: mean.map(|estimate| estimate.2),
                duration_ms: None,
                span_path: None,
                unit: "ms".to_string(),
            },
        );
        Ok(())
    })?;
    if metrics.is_empty() {
        return Err(
            format!("no Criterion estimates found under {}", criterion_root.display()).into()
        );
    }
    Ok(metrics)
}

fn collect_span_metrics(spans: &[SpanRecord]) -> BTreeMap<String, Metric> {
    let mut metrics = BTreeMap::new();
    for span in spans {
        let Some(name) = report_span_metric_name(&span.name) else {
            continue;
        };
        metrics.entry(name.clone()).or_insert_with(|| Metric {
            name,
            source: "tracing-span".to_string(),
            mean_ms: None,
            median_ms: None,
            lower_bound_ms: None,
            upper_bound_ms: None,
            duration_ms: Some(span.duration_ms),
            span_path: Some(span.path.clone()),
            unit: "ms".to_string(),
        });
    }
    metrics
}

pub(crate) fn selected_criterion_axes(bench_axes: &str) -> Option<BTreeSet<String>> {
    let axes = split_csv(bench_axes);
    if axes.is_empty() || axes.iter().any(|axis| axis == "all") {
        return None;
    }
    Some(
        axes.into_iter()
            .map(|axis| {
                if matches!(axis.as_str(), "prove" | "prove_program_sync") {
                    PRIMARY_METRIC.to_string()
                } else {
                    axis
                }
            })
            .collect(),
    )
}

fn report_span_metric_name(name: &str) -> Option<String> {
    match name {
        "execute_trace_inputs_with_package_debug_info_sync"
        | "execute_trace_inputs_with_package_debug_info_at_source_node_sync" => {
            Some("execute_trace_inputs_sync".to_string())
        },
        "build aux traces" => Some("build_aux_trace".to_string()),
        "to_core_chiplets_matrices" => Some("to_row_major_matrix".to_string()),
        "build_trace"
        | "commit to main traces"
        | "commit to aux traces"
        | "evaluate constraints"
        | "commit to quotient poly chunks"
        | "open"
        | "prove_trace_sync" => Some(name.replace(' ', "_")),
        "prove" => Some("prove_span".to_string()),
        "prove_program_sync" => Some("e2e_prove_wall".to_string()),
        _ => None,
    }
}

fn collect_estimate_paths(
    dir: &Path,
    callback: &mut impl FnMut(&Path) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_estimate_paths(&path, callback)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("estimates.json")
            && path
                .parent()
                .and_then(|parent| parent.file_name())
                .and_then(|name| name.to_str())
                == Some("new")
        {
            callback(&path)?;
        }
    }
    Ok(())
}

pub(crate) fn metric_name_from_estimate_path(criterion_root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(criterion_root).ok()?;
    let mut parts: Vec<_> =
        relative.iter().map(|part| part.to_string_lossy().to_string()).collect();
    if parts.len() < 3
        || parts.pop().as_deref() != Some("estimates.json")
        || parts.pop().as_deref() != Some("new")
    {
        return None;
    }
    if parts.first().is_some_and(|part| part == BENCH_GROUP) {
        return parts.last().cloned();
    }
    Some(parts.join("/"))
}

pub(crate) fn estimate_ms(payload: &serde_json::Value, name: &str) -> Option<(f64, f64, f64)> {
    let estimate = payload.get(name)?;
    let point = estimate.get("point_estimate")?.as_f64()? / 1_000_000.0;
    let interval = estimate.get("confidence_interval")?;
    let low = interval.get("lower_bound")?.as_f64()? / 1_000_000.0;
    let high = interval.get("upper_bound")?.as_f64()? / 1_000_000.0;
    Some((point, low, high))
}

fn current_sha(repo_root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}
