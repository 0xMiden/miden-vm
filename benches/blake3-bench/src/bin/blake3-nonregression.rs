use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use miden_vm_blake3_bench::{
    BENCH_GROUP, Blake3Fixture, PRIMARY_METRIC, SpanRecord, collect_trace_spans,
};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(about = "Run and compare the Blake3 1-to-1 Criterion benchmark.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run {
        #[arg(long)]
        repo_root: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 8)]
        rayon_num_threads: usize,
        #[arg(long)]
        sample_size: Option<usize>,
        #[arg(long)]
        light_sample_size: Option<usize>,
        #[arg(long)]
        measurement_time_secs: Option<u64>,
        #[arg(long)]
        warm_up_time_secs: Option<u64>,
        #[arg(long, default_value = "")]
        bench_axes: String,
        #[arg(long, default_value = "")]
        git_ref: String,
    },
    Collect {
        #[arg(long)]
        repo_root: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        bench_wall_ms: Option<f64>,
        #[arg(long)]
        trace_wall_ms: Option<f64>,
        #[arg(long)]
        rayon_num_threads: Option<usize>,
        #[arg(long, default_value = "")]
        bench_axes: String,
        #[arg(long, default_value = "")]
        git_ref: String,
    },
    CollectSpans {
        #[arg(long)]
        repo_root: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Compare {
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        current: PathBuf,
        #[arg(long)]
        summary_out: PathBuf,
        #[arg(long)]
        json_out: PathBuf,
        #[arg(long)]
        threshold_pct: f64,
        #[arg(long)]
        github_output: Option<PathBuf>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct BenchmarkResult {
    repo_root: String,
    git_ref: String,
    git_sha: String,
    bench_wall_ms: Option<f64>,
    trace_wall_ms: Option<f64>,
    rayon_num_threads: Option<usize>,
    bench_axes: Vec<String>,
    sample_size: Option<usize>,
    light_sample_size: Option<usize>,
    measurement_time_secs: Option<u64>,
    warm_up_time_secs: Option<u64>,
    primary_metric: String,
    metrics: BTreeMap<String, Metric>,
    spans: Vec<SpanRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Metric {
    name: String,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mean_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    median_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lower_bound_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upper_bound_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_path: Option<String>,
    unit: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Comparison {
    status: String,
    regression: bool,
    threshold_pct: f64,
    primary_metric: String,
    baseline_sha: String,
    current_sha: String,
    baseline_ref: String,
    current_ref: String,
    baseline_primary_ms: f64,
    current_primary_ms: f64,
    program_delta_ms: f64,
    program_delta_pct: f64,
    baseline_bench_wall_ms: Option<f64>,
    current_bench_wall_ms: Option<f64>,
    rows: Vec<ComparisonRow>,
    top_slowdowns: Vec<ComparisonRow>,
    missing_in_current: Vec<String>,
    missing_in_baseline: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ComparisonRow {
    name: String,
    source: String,
    baseline_ms: f64,
    current_ms: f64,
    delta_ms: f64,
    delta_pct: f64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Commands::Run {
            repo_root,
            output_dir,
            rayon_num_threads,
            sample_size,
            light_sample_size,
            measurement_time_secs,
            warm_up_time_secs,
            bench_axes,
            git_ref,
        } => {
            cmd_run(
                &repo_root,
                &output_dir,
                rayon_num_threads,
                sample_size,
                light_sample_size,
                measurement_time_secs,
                warm_up_time_secs,
                &bench_axes,
                &git_ref,
            )?;
        },
        Commands::Collect {
            repo_root,
            output,
            bench_wall_ms,
            trace_wall_ms,
            rayon_num_threads,
            bench_axes,
            git_ref,
        } => {
            let result = collect_result(
                &repo_root,
                &git_ref,
                bench_wall_ms,
                trace_wall_ms,
                rayon_num_threads,
                &bench_axes,
                None,
                None,
                None,
                None,
                Vec::new(),
            )?;
            write_json(&output, &result)?;
        },
        Commands::CollectSpans { repo_root, output } => {
            let fixture = Blake3Fixture::load_from_repo(&repo_root);
            write_json(&output, &collect_trace_spans(&fixture))?;
        },
        Commands::Compare {
            baseline,
            current,
            summary_out,
            json_out,
            threshold_pct,
            github_output,
        } => {
            let baseline: BenchmarkResult = serde_json::from_str(&fs::read_to_string(&baseline)?)?;
            let current: BenchmarkResult = serde_json::from_str(&fs::read_to_string(&current)?)?;
            let comparison = compare_results(&baseline, &current, threshold_pct)?;
            write_json(&json_out, &comparison)?;
            write_text(&summary_out, &summary_markdown(&comparison))?;
            if let Some(github_output) = github_output {
                write_github_output(&github_output, &comparison)?;
            }
        },
    }
    Ok(())
}

fn cmd_run(
    repo_root: &Path,
    output_dir: &Path,
    rayon_num_threads: usize,
    sample_size: Option<usize>,
    light_sample_size: Option<usize>,
    measurement_time_secs: Option<u64>,
    warm_up_time_secs: Option<u64>,
    bench_axes: &str,
    git_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;
    let mut envs = BTreeMap::new();
    envs.insert("RAYON_NUM_THREADS".to_string(), rayon_num_threads.to_string());
    if let Some(sample_size) = sample_size {
        envs.insert("BLAKE3_SAMPLE_SIZE".to_string(), sample_size.to_string());
        envs.insert("BLAKE3_PROOF_SAMPLE_SIZE".to_string(), sample_size.to_string());
    }
    if let Some(light_sample_size) = light_sample_size {
        envs.insert("BLAKE3_LIGHT_SAMPLE_SIZE".to_string(), light_sample_size.to_string());
    }
    if let Some(measurement_time_secs) = measurement_time_secs {
        envs.insert("BLAKE3_MEASUREMENT_TIME_SECS".to_string(), measurement_time_secs.to_string());
    }
    if let Some(warm_up_time_secs) = warm_up_time_secs {
        envs.insert("BLAKE3_WARM_UP_TIME_SECS".to_string(), warm_up_time_secs.to_string());
    }
    if !bench_axes.trim().is_empty() {
        envs.insert("BLAKE3_BENCH_AXES".to_string(), bench_axes.to_string());
    }

    run_logged_command(
        command("cargo").arg("clean"),
        repo_root,
        &envs,
        &output_dir.join("clean.log"),
    )?;

    let mut bench_command = command("cargo");
    bench_command.args([
        "bench",
        "--profile",
        "optimized",
        "-p",
        "miden-vm-blake3-bench",
        "--bench",
        "blake3_bench",
        "--",
        "--noplot",
    ]);
    if let Some(measurement_time_secs) = measurement_time_secs {
        bench_command.args(["--measurement-time", &measurement_time_secs.to_string()]);
    }
    if let Some(warm_up_time_secs) = warm_up_time_secs {
        bench_command.args(["--warm-up-time", &warm_up_time_secs.to_string()]);
    }
    let bench_wall_ms =
        run_logged_command(&mut bench_command, repo_root, &envs, &output_dir.join("bench.log"))?;

    let spans_path = output_dir.join("spans.json");
    let (trace_wall_ms, spans) = if should_collect_proof_spans(bench_axes) {
        let mut spans_command = command("cargo");
        spans_command
            .args([
                "run",
                "--profile",
                "optimized",
                "-p",
                "miden-vm-blake3-bench",
                "--bin",
                "blake3-nonregression",
                "--",
                "collect-spans",
                "--repo-root",
            ])
            .arg(repo_root)
            .arg("--output")
            .arg(&spans_path);
        let trace_wall_ms = run_logged_command(
            &mut spans_command,
            repo_root,
            &envs,
            &output_dir.join("spans.log"),
        )?;
        let spans: Vec<SpanRecord> = serde_json::from_str(&fs::read_to_string(&spans_path)?)?;
        (Some(trace_wall_ms), spans)
    } else {
        let spans = Vec::new();
        write_json(&spans_path, &spans)?;
        (None, spans)
    };

    let result = collect_result(
        repo_root,
        git_ref,
        Some(bench_wall_ms),
        trace_wall_ms,
        Some(rayon_num_threads),
        bench_axes,
        sample_size,
        light_sample_size,
        measurement_time_secs,
        warm_up_time_secs,
        spans,
    )?;
    write_json(&output_dir.join("result.json"), &result)?;
    Ok(())
}

fn collect_result(
    repo_root: &Path,
    git_ref: &str,
    bench_wall_ms: Option<f64>,
    trace_wall_ms: Option<f64>,
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
        bench_wall_ms,
        trace_wall_ms,
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

fn selected_criterion_axes(bench_axes: &str) -> Option<BTreeSet<String>> {
    let axes = split_csv(bench_axes);
    if axes.is_empty() || axes.iter().any(|axis| axis == "all") {
        return None;
    }
    Some(
        axes.into_iter()
            .map(|axis| {
                if axis == "prove_program_sync" {
                    "prove".to_string()
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
        | "prove"
        | "prove_program_sync"
        | "prove_trace_sync" => Some(name.replace(' ', "_")),
        _ => None,
    }
}

fn metric_value(metric: &Metric) -> Option<f64> {
    metric.mean_ms.or(metric.duration_ms)
}

fn compare_results(
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
    let regression = program_delta_pct > threshold_pct;
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
        baseline_bench_wall_ms: baseline.bench_wall_ms,
        current_bench_wall_ms: current.bench_wall_ms,
        rows,
        top_slowdowns,
        missing_in_current,
        missing_in_baseline,
    })
}

fn summary_markdown(result: &Comparison) -> String {
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

fn write_github_output(path: &Path, result: &Comparison) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "status={}", result.status)?;
    writeln!(file, "regression={}", result.regression)?;
    writeln!(file, "baseline_sha={}", result.baseline_sha)?;
    writeln!(file, "current_sha={}", result.current_sha)?;
    writeln!(file, "program_delta_ms={:.6}", result.program_delta_ms)?;
    writeln!(file, "program_delta_pct={:.6}", result.program_delta_pct)?;
    Ok(())
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

fn metric_name_from_estimate_path(criterion_root: &Path, path: &Path) -> Option<String> {
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

fn estimate_ms(payload: &serde_json::Value, name: &str) -> Option<(f64, f64, f64)> {
    let estimate = payload.get(name)?;
    let point = estimate.get("point_estimate")?.as_f64()? / 1_000_000.0;
    let interval = estimate.get("confidence_interval")?;
    let low = interval.get("lower_bound")?.as_f64()? / 1_000_000.0;
    let high = interval.get("upper_bound")?.as_f64()? / 1_000_000.0;
    Some((point, low, high))
}

fn command(program: &str) -> Command {
    Command::new(program)
}

fn run_logged_command(
    command: &mut Command,
    cwd: &Path,
    envs: &BTreeMap<String, String>,
    log_path: &Path,
) -> Result<f64, Box<dyn std::error::Error>> {
    command.current_dir(cwd);
    for (key, value) in envs {
        command.env(key, value);
    }
    let start = Instant::now();
    let output = command.output()?;
    let elapsed = duration_ms(start.elapsed());
    let mut log = format!("$ {:?}\n", command);
    log.push_str(&String::from_utf8_lossy(&output.stdout));
    log.push_str(&String::from_utf8_lossy(&output.stderr));
    write_text(log_path, &log)?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(format!("command failed with status {}", output.status).into());
    }
    Ok(elapsed)
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

fn should_collect_proof_spans(bench_axes: &str) -> bool {
    let axes = split_csv(bench_axes);
    axes.is_empty()
        || axes.iter().any(|axis| {
            matches!(axis.as_str(), "all" | "prove" | "prove_program_sync" | "prove_trace_sync")
        })
}

fn percent_delta(current: f64, baseline: f64) -> f64 {
    if baseline == 0.0 {
        0.0
    } else {
        ((current - baseline) / baseline) * 100.0
    }
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn write_text(path: &Path, text: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)?;
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
