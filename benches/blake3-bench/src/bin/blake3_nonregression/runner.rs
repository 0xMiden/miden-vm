use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use miden_vm_blake3_bench::SpanRecord;
use serde::Serialize;

use crate::criterion_results::collect_result;

pub(crate) fn cmd_run(
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
        Command::new("cargo").arg("clean"),
        repo_root,
        &envs,
        &output_dir.join("clean.log"),
        true,
    )?;

    let mut build_bench_command = Command::new("cargo");
    build_bench_command.args([
        "bench",
        "--profile",
        "optimized",
        "-p",
        "miden-vm-blake3-bench",
        "--bench",
        "blake3_bench",
        "--no-run",
        "--message-format=json",
    ]);
    let _bench_executable = build_executable(
        &mut build_bench_command,
        repo_root,
        &envs,
        &output_dir.join("bench-build.log"),
    )?;

    let mut bench_command = Command::new("cargo");
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
    let bench_wall_ms = run_logged_command(
        &mut bench_command,
        repo_root,
        &envs,
        &output_dir.join("bench.log"),
        true,
    )?
    .elapsed_ms;

    let spans_path = output_dir.join("spans.json");
    let (span_collection_wall_ms, spans) = if should_collect_proof_spans(bench_axes) {
        let mut build_spans_command = Command::new("cargo");
        build_spans_command.args([
            "build",
            "--profile",
            "optimized",
            "-p",
            "miden-vm-blake3-bench",
            "--bin",
            "blake3-nonregression",
            "--message-format=json",
        ]);
        let spans_executable = build_executable(
            &mut build_spans_command,
            repo_root,
            &envs,
            &output_dir.join("spans-build.log"),
        )?;

        let mut spans_command = Command::new(spans_executable);
        spans_command
            .args(["collect-spans", "--repo-root"])
            .arg(repo_root)
            .arg("--output")
            .arg(&spans_path);
        let span_collection_wall_ms = run_logged_command(
            &mut spans_command,
            repo_root,
            &envs,
            &output_dir.join("spans.log"),
            true,
        )?
        .elapsed_ms;
        let spans: Vec<SpanRecord> = serde_json::from_str(&fs::read_to_string(&spans_path)?)?;
        (Some(span_collection_wall_ms), spans)
    } else {
        let spans = Vec::new();
        write_json(&spans_path, &spans)?;
        (None, spans)
    };

    let result = collect_result(
        repo_root,
        git_ref,
        Some(bench_wall_ms),
        span_collection_wall_ms,
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

fn build_executable(
    command: &mut Command,
    cwd: &Path,
    envs: &BTreeMap<String, String>,
    log_path: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let output = run_logged_command(command, cwd, envs, log_path, false)?;
    executable_from_json_messages(&output.stdout).ok_or_else(|| {
        format!("Cargo did not report an executable in {}", log_path.display()).into()
    })
}

pub(crate) fn executable_from_json_messages(stdout: &str) -> Option<PathBuf> {
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| {
            message.get("reason").and_then(|reason| reason.as_str()) == Some("compiler-artifact")
        })
        .filter_map(|message| {
            message
                .get("executable")
                .and_then(|executable| executable.as_str())
                .map(PathBuf::from)
        })
        .next_back()
}

struct LoggedOutput {
    elapsed_ms: f64,
    stdout: String,
}

fn run_logged_command(
    command: &mut Command,
    cwd: &Path,
    envs: &BTreeMap<String, String>,
    log_path: &Path,
    echo_output: bool,
) -> Result<LoggedOutput, Box<dyn std::error::Error>> {
    command.current_dir(cwd);
    for (key, value) in envs {
        command.env(key, value);
    }
    let start = Instant::now();
    let output = command.output()?;
    let elapsed = duration_ms(start.elapsed());
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let mut log = format!("$ {command:?}\n");
    log.push_str(&stdout);
    log.push_str(&stderr);
    write_text(log_path, &log)?;
    if echo_output {
        print!("{stdout}");
        eprint!("{stderr}");
    }
    if !output.status.success() {
        return Err(format!("command failed with status {}", output.status).into());
    }
    Ok(LoggedOutput { elapsed_ms: elapsed, stdout })
}

fn should_collect_proof_spans(bench_axes: &str) -> bool {
    let axes = split_csv(bench_axes);
    axes.is_empty()
        || axes.iter().any(|axis| {
            matches!(
                axis.as_str(),
                "all" | "e2e_prove" | "prove" | "prove_program_sync" | "prove_trace_sync"
            )
        })
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

pub(crate) fn write_json<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut json = serde_json::to_string_pretty(value)?;
    json.push('\n');
    fs::write(path, json)?;
    Ok(())
}

pub(crate) fn write_text(path: &Path, text: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)?;
    Ok(())
}
