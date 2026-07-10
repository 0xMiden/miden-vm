use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use miden_vm_blake3_bench::{Blake3Fixture, collect_trace_spans};

#[path = "blake3_nonregression/compare.rs"]
mod compare;
#[path = "blake3_nonregression/criterion_results.rs"]
mod criterion_results;
#[path = "blake3_nonregression/model.rs"]
mod model;
#[path = "blake3_nonregression/report.rs"]
mod report;
#[path = "blake3_nonregression/runner.rs"]
mod runner;

use compare::compare_results;
use model::BenchmarkResult;
use report::{summary_markdown, write_github_output};
use runner::{cmd_run, write_json, write_text};

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
        #[arg(long)]
        light_measurement_time_secs: Option<u64>,
        #[arg(long)]
        light_warm_up_time_secs: Option<u64>,
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
            light_measurement_time_secs,
            light_warm_up_time_secs,
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
                light_measurement_time_secs,
                light_warm_up_time_secs,
                &bench_axes,
                &git_ref,
            )?;
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path};

    use crate::{
        compare::compare_results,
        criterion_results::{estimate_ms, metric_name_from_estimate_path, selected_criterion_axes},
        model::{BenchmarkResult, Metric},
        report::summary_markdown,
        runner::executable_from_json_messages,
    };

    #[test]
    fn criterion_estimate_path_yields_axis_name() {
        let root = Path::new("target/criterion");
        let path = root.join("blake3_1to1/build_trace/new/estimates.json");

        assert_eq!(metric_name_from_estimate_path(root, &path).as_deref(), Some("build_trace"));
    }

    #[test]
    fn selected_axes_filter_normalizes_legacy_prove_name() {
        let axes = selected_criterion_axes("prove_program_sync,build_trace").unwrap();

        assert!(axes.contains("e2e_prove"));
        assert!(axes.contains("build_trace"));
        assert!(!axes.contains("prove_program_sync"));
    }

    #[test]
    fn estimate_parser_converts_nanoseconds_to_milliseconds() {
        let payload = serde_json::json!({
            "mean": {
                "point_estimate": 2_000_000.0,
                "confidence_interval": {
                    "lower_bound": 1_000_000.0,
                    "upper_bound": 3_000_000.0
                }
            }
        });

        assert_eq!(estimate_ms(&payload, "mean"), Some((2.0, 1.0, 3.0)));
    }

    #[test]
    fn cargo_json_parser_finds_executable_path() {
        let messages = r#"
{"reason":"compiler-artifact","target":{"kind":["bench"]},"executable":"/tmp/target/optimized/deps/blake3_bench-abc123"}
{"reason":"build-finished","success":true}
"#;

        assert_eq!(
            executable_from_json_messages(messages).as_deref(),
            Some(Path::new("/tmp/target/optimized/deps/blake3_bench-abc123"))
        );
    }

    #[test]
    fn comparison_summary_matches_snapshot() {
        let comparison = compare_results(
            &result_with_metric("base", "e2e_prove", 1_000.0),
            &result_with_metric("head", "e2e_prove", 1_100.0),
            5.0,
        )
        .unwrap();
        let summary = summary_markdown(&comparison);

        assert!(comparison.regression);
        insta::assert_snapshot!("comparison_summary", summary);
    }

    #[test]
    fn comparison_fails_when_secondary_axis_crosses_threshold() {
        let mut baseline = result_with_metric("base", "e2e_prove", 1_000.0);
        baseline.metrics.insert(
            "build_trace".to_string(),
            metric("build_trace", "criterion", Some(100.0), None),
        );
        let mut current = result_with_metric("head", "e2e_prove", 1_010.0);
        current.metrics.insert(
            "build_trace".to_string(),
            metric("build_trace", "criterion", Some(120.0), None),
        );

        let comparison = compare_results(&baseline, &current, 5.0).unwrap();

        assert!(comparison.regression);
    }

    fn metric(name: &str, source: &str, mean_ms: Option<f64>, duration_ms: Option<f64>) -> Metric {
        Metric {
            name: name.to_string(),
            source: source.to_string(),
            mean_ms,
            median_ms: None,
            lower_bound_ms: None,
            upper_bound_ms: None,
            duration_ms,
            span_path: None,
            unit: "ms".to_string(),
        }
    }

    fn result_with_metric(git_ref: &str, name: &str, mean_ms: f64) -> BenchmarkResult {
        let mut metrics = BTreeMap::new();
        metrics.insert(name.to_string(), metric(name, "criterion", Some(mean_ms), None));
        BenchmarkResult {
            repo_root: ".".to_string(),
            git_ref: git_ref.to_string(),
            git_sha: format!("{git_ref}-sha"),
            bench_wall_ms: None,
            span_collection_wall_ms: None,
            rayon_num_threads: None,
            bench_axes: vec![name.to_string()],
            sample_size: None,
            light_sample_size: None,
            measurement_time_secs: None,
            warm_up_time_secs: None,
            light_measurement_time_secs: None,
            light_warm_up_time_secs: None,
            primary_metric: name.to_string(),
            metrics,
            spans: Vec::new(),
        }
    }
}
