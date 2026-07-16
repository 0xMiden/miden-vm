use std::collections::BTreeMap;

use miden_vm_blake3_bench::SpanRecord;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BenchmarkResult {
    pub(crate) repo_root: String,
    pub(crate) git_ref: String,
    pub(crate) git_sha: String,
    pub(crate) bench_wall_ms: Option<f64>,
    pub(crate) span_collection_wall_ms: Option<f64>,
    pub(crate) rayon_num_threads: Option<usize>,
    pub(crate) bench_axes: Vec<String>,
    pub(crate) sample_size: Option<usize>,
    pub(crate) light_sample_size: Option<usize>,
    pub(crate) measurement_time_secs: Option<u64>,
    pub(crate) warm_up_time_secs: Option<u64>,
    pub(crate) light_measurement_time_secs: Option<u64>,
    pub(crate) light_warm_up_time_secs: Option<u64>,
    pub(crate) primary_metric: String,
    pub(crate) metrics: BTreeMap<String, Metric>,
    pub(crate) spans: Vec<SpanRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Metric {
    pub(crate) name: String,
    pub(crate) source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mean_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) median_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) lower_bound_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) upper_bound_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) duration_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) span_path: Option<String>,
    pub(crate) unit: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Comparison {
    pub(crate) status: String,
    pub(crate) regression: bool,
    pub(crate) threshold_pct: f64,
    pub(crate) min_regression_ms: f64,
    pub(crate) primary_metric: String,
    pub(crate) baseline_sha: String,
    pub(crate) current_sha: String,
    pub(crate) baseline_ref: String,
    pub(crate) current_ref: String,
    pub(crate) baseline_primary_ms: f64,
    pub(crate) current_primary_ms: f64,
    pub(crate) program_delta_ms: f64,
    pub(crate) program_delta_pct: f64,
    pub(crate) baseline_bench_wall_ms: Option<f64>,
    pub(crate) current_bench_wall_ms: Option<f64>,
    pub(crate) rows: Vec<ComparisonRow>,
    pub(crate) regression_rows: Vec<ComparisonRow>,
    pub(crate) top_slowdowns: Vec<ComparisonRow>,
    pub(crate) missing_in_current: Vec<String>,
    pub(crate) missing_in_baseline: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ComparisonRow {
    pub(crate) name: String,
    pub(crate) source: String,
    pub(crate) baseline_ms: f64,
    pub(crate) current_ms: f64,
    pub(crate) delta_ms: f64,
    pub(crate) delta_pct: f64,
}
