//! Lifted STARK prove/verify profiling binary.
//!
//! Proves and verifies a set of AIR instances, printing a configuration summary,
//! proof size, and total time. Trace specifications are passed as positional
//! arguments; all parameters have sensible defaults.
//!
//! By default the output is concise (config header + proof size + total time).
//! Pass `-v` for the full hierarchical tracing tree, or set `RUST_LOG` for
//! fine-grained control.
//!
//! ```bash
//! # Quick run with defaults (miden:18):
//! cargo run -p miden-bench --features concurrent --release
//!
//! # Dummy degree-9 AIRs with configurable widths (default log_blowup=3):
//! cargo run -p miden-bench --features concurrent --release -- miden:18:51 miden:19:20
//!
//! # Full tracing tree:
//! cargo run -p miden-bench --features concurrent --release -- -v miden:15
//!
//! # Select a commitment hash:
//! cargo run -p miden-bench --features concurrent --release -- -H blake3 miden:15
//! ```

mod cli;
mod lifted;

use std::{fmt, time::Instant};

use clap::Parser;
use miden_core::Felt as MidenFelt;
use miden_stark::{
    GenericStarkConfig,
    config::eidos_config,
    pcs::PcsParams,
    testing::{
        airs::miden::generate_dummy_trace,
        configs::{
            Felt, QuadFelt, goldilocks_blake3 as blake3, goldilocks_blake3_192 as blake3_192,
            goldilocks_keccak as keccak,
        },
    },
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{SeedableRng, rngs::SmallRng};
use tracing::trace_span;
use tracing_subscriber::{Layer, Registry, layer::SubscriberExt, util::SubscriberInitExt};

use crate::cli::{Cli, HashFn, TraceSpec};

// ════════════════════════════════════════════════════════════════════════════��══
// Run result
// ═══════════════════════════════════════════════════════════════════════════════

/// Captured output from a single prove/verify invocation.
pub(crate) struct RunResult {
    pub(crate) proof_size_bytes: usize,
    /// Number of field elements in the proof.
    pub(crate) field_elems: usize,
    /// Number of commitments in the proof.
    pub(crate) commitments: usize,
}

impl fmt::Display for RunResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "proof size: {}", format_bytes(self.proof_size_bytes))?;
        if self.field_elems > 0 || self.commitments > 0 {
            write!(f, " ({} field elems, {} commitments)", self.field_elems, self.commitments,)?;
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Configuration summary
// ═══════════════════════════════════════════════════════════════════════════════

fn print_config(cli: &Cli, specs: &[TraceSpec], traces: &[RowMajorMatrix<Felt>], log_blowup: u8) {
    eprintln!("{:<20} {}", "hash:", cli.hash);
    eprintln!("{:<20} {}", "seed:", cli.seed);
    for (i, (spec, trace)) in specs.iter().zip(traces).enumerate() {
        let label = if i == 0 { "traces:" } else { "" };
        eprintln!(
            "{:<20} miden:{} (width={}, {})",
            label,
            spec.log_height,
            trace.width(),
            trace_row_summary(spec, trace.height()),
        );
    }
    eprintln!("{:<20} {}", "log_blowup:", log_blowup);
    eprintln!("{:<20} {}", "log_folding_arity:", cli.log_folding_arity);
    eprintln!("{:<20} {}", "log_final_degree:", cli.log_final_degree);
    eprintln!("{:<20} {}", "num_queries:", cli.num_queries);
    eprintln!("{:<20} {}", "deep_pow_bits:", cli.deep_pow_bits);
    eprintln!("{:<20} {}", "folding_pow_bits:", cli.folding_pow_bits);
    eprintln!("{:<20} {}", "query_pow_bits:", cli.query_pow_bits);
    eprintln!();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Trace generation
// ═══════════════════════════════════════════════════════════════════════════════

fn generate_traces(specs: &[TraceSpec], rng: &mut SmallRng) -> Vec<RowMajorMatrix<Felt>> {
    specs
        .iter()
        .map(|spec| {
            trace_span!(target: "miden::bench", "generate trace", air = "miden", log_height = spec.log_height)
                .in_scope(|| generate_dummy_trace(spec.width, spec.log_height, rng))
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

fn main() {
    let cli = Cli::parse();
    let mut specs = if cli.traces.is_empty() {
        vec![TraceSpec::default()]
    } else {
        cli.traces.clone()
    };

    // Sort by ascending height for deterministic output.
    specs.sort_by_key(|s| s.log_height);

    let log_blowup = cli.log_blowup.unwrap_or(3);

    // Set up tracing subscriber (quiet by default, -v for full tree).
    init_tracing(cli.verbose);

    let mut rng = SmallRng::seed_from_u64(cli.seed);
    let traces = generate_traces(&specs, &mut rng);

    // Print configuration summary.
    print_config(&cli, &specs, &traces, log_blowup);

    // Build PCS params (shared across hash functions).
    let pcs = PcsParams::new(
        log_blowup,
        cli.log_folding_arity,
        cli.log_final_degree,
        cli.folding_pow_bits,
        cli.deep_pow_bits,
        cli.num_queries,
        cli.query_pow_bits,
    )
    .expect("invalid PCS params");

    type Dft = p3_dft::Radix2DitParallel<Felt>;

    // Convert field representations before timing the native Eidos prover.
    let (traces, native_traces) = if cli.hash == HashFn::Eidos {
        let native = traces
            .into_iter()
            .map(|matrix| {
                RowMajorMatrix::new(
                    matrix.values.into_iter().map(MidenFelt::from).collect(),
                    matrix.width,
                )
            })
            .collect::<Vec<_>>();
        (Vec::new(), Some(native))
    } else {
        (traces, None)
    };

    // Run prove/verify.
    let start = Instant::now();
    let result = match cli.hash {
        HashFn::Eidos => {
            let config = eidos_config(
                pcs,
                [MidenFelt::ZERO; 4],
                miden_core::program::domain::STARK_TRANSCRIPT,
            );
            lifted::run_lifted(&config, &specs, native_traces.expect("native Eidos traces"), &cli)
        },
        HashFn::Keccak => {
            let config = GenericStarkConfig::<Felt, QuadFelt, _, _, _>::new(
                pcs,
                keccak::test_lmcs(),
                Dft::default(),
                keccak::test_challenger(),
            );
            lifted::run_lifted(&config, &specs, traces, &cli)
        },
        HashFn::Blake3 => {
            let config = GenericStarkConfig::<Felt, QuadFelt, _, _, _>::new(
                pcs,
                blake3::test_lmcs(),
                Dft::default(),
                blake3::test_challenger(),
            );
            lifted::run_lifted(&config, &specs, traces, &cli)
        },
        HashFn::Blake3_192 => {
            let config = GenericStarkConfig::<Felt, QuadFelt, _, _, _>::new(
                pcs,
                blake3_192::test_lmcs(),
                Dft::default(),
                blake3_192::test_challenger(),
            );
            lifted::run_lifted(&config, &specs, traces, &cli)
        },
    };
    let elapsed = start.elapsed();

    println!("{result}");
    println!("total time: {:.3} s", elapsed.as_secs_f64());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn init_tracing(verbose: bool) {
    let default_filter = if verbose {
        "debug,miden::vm=trace,miden::bench=trace"
    } else {
        "warn"
    };

    let env_filter = match std::env::var("RUST_LOG") {
        Ok(value) => tracing_subscriber::EnvFilter::try_new(value).expect("invalid RUST_LOG"),
        Err(std::env::VarError::NotPresent) => tracing_subscriber::EnvFilter::new(default_filter),
        Err(error) => panic!("invalid RUST_LOG: {error}"),
    };

    Registry::default()
        .with(tracing_forest::ForestLayer::default().with_filter(env_filter))
        .init();
}

fn trace_row_summary(spec: &TraceSpec, trace_height: usize) -> String {
    format!("2^{} = {trace_height} rows", spec.log_height)
}

pub(crate) fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miden_trace_summary_keeps_power_of_two_rows() {
        let spec = TraceSpec { log_height: 19, ..TraceSpec::default() };

        assert_eq!(trace_row_summary(&spec, 524_288), "2^19 = 524288 rows");
    }
}
