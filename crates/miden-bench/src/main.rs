//! Unified STARK prove/verify profiling binary.
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
//! # Quick run with defaults (blake3:15 keccak:18 poseidon2:19):
//! cargo run -p miden-bench --features parallel --release
//!
//! # Custom traces:
//! cargo run -p miden-bench --features parallel --release -- keccak:15 keccak:18 keccak:19
//!
//! # Full tracing tree:
//! cargo run -p miden-bench --features parallel --release -- -v keccak:15
//!
//! # Multi-iteration with warm-up (reports min/median/mean/max):
//! cargo run -p miden-bench --features parallel --release -- -n 5 keccak:15
//!
//! # Miden-shaped AIR (auto log_blowup=3):
//! cargo run -p miden-bench --features parallel --release -- miden:18:51 miden:19:20
//!
//! # Batch-STARK comparison:
//! cargo run -p miden-bench --features parallel --release -- -m batch keccak:15 keccak:18
//! ```

mod batch;
mod cli;
mod lifted;

use std::{fmt, time::Instant};

use clap::Parser;
use miden_lifted_stark::{
    GenericStarkConfig, PcsParams,
    testing::{
        airs::{
            blake3::generate_blake3_trace,
            keccak::generate_keccak_trace,
            miden::generate_dummy_trace,
            poseidon2::{HALF_FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH, generate_poseidon2_trace},
        },
        configs::{
            Felt, QuadFelt, goldilocks_blake3 as blake3, goldilocks_blake3_192 as blake3_192,
            goldilocks_keccak as keccak, goldilocks_poseidon2 as gl,
        },
    },
};
use p3_goldilocks::GenericPoseidon2LinearLayersGoldilocks;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_poseidon2_air::RoundConstants;
use rand::{RngExt, SeedableRng, rngs::SmallRng};
use tracing::info_span;
use tracing_subscriber::{Layer, Registry, layer::SubscriberExt, util::SubscriberInitExt};

use crate::cli::{AirType, Cli, HashFn, Mode, TraceSpec};

// ─── Type aliases ───────────────────────────────────────────────────────────���

type Gl = p3_goldilocks::Goldilocks;
type GlRoundConstants = RoundConstants<Gl, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

type BatchPoseidon2Air = p3_poseidon2_air::Poseidon2Air<
    Felt,
    GenericPoseidon2LinearLayersGoldilocks,
    WIDTH,
    { miden_lifted_stark::testing::airs::poseidon2::SBOX_DEGREE },
    { miden_lifted_stark::testing::airs::poseidon2::SBOX_REGISTERS },
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

const KECCAK_ROWS_PER_HASH: usize = 24;

// ════════════════════════════════════════════════════════════════════════════��══
// Run result
// ═══════════════════════════════════════════════════════════════════════════════

/// Captured output from a single prove/verify invocation.
pub(crate) struct RunResult {
    pub(crate) proof_size_bytes: usize,
    /// Number of field elements in the proof (lifted only, 0 for batch).
    pub(crate) field_elems: usize,
    /// Number of commitments in the proof (lifted only, 0 for batch).
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
    let mode = match cli.mode {
        Mode::Lifted => "lifted",
        Mode::Batch => "batch",
    };
    eprintln!("{:<20} {mode}", "mode:");
    eprintln!("{:<20} {}", "hash:", cli.hash);
    eprintln!("{:<20} {}", "seed:", cli.seed);
    for (i, (spec, trace)) in specs.iter().zip(traces).enumerate() {
        let label = if i == 0 { "traces:" } else { "" };
        eprintln!(
            "{:<20} {}:{} (width={}, 2^{} = {} rows)",
            label,
            spec.air_type,
            spec.log_height,
            trace.width(),
            spec.log_height,
            trace.height(),
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
// Trace generation (shared between modes)
// ═══════════════════════════════════════════════════════════════════════════════

fn generate_traces(
    specs: &[TraceSpec],
    rng: &mut SmallRng,
    constants: Option<&GlRoundConstants>,
) -> Vec<RowMajorMatrix<Felt>> {
    specs
        .iter()
        .map(|spec| {
            info_span!("generate trace", air = %spec.air_type, log_height = spec.log_height)
                .in_scope(|| match spec.air_type {
                    AirType::Keccak => {
                        let n = (1usize << spec.log_height) / KECCAK_ROWS_PER_HASH;
                        let inputs: Vec<[u64; 25]> = (0..n).map(|_| rng.random()).collect();
                        generate_keccak_trace(inputs)
                    },
                    AirType::Poseidon2 => {
                        let n = 1usize << spec.log_height;
                        let inputs: Vec<[Felt; 12]> = (0..n).map(|_| rng.random()).collect();
                        generate_poseidon2_trace(
                            inputs,
                            constants.expect("poseidon2 constants required"),
                        )
                    },
                    AirType::Blake3 => {
                        let n = 1usize << spec.log_height;
                        let inputs: Vec<[u32; 24]> = (0..n).map(|_| rng.random()).collect();
                        generate_blake3_trace(inputs)
                    },
                    AirType::Miden => generate_dummy_trace(spec.width, spec.log_height, rng),
                })
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

fn main() {
    let cli = Cli::parse();

    // Apply defaults.
    let mut specs = if cli.traces.is_empty() {
        vec![
            TraceSpec {
                air_type: AirType::Blake3,
                log_height: 15,
                width: 0,
                num_aux_cols: 0,
            },
            TraceSpec {
                air_type: AirType::Keccak,
                log_height: 18,
                width: 0,
                num_aux_cols: 0,
            },
            TraceSpec {
                air_type: AirType::Poseidon2,
                log_height: 19,
                width: 0,
                num_aux_cols: 0,
            },
        ]
    } else {
        cli.traces.clone()
    };

    // Sort by ascending height (required by the lifted prover).
    specs.sort_by_key(|s| s.log_height);

    let has_miden = specs.iter().any(|s| s.air_type == AirType::Miden);
    let log_blowup = cli.log_blowup.unwrap_or(if has_miden { 3 } else { 1 });

    // Set up tracing subscriber (quiet by default, -v for full tree).
    init_tracing(cli.verbose);

    // Generate Poseidon2 round constants (from RNG, before trace inputs).
    let mut rng = SmallRng::seed_from_u64(cli.seed);
    let poseidon2_constants: Option<GlRoundConstants> =
        if specs.iter().any(|s| s.air_type == AirType::Poseidon2) {
            Some(RoundConstants::from_rng(&mut rng))
        } else {
            None
        };

    // Generate traces.
    let traces = generate_traces(&specs, &mut rng, poseidon2_constants.as_ref());

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

    // Run prove/verify.
    let start = Instant::now();
    let result = match cli.mode {
        Mode::Lifted => match cli.hash {
            HashFn::Poseidon2 => {
                let config = GenericStarkConfig::new(
                    pcs,
                    gl::test_lmcs(),
                    Dft::default(),
                    gl::test_challenger(),
                );
                lifted::run_lifted(&config, &specs, &traces, &poseidon2_constants, &cli)
            },
            HashFn::Keccak => {
                let config = GenericStarkConfig::new(
                    pcs,
                    keccak::test_lmcs(),
                    Dft::default(),
                    keccak::test_challenger(),
                );
                lifted::run_lifted(&config, &specs, &traces, &poseidon2_constants, &cli)
            },
            HashFn::Blake3 => {
                let config = GenericStarkConfig::new(
                    pcs,
                    blake3::test_lmcs(),
                    Dft::default(),
                    blake3::test_challenger(),
                );
                lifted::run_lifted(&config, &specs, &traces, &poseidon2_constants, &cli)
            },
            HashFn::Blake3_192 => {
                let config = GenericStarkConfig::new(
                    pcs,
                    blake3_192::test_lmcs(),
                    Dft::default(),
                    blake3_192::test_challenger(),
                );
                lifted::run_lifted(&config, &specs, &traces, &poseidon2_constants, &cli)
            },
        },
        Mode::Batch => match cli.hash {
            HashFn::Poseidon2 => {
                batch::run_batch_poseidon2(&specs, &traces, &poseidon2_constants, log_blowup, &cli)
            },
            HashFn::Keccak => {
                batch::run_batch_keccak(&specs, &traces, &poseidon2_constants, log_blowup, &cli)
            },
            HashFn::Blake3 => {
                batch::run_batch_blake3(&specs, &traces, &poseidon2_constants, log_blowup, &cli)
            },
            HashFn::Blake3_192 => {
                batch::run_batch_blake3_192(&specs, &traces, &poseidon2_constants, log_blowup, &cli)
            },
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
    let default_level = if verbose {
        tracing_forest::util::LevelFilter::DEBUG
    } else {
        tracing_forest::util::LevelFilter::WARN
    };

    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env_lossy();

    Registry::default()
        .with(tracing_forest::ForestLayer::default().with_filter(env_filter))
        .init();
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
