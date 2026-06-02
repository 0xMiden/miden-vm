//! Traced PCS run for profiling with `tracing-subscriber`.
//!
//! Runs the lifted PCS open (Goldilocks + Poseidon2, arity-4) at log heights 16, 18, 20
//! with a tracing subscriber that prints hierarchical span timings.
//!
//! Run with:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench -p miden-lifted-stark --bench pcs_trace --features testing,parallel
//! ```

use std::time::Instant;

use miden_lifted_stark::testing::{
    LOG_HEIGHTS, Lmcs, LmcsTree, PcsParams, RELATIVE_SPECS, canonical_domain,
    configs::goldilocks_poseidon2::{Felt, QuadFelt, test_challenger, test_lmcs},
    generate_matrices_from_specs, open_with_channel,
};
use miden_stark_transcript::ProverTranscript;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_matrix::{Matrix, bitrev::BitReversibleMatrix, dense::RowMajorMatrix};
use tracing_subscriber::EnvFilter;

fn main() {
    // Initialize tracing subscriber.
    // Use RUST_LOG to control verbosity, e.g. RUST_LOG=debug for debug_span! events.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")),
        )
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    let dft = Radix2DitParallel::<Felt>::default();

    let params = PcsParams::new(
        2,  // log_blowup
        2,  // log_folding_arity (arity 4)
        8,  // log_final_degree
        0,  // folding_pow_bits
        0,  // deep_pow_bits
        30, // num_queries
        0,  // query_pow_bits
    )
    .expect("valid PCS params");

    for &log_lde_height in LOG_HEIGHTS {
        let size = 1usize << log_lde_height;
        eprintln!("\n{}", "=".repeat(60));
        eprintln!("=== Goldilocks lifted/arity4  log_height={log_lde_height}  (n={size}) ===");
        eprintln!("{}\n", "=".repeat(60));

        // LDE coset for this batch — sole source of `F::GENERATOR`.
        let domain = canonical_domain::<Felt>(log_lde_height, 0);
        let shift = domain.lde_shift();

        let matrix_groups: Vec<Vec<RowMajorMatrix<Felt>>> =
            generate_matrices_from_specs(RELATIVE_SPECS, log_lde_height);

        let lmcs = test_lmcs();

        // Compute LDE matrices and build LMCS tree
        let mut all_lde_matrices: Vec<_> = matrix_groups
            .iter()
            .flat_map(|matrices| {
                matrices.iter().map(|m| {
                    dft.coset_lde_batch(m.clone(), 2, shift)
                        .bit_reverse_rows()
                        .to_row_major_matrix()
                        .bit_reverse_rows()
                })
            })
            .collect::<Vec<_>>();
        all_lde_matrices.sort_by_key(Matrix::height);

        let tree = lmcs.build_aligned_tree(all_lde_matrices);
        let commitment = tree.root();

        let mut challenger = test_challenger();
        challenger.observe(commitment);
        let z1: QuadFelt = challenger.sample_algebra_element();
        let z2: QuadFelt = challenger.sample_algebra_element();
        let mut channel = ProverTranscript::new(challenger);

        let trace_trees: &[&_] = &[&tree];

        let start = Instant::now();
        open_with_channel::<Felt, QuadFelt, _, _, _, 2>(
            &params,
            &lmcs,
            &domain,
            [z1, z2],
            trace_trees,
            &mut channel,
        );
        let elapsed = start.elapsed();

        eprintln!(">>> Total open_with_channel: {elapsed:.3?}\n");
    }
}
