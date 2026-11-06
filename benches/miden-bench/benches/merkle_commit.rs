//! Merkle tree commit benchmarks for LMCS.
//!
//! Benchmarks LMCS commit operations including ExtensionMmcs for FRI.
//! Runs benchmarks for Goldilocks with Eidos.
//!
//! Run with:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench -p miden-bench --bench merkle_commit
//!
//! # With parallelism
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench -p miden-bench \
//!     --bench merkle_commit --features concurrent
//!
//! # Filter by field
//! cargo bench -p miden-bench --bench merkle_commit -- goldilocks
//! ```

#[path = "support/eidos.rs"]
mod eidos;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use eidos::{Felt, QuadFelt, test_lmcs};
use miden_stark::testing::{
    LOG_HEIGHTS, Lmcs, LmcsTree, PARALLEL_STR, RELATIVE_SPECS, generate_matrices_from_specs,
    total_elements,
};
use p3_matrix::{bitrev::BitReversalPerm, dense::RowMajorMatrix, extension::FlatMatrixView};
use rand::{SeedableRng, rngs::SmallRng};

// =============================================================================
// Benchmark implementation
// =============================================================================

fn bench_merkle_commit(c: &mut Criterion) {
    let lmcs = test_lmcs();

    for &log_max_height in LOG_HEIGHTS {
        let n_leaves = 1usize << log_max_height;
        let group_name = format!("MerkleCommit/{n_leaves}/goldilocks/eidos/{PARALLEL_STR}");
        let mut group = c.benchmark_group(&group_name);
        group.throughput(Throughput::Elements(total_elements(
            &generate_matrices_from_specs::<Felt>(RELATIVE_SPECS, log_max_height),
        )));

        // Generate matrices using canonical specs
        let matrix_groups: Vec<Vec<RowMajorMatrix<Felt>>> =
            generate_matrices_from_specs(RELATIVE_SPECS, log_max_height);

        // LMCS commit
        {
            group.bench_with_input(
                BenchmarkId::from_parameter("lmcs"),
                &matrix_groups,
                |b, groups| {
                    b.iter(|| {
                        for matrices in groups {
                            let tree = lmcs.build_tree(matrices.clone());
                            black_box(tree.root());
                        }
                    });
                },
            );
        }

        // Extension field matrix with width-2 (simulates FRI arity-2 commit)
        // Uses FlatMatrixView to convert EF matrix to base field view
        {
            let rng = &mut SmallRng::seed_from_u64(miden_stark::testing::TEST_SEED);
            let ext_matrix = RowMajorMatrix::<QuadFelt>::rand(rng, n_leaves, 2);

            group.bench_with_input(
                BenchmarkId::from_parameter("ext/arity2"),
                &ext_matrix,
                |b, matrix| {
                    b.iter(|| {
                        let flat = FlatMatrixView::new(matrix.clone());
                        let tree = lmcs.build_tree(vec![BitReversalPerm::new_view(flat)]);
                        black_box(tree.root())
                    });
                },
            );
        }

        // Extension field matrix with width-4 (simulates FRI arity-4 commit)
        {
            let rng = &mut SmallRng::seed_from_u64(miden_stark::testing::TEST_SEED);
            let ext_matrix = RowMajorMatrix::<QuadFelt>::rand(rng, n_leaves, 4);

            group.bench_with_input(
                BenchmarkId::from_parameter("ext/arity4"),
                &ext_matrix,
                |b, matrix| {
                    b.iter(|| {
                        let flat = FlatMatrixView::new(matrix.clone());
                        let tree = lmcs.build_tree(vec![BitReversalPerm::new_view(flat)]);
                        black_box(tree.root())
                    });
                },
            );
        }

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(12))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_merkle_commit
}
criterion_main!(benches);
