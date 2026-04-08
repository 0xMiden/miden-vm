//! DEEP quotient benchmarks.
//!
//! Benchmarks the barycentric evaluation used in DEEP quotient construction.
//! Runs benchmarks for Goldilocks with Poseidon2.
//!
//! Run with:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench deep_quotient --features testing
//!
//! # With parallelism
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench deep_quotient --features testing,parallel
//!
//! # Filter by field
//! cargo bench --bench deep_quotient --features testing -- goldilocks
//! ```

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_lifted_stark::{
    Lmcs, LmcsTree,
    testing::{
        LOG_HEIGHTS, PARALLEL_STR, PointQuotients, RELATIVE_SPECS, bit_reversed_coset_points,
        configs::goldilocks_poseidon2::{Felt, QuadFelt, test_lmcs},
        generate_matrices_from_specs, total_elements,
    },
};
use p3_field::FieldArray;
use p3_matrix::dense::RowMajorMatrix;
use rand::{RngExt, SeedableRng, distr::StandardUniform, rngs::SmallRng};

/// Log blowup factor for LDE.
const LOG_BLOWUP: u8 = 3;

// =============================================================================
// Benchmark implementation
// =============================================================================

fn bench_deep_quotient(c: &mut Criterion) {
    let lmcs = test_lmcs();

    for &log_lde_height in LOG_HEIGHTS {
        let n_leaves = 1usize << log_lde_height;
        let group_name =
            format!("DEEP_Quotient/{}/goldilocks/poseidon2/{}", n_leaves, PARALLEL_STR);
        let mut group = c.benchmark_group(&group_name);

        // Generate matrices using canonical specs
        let matrix_groups: Vec<Vec<RowMajorMatrix<Felt>>> =
            generate_matrices_from_specs(RELATIVE_SPECS, log_lde_height);
        group.throughput(Throughput::Elements(total_elements(&matrix_groups)));

        let trees: Vec<_> =
            matrix_groups.iter().map(|matrices| lmcs.build_tree(matrices.clone())).collect();

        // Precompute coset points (LDE domain matches max matrix height)
        let coset_points = bit_reversed_coset_points::<Felt>(log_lde_height);

        // Get matrix references from trees (stored as BitReversedMatrixView after build_tree)
        let matrices_refs: Vec<Vec<_>> =
            trees.iter().map(|tree| tree.leaves().iter().collect()).collect();

        // Benchmark: batch_eval_lifted with 1 point
        group.bench_function(BenchmarkId::from_parameter("batch_eval/N1"), |b| {
            let mut rng = SmallRng::seed_from_u64(789);
            b.iter(|| {
                let z: QuadFelt = rng.sample(StandardUniform);
                let quotient =
                    PointQuotients::<Felt, QuadFelt, 1>::new(FieldArray([z]), &coset_points);
                black_box(quotient.batch_eval_lifted(&matrices_refs, &coset_points, LOG_BLOWUP))
            });
        });

        // Benchmark: batch_eval_lifted with 2 points
        group.bench_function(BenchmarkId::from_parameter("batch_eval/N2"), |b| {
            let mut rng = SmallRng::seed_from_u64(789);
            b.iter(|| {
                let z1: QuadFelt = rng.sample(StandardUniform);
                let z2: QuadFelt = rng.sample(StandardUniform);
                let quotient =
                    PointQuotients::<Felt, QuadFelt, 2>::new(FieldArray([z1, z2]), &coset_points);
                black_box(quotient.batch_eval_lifted(&matrices_refs, &coset_points, LOG_BLOWUP))
            });
        });

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(12))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_deep_quotient
}
criterion_main!(benches);
