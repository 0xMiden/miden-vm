//! FRI folding benchmarks for lifted implementation.
//!
//! Benchmarks FRI fold operations at different arities (2, 4, 8).
//! Runs benchmarks for Goldilocks (field-only, no hashing).
//!
//! Run with:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench fri_fold --features testing
//!
//! # With parallelism
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench fri_fold --features testing,parallel
//!
//! # Filter by field
//! cargo bench --bench fri_fold --features testing -- goldilocks
//! ```

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_lifted_stark::testing::{
    FRI_FOLD_ARITY_2, FRI_FOLD_ARITY_4, FRI_FOLD_ARITY_8, FriFold, LOG_HEIGHTS, PARALLEL_STR,
    TEST_SEED,
    configs::goldilocks_poseidon2::{Felt, QuadFelt},
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{RngExt, SeedableRng, distr::StandardUniform, rngs::SmallRng};

/// Target number of rows after all folding rounds.
const TARGET: usize = 8;

fn bench_lifted_fold(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    fold: FriFold,
    n_elems: usize,
) {
    let rng = &mut SmallRng::seed_from_u64(TEST_SEED);
    let arity = fold.arity();

    let n_rows = n_elems / arity;
    let s_invs: Vec<Felt> = rng.sample_iter(StandardUniform).take(n_rows).collect();

    let values: Vec<QuadFelt> = rng.sample_iter(StandardUniform).take(n_elems).collect();
    let input = RowMajorMatrix::new(values, arity);

    group.bench_with_input(
        BenchmarkId::from_parameter(format!("arity{arity}")),
        &n_elems,
        |b, &_n| {
            b.iter(|| {
                let mut current = input.clone();

                while current.height() > TARGET {
                    let rows = current.height();
                    let beta: QuadFelt = rng.sample(StandardUniform);
                    let evals = fold.fold_matrix(
                        black_box(current.as_view()),
                        black_box(&s_invs[..rows]),
                        black_box(beta),
                    );
                    current = RowMajorMatrix::new(evals, arity);
                }
                black_box(current)
            });
        },
    );
}

fn bench_fri_fold(c: &mut Criterion) {
    for &log_height in LOG_HEIGHTS {
        let n_elems = 1usize << log_height;
        let group_name = format!("FRI_Fold/{n_elems}/goldilocks/{PARALLEL_STR}");
        let mut group = c.benchmark_group(&group_name);
        group.throughput(Throughput::Elements(n_elems as u64));

        bench_lifted_fold(&mut group, FRI_FOLD_ARITY_2, n_elems);
        bench_lifted_fold(&mut group, FRI_FOLD_ARITY_4, n_elems);
        bench_lifted_fold(&mut group, FRI_FOLD_ARITY_8, n_elems);

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(12))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_fri_fold
}
criterion_main!(benches);
