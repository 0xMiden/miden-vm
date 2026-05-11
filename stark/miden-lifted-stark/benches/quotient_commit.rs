//! Lifted `commit_quotient` benchmark.
//!
//! Measures the decomposition + LDE + Merkle commit pipeline for quotient
//! polynomials at different trace sizes.
//!
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench quotient_commit --features testing
//! ```

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_lifted_stark::{
    GenericStarkConfig, LiftedDomain, log2_strict_u8,
    testing::{
        QC_CONSTRAINT_DEGREE, QC_PCS_PARAMS, commit_quotient, configs::goldilocks_poseidon2 as gl,
    },
};
use p3_dft::Radix2DitParallel;
use rand::{RngExt, SeedableRng, rngs::SmallRng};

fn random_quotient_evals(n: usize, d: usize, seed: u64) -> Vec<gl::QuadFelt> {
    let mut rng = SmallRng::seed_from_u64(seed);
    (0..n * d).map(|_| rng.random()).collect()
}

fn bench_quotient_commit(c: &mut Criterion) {
    let config = GenericStarkConfig::new(
        QC_PCS_PARAMS,
        gl::test_lmcs(),
        Radix2DitParallel::default(),
        gl::test_challenger(),
    );
    let mut group = c.benchmark_group("quotient_commit");

    for log_n in [16u8, 17u8] {
        let n = 1usize << log_n;
        let b = 1usize << QC_PCS_PARAMS.log_blowup();
        let label = format!("N=2^{log_n}");

        let log_d = log2_strict_u8(QC_CONSTRAINT_DEGREE);
        let domain = LiftedDomain::<gl::Felt>::canonical(log_n, QC_PCS_PARAMS.log_blowup())
            .evaluation_domain(log_d);

        group.bench_function(BenchmarkId::new("lifted", &label), |bench| {
            bench.iter(|| {
                let mut q_evals = random_quotient_evals(n, QC_CONSTRAINT_DEGREE, 42);
                q_evals.reserve(n * b - n * QC_CONSTRAINT_DEGREE);
                let committed = commit_quotient(&config, q_evals, &domain);
                black_box(committed)
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_quotient_commit
}
criterion_main!(benches);
