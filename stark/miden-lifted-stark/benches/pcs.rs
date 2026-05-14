//! Lifted PCS open benchmarks at different folding arities.
//!
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench pcs --features testing
//! ```

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use miden_lifted_stark::{
    LiftedDomain, Lmcs, LmcsTree,
    testing::{
        BENCH_PCS_PARAMS, LOG_HEIGHTS, PARALLEL_STR, RELATIVE_SPECS,
        configs::goldilocks_poseidon2::{Felt, QuadFelt, test_challenger, test_lmcs},
        generate_matrices_from_specs, open_with_channel, total_elements,
    },
};
use miden_stark_transcript::ProverTranscript;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

fn bench_pcs(c: &mut Criterion) {
    let dft = Radix2DitParallel::<Felt>::default();
    let lmcs = test_lmcs();

    for &log_lde_height in LOG_HEIGHTS {
        let domain = LiftedDomain::<Felt>::canonical(log_lde_height, 0);
        let shift = domain.lde_shift();
        let max_lde_size = 1usize << log_lde_height;
        let group_name = format!("PCS_Open/{max_lde_size}/goldilocks/poseidon2/{PARALLEL_STR}");
        let mut group = c.benchmark_group(&group_name);

        let matrix_groups: Vec<Vec<RowMajorMatrix<Felt>>> =
            generate_matrices_from_specs(RELATIVE_SPECS, log_lde_height);
        group.throughput(Throughput::Elements(total_elements(&matrix_groups)));

        // Compute LDE matrices and flatten into a single group (sorted by height)
        let mut all_lde_matrices: Vec<_> = matrix_groups
            .iter()
            .flat_map(|matrices| {
                matrices.iter().map(|m| {
                    dft.coset_lde_batch(m.clone(), BENCH_PCS_PARAMS.log_blowup() as usize, shift)
                })
            })
            .collect();
        all_lde_matrices.sort_by_key(Matrix::height);

        let tree = lmcs.build_aligned_tree(all_lde_matrices);
        let commitment = tree.root();

        let base_challenger = test_challenger();

        {
            group.bench_function("open", |b| {
                b.iter(|| {
                    let mut challenger = base_challenger.clone();
                    challenger.observe(commitment);
                    let z1: QuadFelt = challenger.sample_algebra_element();
                    let z2: QuadFelt = challenger.sample_algebra_element();
                    let mut channel = ProverTranscript::new(challenger);

                    let trace_trees: &[&_] = &[&tree];
                    open_with_channel::<Felt, QuadFelt, _, _, _, 2>(
                        &BENCH_PCS_PARAMS,
                        &lmcs,
                        &domain,
                        [z1, z2],
                        trace_trees,
                        &mut channel,
                    );
                    black_box(channel.finalize())
                });
            });
        }

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_pcs
}
criterion_main!(benches);
