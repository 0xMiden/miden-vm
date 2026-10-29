//! Benchmark MastForest::merge on a handful of randomly generated forests.

use std::{hint::black_box, sync::Arc};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_core::mast::{
    MastForest, MastForestError, MastForestMergeSource, MastForestRead, MastForestRootMap,
    SparseMastForest, SparseMastForestBuilder, VisitKind,
    arbitrary::{GenerationMode, MastForestParams},
};
use proptest::{
    arbitrary::any_with,
    strategy::Strategy,
    test_runner::{Config, RngAlgorithm, TestRng, TestRunner},
};

/// Draw one MastForest sample from proptest's strategy space using the Arbitrary impl.
fn sample_forest(params: MastForestParams, runner: &mut TestRunner) -> MastForest {
    let strat = any_with::<MastForest>(params);
    strat.new_tree(runner).expect("strategy should be valid").current()
}

/// Pre-generate `count` random forests so setup cost is not measured in the benchmark.
fn make_forest_set(count: usize, params: MastForestParams) -> Vec<MastForest> {
    let seed = [0u8; 32];
    // Deterministic RNG so runs are reproducible; remove to get fresh each run.
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &seed),
    );
    (0..count).map(|_| sample_forest(params.clone(), &mut runner)).collect()
}

fn forest_params(blocks_per_forest: usize) -> MastForestParams {
    MastForestParams {
        blocks: blocks_per_forest..=blocks_per_forest,
        max_joins: blocks_per_forest.min(8),
        max_splits: blocks_per_forest.min(8),
        max_loops: blocks_per_forest.min(4),
        max_calls: blocks_per_forest.min(4),
        max_syscalls: 0,
        max_externals: blocks_per_forest.min(2),
        max_dyns: blocks_per_forest.min(2),
        mode: GenerationMode::StructureOnly,
        ..Default::default()
    }
}

fn make_sparse_forest_set(forests: &[MastForest]) -> Vec<SparseMastForest> {
    forests
        .iter()
        .map(|forest| {
            let mut builder = SparseMastForestBuilder::new(Arc::new(forest.clone()));
            for (index, (node_id, node)) in forest.node_entries().enumerate() {
                let kind = if index % 2 == 1 && !node.is_external() {
                    VisitKind::DigestOnly
                } else {
                    VisitKind::FullVisit
                };
                builder.record_visit(node_id, kind);
            }
            let sparse = builder.finalize();
            assert!(sparse.node_entries().next().is_some());
            assert!(sparse.digest_entries().next().is_some());
            assert_eq!(
                sparse.node_entries().count() + sparse.digest_entries().count(),
                forest.num_nodes() as usize
            );
            sparse
        })
        .collect()
}

fn mixed_sources<'forest>(
    dense: &'forest [MastForest],
    sparse: &'forest [SparseMastForest],
) -> Vec<MastForestMergeSource<'forest>> {
    dense
        .iter()
        .zip(sparse)
        .flat_map(|(dense, sparse)| {
            [MastForestMergeSource::from(dense), MastForestMergeSource::from(sparse)]
        })
        .collect()
}

fn bench_merge_varied_sizes(c: &mut Criterion) {
    // Merge 5 forests each time; vary the number of blocks per forest.
    let num_forests = 5usize;
    let sizes: &[usize] = &[8, 16, 32, 64, 128, 256];

    let mut group = c.benchmark_group("mast_forest_merge/varied_sizes");

    for &blocks_per_forest in sizes {
        // Pre-generate inputs (excluded from timing).
        let forests: Vec<MastForest> =
            make_forest_set(num_forests, forest_params(blocks_per_forest));

        // Report throughput as total "elements" processed per merge call.
        // Here we treat one "element" as one block/node.
        let total_elems = num_forests * blocks_per_forest;
        group.throughput(Throughput::Elements(total_elems as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(blocks_per_forest),
            &forests,
            |b, forests| {
                b.iter(|| {
                    let result: Result<(MastForest, MastForestRootMap), MastForestError> =
                        MastForest::merge(forests.iter());
                    black_box(result.unwrap());
                });
            },
        );
    }

    group.finish();
}

fn bench_mixed_merge_varied_sizes(c: &mut Criterion) {
    let num_forests = 5usize;
    let sizes: &[usize] = &[8, 16, 32, 64, 128, 256];
    let mut group = c.benchmark_group("mast_forest_merge/mixed_varied_sizes");

    for &blocks_per_forest in sizes {
        let dense = make_forest_set(num_forests, forest_params(blocks_per_forest));
        let sparse = make_sparse_forest_set(&dense);
        let sources = mixed_sources(&dense, &sparse);
        group.throughput(Throughput::Elements((2 * num_forests * blocks_per_forest) as u64));

        group.bench_with_input(
            BenchmarkId::new("dense_output", blocks_per_forest),
            &sources,
            |b, sources| {
                b.iter(|| {
                    let result = MastForest::merge(sources.iter().copied());
                    black_box(result.unwrap());
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("sparse_output", blocks_per_forest),
            &sources,
            |b, sources| {
                b.iter(|| {
                    let result = SparseMastForest::merge(sources.iter().copied());
                    black_box(result.unwrap());
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_merge_varied_sizes, bench_mixed_merge_varied_sizes);
criterion_main!(benches);
