//! Benchmark MastForest::merge on a handful of randomly generated forests.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_core::mast::{
    MastForest, MastForestError, MastForestRootMap, arbitrary::MastForestParams,
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

fn bench_merge_varied_sizes(c: &mut Criterion) {
    // Merge 5 forests each time; vary the number of blocks per forest.
    let num_forests = 5usize;
    let sizes: &[usize] = &[8, 16, 32, 64, 128, 256];

    let mut group = c.benchmark_group("mast_forest_merge/varied_sizes");

    for &blocks_per_forest in sizes {
        // Generator knobs for this input size.
        let gen_params = MastForestParams {
            decorators: 32,                                // IDs in [0, 32)
            blocks: blocks_per_forest..=blocks_per_forest, // fixed size per forest
        };

        // Pre-generate inputs (excluded from timing).
        let forests: Vec<MastForest> = make_forest_set(num_forests, gen_params);

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

criterion_group!(benches, bench_merge_varied_sizes);
criterion_main!(benches);
