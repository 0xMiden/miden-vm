//! Benchmark MastForest serialization and report byte sizes for full/stripped/hashless.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_core::{
    mast::{MastForest, arbitrary::MastForestParams},
    serde::Serializable,
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

fn serialize_sizes(forest: &MastForest) -> (usize, usize, usize) {
    let full_bytes = forest.to_bytes();

    let mut stripped_bytes = Vec::new();
    forest.write_stripped(&mut stripped_bytes);

    let mut hashless_bytes = Vec::new();
    forest.write_hashless(&mut hashless_bytes);

    (full_bytes.len(), stripped_bytes.len(), hashless_bytes.len())
}

fn bench_serialization_sizes(c: &mut Criterion) {
    let sizes: &[usize] = &[8, 16, 32, 64, 128, 256];
    let mut group = c.benchmark_group("mast_serialization");

    let seed = [0u8; 32];
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &seed),
    );

    for &blocks_per_forest in sizes {
        let gen_params = MastForestParams {
            decorators: 32,
            blocks: blocks_per_forest..=blocks_per_forest,
            max_joins: blocks_per_forest.min(8),
            max_splits: blocks_per_forest.min(8),
            max_loops: blocks_per_forest.min(4),
            max_calls: blocks_per_forest.min(4),
            max_syscalls: 0,
            max_externals: blocks_per_forest.min(2),
            max_dyns: blocks_per_forest.min(2),
        };

        let forest = sample_forest(gen_params, &mut runner);
        let (full, stripped, hashless) = serialize_sizes(&forest);
        eprintln!("blocks={blocks_per_forest} full={full} stripped={stripped} hashless={hashless}");

        group.throughput(Throughput::Bytes(full as u64));
        group.bench_with_input(
            BenchmarkId::new("full", blocks_per_forest),
            &forest,
            |b, forest| {
                b.iter(|| black_box(forest.to_bytes()));
            },
        );

        group.throughput(Throughput::Bytes(stripped as u64));
        group.bench_with_input(
            BenchmarkId::new("stripped", blocks_per_forest),
            &forest,
            |b, forest| {
                b.iter(|| {
                    let mut bytes = Vec::new();
                    forest.write_stripped(&mut bytes);
                    black_box(bytes);
                });
            },
        );

        group.throughput(Throughput::Bytes(hashless as u64));
        group.bench_with_input(
            BenchmarkId::new("hashless", blocks_per_forest),
            &forest,
            |b, forest| {
                b.iter(|| {
                    let mut bytes = Vec::new();
                    forest.write_hashless(&mut bytes);
                    black_box(bytes);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_serialization_sizes);
criterion_main!(benches);
