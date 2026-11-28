//! Benchmark exact-ID and content-based subset checks across dense and sparse forests.

use std::{hint::black_box, sync::Arc};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_core::{
    Felt,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, MastForest, MastForestRead, MastNodeId,
        SparseMastForest, SparseMastForestBuilder, VisitKind,
    },
    operations::Operation,
};

struct SubsetFixture {
    source: Arc<MastForest>,
    remapped_dense: MastForest,
    exact_sparse: SparseMastForest,
    mixed_sparse: SparseMastForest,
    remapped_sparse: SparseMastForest,
}

fn append_call_chain(forest: &mut MastForest, node_count: usize, value: Felt) -> MastNodeId {
    let mut root = BasicBlockNodeBuilder::new(vec![Operation::Push(value)])
        .add_to_forest(forest)
        .expect("benchmark block must be valid");
    for _ in 1..node_count {
        root = CallNodeBuilder::new(root)
            .add_to_forest(forest)
            .expect("benchmark call must be valid");
    }
    root
}

fn make_fixture(node_count: usize) -> SubsetFixture {
    let value = Felt::new(7).expect("benchmark value must fit the base field");

    let mut remapped_dense = MastForest::new();
    let remapped_root = append_call_chain(&mut remapped_dense, node_count, value);
    remapped_dense.make_root(remapped_root);
    let remapped_sparse = SparseMastForest::from_procedure_roots(&remapped_dense, &[remapped_root])
        .expect("benchmark root must be exported");

    let mut source = MastForest::new();
    BasicBlockNodeBuilder::new(vec![Operation::Drop])
        .add_to_forest(&mut source)
        .expect("benchmark prefix must be valid");
    let source_root = append_call_chain(&mut source, node_count, value);
    source.make_root(source_root);
    let exact_sparse = SparseMastForest::from_procedure_roots(&source, &[source_root])
        .expect("benchmark root must be exported");

    let source = Arc::new(source);
    let mut mixed_builder = SparseMastForestBuilder::new(Arc::clone(&source));
    for (index, (node_id, _)) in exact_sparse.node_entries().enumerate() {
        let kind = if index % 2 == 0 {
            VisitKind::FullVisit
        } else {
            VisitKind::DigestOnly
        };
        mixed_builder.record_visit(node_id, kind);
    }
    let mixed_sparse = mixed_builder.finalize();

    assert!(exact_sparse.is_source_subset_of(source.as_ref()));
    assert!(mixed_sparse.is_source_subset_of(source.as_ref()));
    assert!(remapped_dense.is_content_subset_of(source.as_ref()));
    assert!(remapped_sparse.is_content_subset_of(source.as_ref()));
    assert!(mixed_sparse.is_content_subset_of(source.as_ref()));

    SubsetFixture {
        source,
        remapped_dense,
        exact_sparse,
        mixed_sparse,
        remapped_sparse,
    }
}

fn bench_source_id_subset(c: &mut Criterion, fixtures: &[(usize, SubsetFixture)]) {
    let mut group = c.benchmark_group("mast_forest_subset/source_ids");
    for (node_count, fixture) in fixtures {
        group.throughput(Throughput::Elements(*node_count as u64));
        group.bench_with_input(
            BenchmarkId::new("dense_self", node_count),
            fixture,
            |b, fixture| {
                b.iter(|| {
                    let candidate = black_box(fixture.source.as_ref());
                    let source = black_box(fixture.source.as_ref());
                    black_box(candidate.is_source_subset_of(source));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("sparse_full", node_count),
            fixture,
            |b, fixture| {
                b.iter(|| {
                    black_box(
                        black_box(&fixture.exact_sparse)
                            .is_source_subset_of(black_box(fixture.source.as_ref())),
                    );
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("sparse_full_and_digest", node_count),
            fixture,
            |b, fixture| {
                b.iter(|| {
                    black_box(
                        black_box(&fixture.mixed_sparse)
                            .is_source_subset_of(black_box(fixture.source.as_ref())),
                    );
                });
            },
        );
    }
    group.finish();
}

fn bench_content_subset(c: &mut Criterion, fixtures: &[(usize, SubsetFixture)]) {
    let mut group = c.benchmark_group("mast_forest_subset/content");
    for (node_count, fixture) in fixtures {
        group.throughput(Throughput::Elements(*node_count as u64));
        group.bench_with_input(
            BenchmarkId::new("dense_remapped", node_count),
            fixture,
            |b, fixture| {
                b.iter(|| {
                    black_box(
                        black_box(&fixture.remapped_dense)
                            .is_content_subset_of(black_box(fixture.source.as_ref())),
                    );
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("sparse_remapped", node_count),
            fixture,
            |b, fixture| {
                b.iter(|| {
                    black_box(
                        black_box(&fixture.remapped_sparse)
                            .is_content_subset_of(black_box(fixture.source.as_ref())),
                    );
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("sparse_full_and_digest", node_count),
            fixture,
            |b, fixture| {
                b.iter(|| {
                    black_box(
                        black_box(&fixture.mixed_sparse)
                            .is_content_subset_of(black_box(fixture.source.as_ref())),
                    );
                });
            },
        );
    }
    group.finish();
}

fn bench_subset_checks(c: &mut Criterion) {
    let fixtures: Vec<_> = [8, 64, 512, 4_096]
        .into_iter()
        .map(|node_count| (node_count, make_fixture(node_count)))
        .collect();
    bench_source_id_subset(c, &fixtures);
    bench_content_subset(c, &fixtures);
}

criterion_group!(benches, bench_subset_checks);
criterion_main!(benches);
