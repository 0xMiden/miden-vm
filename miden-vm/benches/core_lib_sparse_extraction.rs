//! Measure sparse extraction from the core library, excluding package loading and root selection.

use std::{collections::BTreeSet, hint::black_box};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_core::mast::{MastNodeExt, SparseMastForest, SparseMastForestBuilder, VisitKind};
use miden_core_lib::CoreLibrary;

fn core_lib_sparse_extraction(c: &mut Criterion) {
    let library = CoreLibrary::default();
    let source = library.mast_forest();
    let exports = source.procedure_roots();
    assert!(exports.len() >= 16);

    let mut group = c.benchmark_group("core_lib_sparse_extraction");
    for root_count in [1, 4, 16, exports.len()] {
        // Spread the selected roots across the library's export order.
        let roots: Vec<_> = (0..root_count)
            .map(|index| exports[index * exports.len() / root_count])
            .collect();
        let mut reachable = BTreeSet::new();
        let mut pending = roots.clone();
        while let Some(node_id) = pending.pop() {
            if reachable.insert(node_id) {
                source[node_id].append_children_to(&mut pending);
            }
        }

        let extracted = SparseMastForest::from_procedure_roots(source, &roots)
            .expect("selected core library roots must be exported");
        assert_eq!(extracted.procedure_roots(), roots);
        assert_eq!(extracted.nodes().keys().copied().collect::<BTreeSet<_>>(), reachable);
        println!(
            "core_lib_fixture source_nodes={} exported_roots={} selected_roots={} extracted_nodes={} root_ids={roots:?}",
            source.num_nodes(),
            exports.len(),
            root_count,
            reachable.len(),
        );
        let parameter = format!("roots={root_count}/nodes={}", reachable.len());
        group.throughput(Throughput::Elements(reachable.len() as u64));
        group.bench_function(BenchmarkId::new("direct_sparse", &parameter), |bench| {
            bench.iter(|| {
                black_box(
                    SparseMastForest::from_procedure_roots(
                        black_box(source.as_ref()),
                        black_box(&roots),
                    )
                    .expect("selected core library roots must be exported"),
                )
            });
        });
        group.bench_function(BenchmarkId::new("replay_builder", &parameter), |bench| {
            bench.iter(|| {
                let mut builder = SparseMastForestBuilder::new(source.clone());
                for &node_id in black_box(&reachable) {
                    builder.record_visit(node_id, VisitKind::FullVisit);
                }
                black_box(builder.finalize())
            });
        });
    }
    group.finish();
}

criterion_group!(benches, core_lib_sparse_extraction);
criterion_main!(benches);
