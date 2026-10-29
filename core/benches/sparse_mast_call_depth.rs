//! Measure extraction at exact call depths, with growing and fixed reachable node counts.

use std::{
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_core::mast::{
    CallNodeBuilder, JoinNodeBuilder, MastForest, MastNode, MastNodeExt, MastNodeId,
    SparseMastForest,
    arbitrary::{GenerationMode, MastForestParams},
};
use proptest::{
    arbitrary::any_with,
    strategy::Strategy,
    test_runner::{Config, RngAlgorithm, TestRng, TestRunner},
};

fn source_blocks() -> MastForest {
    let params = MastForestParams {
        blocks: 4_096..=4_096,
        max_joins: 0,
        max_splits: 0,
        max_loops: 0,
        max_calls: 0,
        max_syscalls: 0,
        max_externals: 0,
        max_dyns: 0,
        mode: GenerationMode::StructureOnly,
        ..Default::default()
    };
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &[17; 32]),
    );
    any_with::<MastForest>(params)
        .new_tree(&mut runner)
        .expect("forest strategy must be valid")
        .current()
}

fn fixture(
    blocks: &MastForest,
    frames: usize,
    seeds: usize,
    fixed_nodes: bool,
) -> (MastForest, Vec<MastNodeId>, usize) {
    let calls = if fixed_nodes { 31 } else { frames - 1 };
    let joins = if fixed_nodes { 224 } else { 0 };
    let mut source = blocks.clone();
    let mut roots = Vec::new();
    for seed in 0..seeds {
        let leaf = MastNodeId::new_unchecked(seed as u32);
        assert!(matches!(source[leaf], MastNode::Block(_)));
        let mut call_roots = Vec::new();
        let mut remaining = calls;
        while remaining > 0 {
            let chain_length = remaining.min(frames - 1);
            let mut root = leaf;
            for _ in 0..chain_length {
                root = CallNodeBuilder::new(root).add_to_forest(&mut source).unwrap();
            }
            call_roots.push(root);
            remaining -= chain_length;
        }
        let mut root = call_roots.pop().unwrap();
        let used_joins = call_roots.len();
        assert!(used_joins <= joins);
        for child in call_roots {
            root = JoinNodeBuilder::new([root, child]).add_to_forest(&mut source).unwrap();
        }
        for _ in used_joins..joins {
            root = JoinNodeBuilder::new([root, leaf]).add_to_forest(&mut source).unwrap();
        }
        source.make_root(root);
        roots.push(root);
    }

    let mut reachable = BTreeSet::new();
    let mut pending = roots.clone();
    while let Some(node_id) = pending.pop() {
        if reachable.insert(node_id) {
            source[node_id].append_children_to(&mut pending);
        }
    }
    assert_eq!(reachable.len(), seeds * (calls + joins + 1));
    assert_eq!(
        reachable.iter().filter(|&&id| matches!(source[id], MastNode::Call(_))).count(),
        seeds * calls
    );
    assert_eq!(
        reachable.iter().filter(|&&id| matches!(source[id], MastNode::Join(_))).count(),
        seeds * joins
    );

    // Count the initial frame plus nested calls independently of the fixture's construction.
    let mut depths = BTreeMap::new();
    for &node_id in &reachable {
        let node = &source[node_id];
        let mut depth = 1;
        node.for_each_child(|child| depth = depth.max(depths[&child]));
        depths.insert(node_id, depth + usize::from(matches!(node, MastNode::Call(_))));
    }
    for root in &roots {
        assert_eq!(depths[root], frames);
    }
    let extracted = SparseMastForest::from_procedure_roots(&source, &roots).unwrap();
    assert_eq!(extracted.nodes().keys().copied().collect::<BTreeSet<_>>(), reachable);
    assert_eq!(extracted.procedure_roots(), roots);

    println!(
        "fixture frames={frames} seeds={seeds} source_nodes={} extracted_nodes={} calls={} joins={}",
        source.num_nodes(),
        reachable.len(),
        seeds * calls,
        seeds * joins,
    );
    (source, roots, reachable.len())
}

fn call_depth(c: &mut Criterion) {
    let blocks = source_blocks();
    for workload in ["growing_chain", "fixed_nodes"] {
        let mut group = c.benchmark_group(format!("sparse_mast_call_depth/{workload}"));
        for seeds in [1, 4] {
            for frames in [8, 16, 32] {
                let (source, roots, nodes) =
                    fixture(&blocks, frames, seeds, workload == "fixed_nodes");
                group.throughput(Throughput::Elements(nodes as u64));
                group.bench_function(
                    BenchmarkId::new(format!("seeds={seeds}"), format!("frames={frames}")),
                    |bench| {
                        bench.iter(|| {
                            black_box(
                                SparseMastForest::from_procedure_roots(
                                    black_box(&source),
                                    black_box(&roots),
                                )
                                .unwrap(),
                            )
                        });
                    },
                );
            }
        }
        group.finish();
    }
}

criterion_group!(benches, call_depth);
criterion_main!(benches);
