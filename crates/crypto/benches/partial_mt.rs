//! PartialMerkleTree construction and operation benchmarks.

use std::{hint, time::Duration};

use criterion::{
    BatchSize, Bencher, BenchmarkGroup, Criterion, criterion_group, criterion_main,
    measurement::WallTime,
};
use miden_crypto::{
    Word,
    merkle::{MerklePath, MerkleTree, NodeIndex, PartialMerkleTree},
};

mod common;
use common::data::{WordPattern, generate_word_pattern};

// === PartialMerkleTree Add Path Fixtures ===

const TREE_DEPTH: u8 = 10;
const TREE_LEAF_COUNT: u64 = 1 << TREE_DEPTH;
const KNOWN_LEAF_COUNT: u64 = 128;
const MIXED_DEPTH: u8 = 8;

#[derive(Clone)]
struct AddPathFixture {
    tree: PartialMerkleTree,
    path: MerklePath,
    index: u64,
    value: Word,
    expect_ok: bool,
}

struct AddPathInput {
    tree: PartialMerkleTree,
    path: Option<MerklePath>,
    index: u64,
    value: Word,
    expect_ok: bool,
}

fn full_tree(seed: u64) -> MerkleTree {
    let leaves = (0..TREE_LEAF_COUNT)
        .map(|i| generate_word_pattern(seed + i, WordPattern::MerkleStandard))
        .collect::<Vec<_>>();
    MerkleTree::new(leaves).unwrap()
}

fn partial_tree_with_paths(tree: &MerkleTree, depth: u8, count: u64) -> PartialMerkleTree {
    let paths = (0..count).map(|position| {
        let index = NodeIndex::new(depth, position).unwrap();
        (position, tree.get_node(index).unwrap(), tree.get_path(index).unwrap())
    });
    PartialMerkleTree::with_paths(paths).unwrap()
}

fn add_path_fixture(
    tree: PartialMerkleTree,
    source: &MerkleTree,
    depth: u8,
    position: u64,
    expect_ok: bool,
) -> AddPathFixture {
    let index = NodeIndex::new(depth, position).unwrap();
    AddPathFixture {
        tree,
        path: source.get_path(index).unwrap(),
        index: position,
        value: source.get_node(index).unwrap(),
        expect_ok,
    }
}

fn run_add_path(input: &mut AddPathInput) -> bool {
    let path = input.path.take().expect("each input has exactly one path");
    let result = input.tree.add_path(input.index, input.value, path);
    let ok = result.is_ok();
    assert_eq!(ok, input.expect_ok, "unexpected add_path result");
    ok
}

fn bench_add_path_case(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    fixture: AddPathFixture,
) {
    group.bench_function(name, |b| {
        b.iter_batched_ref(
            || AddPathInput {
                tree: fixture.tree.clone(),
                path: Some(fixture.path.clone()),
                index: fixture.index,
                value: fixture.value,
                expect_ok: fixture.expect_ok,
            },
            run_add_path,
            BatchSize::SmallInput,
        );
    });
}

fn benchmark_add_path(c: &mut Criterion) {
    let tree_a = full_tree(0);
    let tree_b = full_tree(1_000_000);

    let known_tree = partial_tree_with_paths(&tree_a, TREE_DEPTH, KNOWN_LEAF_COUNT);
    let mixed_tree = partial_tree_with_paths(&tree_a, MIXED_DEPTH, 1);

    let first = add_path_fixture(PartialMerkleTree::new(), &tree_a, TREE_DEPTH, 0, true);
    let new_path =
        add_path_fixture(known_tree.clone(), &tree_a, TREE_DEPTH, KNOWN_LEAF_COUNT, true);
    let existing = add_path_fixture(known_tree.clone(), &tree_a, TREE_DEPTH, 0, true);
    let conflicting = add_path_fixture(known_tree, &tree_b, TREE_DEPTH, KNOWN_LEAF_COUNT, false);
    let mixed_new = add_path_fixture(mixed_tree.clone(), &tree_a, TREE_DEPTH, 0, true);
    let mixed_conflicting = add_path_fixture(mixed_tree, &tree_b, TREE_DEPTH, 0, false);

    let mut group = c.benchmark_group("partial_mt_add_path");
    group.sample_size(100);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));

    bench_add_path_case(&mut group, "first_path_depth10", first);
    bench_add_path_case(&mut group, "new_path_depth10_128_known", new_path);
    bench_add_path_case(&mut group, "existing_path_depth10_128_known", existing);
    bench_add_path_case(&mut group, "conflicting_path_depth10_128_known", conflicting);
    bench_add_path_case(&mut group, "mixed_depth_new_8_to_10", mixed_new);
    bench_add_path_case(&mut group, "mixed_depth_conflict_8_to_10", mixed_conflicting);

    group.finish();
}

// === PartialMerkleTree Construction Benchmarks ===

benchmark_multi!(
    partial_merkle_tree_with_leaves,
    "partial_merkle_tree_with_leaves",
    &[64, 256, 1024, 4096, 8192, 16_384, 65_536],
    |b: &mut Bencher<'_>, &num_leaves: &usize| {
        b.iter_batched(
            || {
                // Generate entries at the same depth (no ancestor relationships)
                let depth = (num_leaves as f64).log2() as u8;
                let entries: Vec<(NodeIndex, Word)> = (0..num_leaves as u64)
                    .map(|i| {
                        let node = NodeIndex::new(depth, i).unwrap();
                        let word = generate_word_pattern(i, WordPattern::MerkleStandard);
                        (node, word)
                    })
                    .collect();
                entries
            },
            |entries| {
                let tree = PartialMerkleTree::with_leaves(hint::black_box(entries)).unwrap();
                hint::black_box(tree);
            },
            BatchSize::SmallInput,
        );
    }
);

// === Benchmark Group Definition ===

criterion_group!(partial_mt_benches, partial_merkle_tree_with_leaves, benchmark_add_path,);

criterion_main!(partial_mt_benches);
