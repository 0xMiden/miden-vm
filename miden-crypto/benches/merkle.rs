//! MerkleTree construction and operation benchmarks.
//!
//! This module benchmarks the creation and operations of Merkle trees,
//! including tree construction, path computation, updates, and verification.

use std::hint;

use criterion::{BatchSize, Bencher, Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Word,
    merkle::{MerklePath, MerkleTree, NodeIndex},
};

mod common;
use common::{
    config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE},
    data::{WordPattern, generate_words_merkle_std, generate_words_pattern},
};

// === MerkleTree Construction Benchmarks ===

benchmark_multi!(
    merkle_tree_construction,
    "merkle_tree_construction",
    &[4, 8, 16, 32, 64, 128, 256, 1024, 4096, 16384, 65536],
    |b: &mut Bencher<'_>, &num_leaves: &usize| {
        b.iter_batched(
            || generate_words_pattern(num_leaves, WordPattern::Random),
            |leaves| {
                let tree = MerkleTree::new(hint::black_box(leaves)).unwrap();
                assert_eq!(tree.depth(), num_leaves.ilog2() as u8);
            },
            BatchSize::SmallInput,
        );
    }
);

benchmark_multi!(
    balanced_merkle_even,
    "balanced-merkle-even",
    &[4, 8, 16, 32, 64, 128, 256, 1024, 4096, 16384, 65536],
    |b: &mut Bencher<'_>, num_leaves: &usize| {
        b.iter_batched(
            || {
                let entries = generate_words_merkle_std(*num_leaves);
                assert_eq!(entries.len(), *num_leaves);
                entries
            },
            |leaves| {
                let tree = MerkleTree::new(hint::black_box(leaves)).unwrap();
                assert_eq!(tree.depth(), num_leaves.ilog2() as u8);
            },
            BatchSize::SmallInput,
        );
    }
);

// === MerkleTree Operation Benchmarks ===

benchmark_with_setup_data!(
    merkle_tree_root,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "merkle-tree-root",
    || {
        let entries = generate_words_merkle_std(256);
        MerkleTree::new(&entries).unwrap()
    },
    |b: &mut Bencher<'_>, tree: &MerkleTree| {
        b.iter(|| {
            hint::black_box(tree.root());
        });
    }
);

benchmark_with_setup_data!(
    merkle_tree_get_path,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "merkle-tree-get-path",
    || {
        // Setup
        let leaves = generate_words_merkle_std(256);
        let tree = MerkleTree::new(&leaves).unwrap();
        let index = NodeIndex::new(8, 128).unwrap();
        (tree, index)
    },
    |b: &mut Bencher<'_>, (tree, index): &(MerkleTree, NodeIndex)| {
        b.iter(|| {
            let _path = hint::black_box(tree.get_path(*index)).unwrap();
        })
    },
);

benchmark_batch!(
    merkle_tree_batch_update,
    &[1, 16, 32, 64, 128],
    |b: &mut Bencher<'_>, update_count: usize| {
        let mut tree = MerkleTree::new(generate_words_merkle_std(256)).unwrap();
        let new_leaves: Vec<Word> = generate_words_pattern(update_count, WordPattern::Random);

        b.iter(|| {
            for (i, new_leaf) in new_leaves.iter().enumerate() {
                hint::black_box(tree.update_leaf(i as u64, *new_leaf)).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
);

benchmark_with_setup_data!(
    merkle_tree_leaves,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "merkle-tree-leaves",
    || {
        let entries = generate_words_merkle_std(256);
        MerkleTree::new(&entries).unwrap()
    },
    |b: &mut Bencher<'_>, tree: &MerkleTree| {
        b.iter(|| {
            hint::black_box(tree.leaves().collect::<Vec<_>>());
        });
    }
);

benchmark_with_setup_data!(
    merkle_tree_inner_nodes,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "merkle-tree-inner-nodes",
    || {
        let entries = generate_words_merkle_std(256);
        MerkleTree::new(&entries).unwrap()
    },
    |b: &mut Bencher<'_>, tree: &MerkleTree| {
        b.iter(|| {
            hint::black_box(tree.inner_nodes().collect::<Vec<_>>());
        });
    }
);

// === MerklePath Verification Benchmark ===

benchmark_with_setup_data!(
    merkle_path_verify,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "merkle_path_verify",
    || {
        // Setup
        let leaves = generate_words_merkle_std(256);
        let tree = MerkleTree::new(&leaves).unwrap();
        let leaf_index = 128;
        let node_index = NodeIndex::new(8, leaf_index).unwrap();
        let path = tree.get_path(node_index).unwrap();
        let leaf = leaves[leaf_index as usize];
        let root = tree.root();
        (path, leaf_index, leaf, root)
    },
    |b: &mut Bencher<'_>, (path, index, leaf, root): &(MerklePath, u64, Word, Word)| {
        b.iter(|| {
            let _ = path.verify(*index, hint::black_box(*leaf), hint::black_box(root));
        })
    },
);

// === Benchmark Group Definition ===

criterion_group!(
    merkle_benches,
    merkle_tree_construction,
    balanced_merkle_even,
    merkle_tree_root,
    merkle_tree_get_path,
    merkle_tree_batch_update,
    merkle_tree_leaves,
    merkle_tree_inner_nodes,
    merkle_path_verify,
);

criterion_main!(merkle_benches);
