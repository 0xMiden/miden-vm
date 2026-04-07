//! SparseMerklePath operation benchmarks.
//!
//! This module benchmarks operations on SparseMerklePath, with a focus on
//! the NonZero construction pattern used in path_depth_iter at line 446.

use std::hint;

use criterion::{Bencher, Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Felt, Word,
    merkle::{
        MerklePath, MerkleTree, NodeIndex,
        smt::{LeafIndex, SimpleSmt},
    },
};

mod common;
use common::{config::*, data::*};

// === SparseMerklePath Construction Benchmarks ===

benchmark_multi!(
    sparse_path_from_sized_iter,
    "sparse_path_from_sized_iter",
    &[8, 12, 16],
    |b: &mut Bencher<'_>, &depth: &usize| {
        b.iter_batched(
            || generate_words_pattern(1usize << depth, WordPattern::Random),
            |leaves| {
                let tree = MerkleTree::new(hint::black_box(leaves)).unwrap();
                let path = tree.get_path(NodeIndex::new(depth as u8, 0).unwrap()).unwrap();
                let _sparse_path = miden_crypto::merkle::SparseMerklePath::from_sized_iter(path);
            },
            criterion::BatchSize::SmallInput,
        );
    }
);

// === NonZero Construction Pattern Benchmarks ===
// Focus on line 446: unsafe { NonZero::new_unchecked(depth) }
// We benchmark iteration which exercises this code path

benchmark_with_setup_data!(
    sparse_path_iteration_full,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "sparse_path_iteration_full",
    || {
        // Create a SparseMerklePath at depth 16
        let leaves = generate_words_pattern(1 << 16, WordPattern::Random);
        let tree = MerkleTree::new(leaves).unwrap();
        let path = tree.get_path(NodeIndex::new(16, 0).unwrap()).unwrap();
        miden_crypto::merkle::SparseMerklePath::from_sized_iter(path).unwrap()
    },
    |b: &mut Bencher<'_>, sparse_path: &miden_crypto::merkle::SparseMerklePath| {
        b.iter(|| {
            let _count: Vec<_> = hint::black_box(sparse_path.iter()).collect();
        });
    }
);

// === Comparison with Regular MerklePath ===

benchmark_with_setup_data!(
    compare_path_iteration,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "compare_path_iteration",
    || {
        let leaves = generate_words_merkle_std(256);
        let tree = MerkleTree::new(&leaves).unwrap();
        let merkle_path = tree.get_path(NodeIndex::new(8, 128).unwrap()).unwrap();
        let sparse_path =
            miden_crypto::merkle::SparseMerklePath::from_sized_iter(merkle_path.clone()).unwrap();
        (merkle_path, sparse_path)
    },
    |b: &mut Bencher<'_>,
     (merkle_path, sparse_path): &(MerklePath, miden_crypto::merkle::SparseMerklePath)| {
        b.iter(|| {
            let merkle_nodes: Vec<_> = hint::black_box(merkle_path.iter()).collect();
            let sparse_nodes: Vec<_> = hint::black_box(sparse_path.iter()).collect();
            // Ensure both iterators produce the same number of nodes
            assert_eq!(merkle_nodes.len(), sparse_nodes.len());
        });
    }
);

// === SparseMerklePath with Empty Nodes ===

benchmark_with_setup_data!(
    sparse_path_with_empty_nodes,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "sparse_path_with_empty_nodes",
    || {
        // Create a SimpleSmt which will have many empty nodes
        let mut tree = SimpleSmt::new().unwrap();
        let mut indices = Vec::new();
        let mut values = Vec::new();

        // Insert a few sparse entries
        for i in [0u64, 100, 500, 1000] {
            let leaf_idx = LeafIndex::new(i).unwrap();
            let value = Word::new([
                Felt::new_unchecked(i),
                Felt::new_unchecked(i),
                Felt::new_unchecked(i),
                Felt::new_unchecked(i),
            ]);
            tree.insert(leaf_idx, value);
            indices.push(i);
            values.push(value);
        }

        (tree, indices, values)
    },
    |b: &mut Bencher<'_>, (tree, indices, values): &(SimpleSmt<10>, Vec<u64>, Vec<Word>)| {
        b.iter(|| {
            for (idx, _val) in indices.iter().zip(values.iter()) {
                let leaf_idx = LeafIndex::new(*idx).unwrap();
                let proof = tree.open(&leaf_idx);
                let _sparse = hint::black_box(
                    miden_crypto::merkle::SparseMerklePath::from_sized_iter(proof.path.into_iter())
                        .unwrap(),
                );
            }
        });
    }
);

// === at_depth Operation Benchmark ===

benchmark_with_setup_data!(
    sparse_path_at_depth,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "sparse_path_at_depth",
    || {
        let leaves = generate_words_merkle_std(256);
        let tree = MerkleTree::new(&leaves).unwrap();
        let path = tree.get_path(NodeIndex::new(8, 128).unwrap()).unwrap();
        let sparse_path = miden_crypto::merkle::SparseMerklePath::from_sized_iter(path).unwrap();
        (sparse_path, 8u8)
    },
    |b: &mut Bencher<'_>, (sparse_path, depth): &(miden_crypto::merkle::SparseMerklePath, u8)| {
        b.iter(|| {
            for d in 1..=*depth {
                let nz = core::num::NonZero::new(d).unwrap();
                let _node = hint::black_box(sparse_path.at_depth(nz).unwrap());
            }
        });
    }
);

// === Conversion Benchmarks ===

benchmark_with_setup_data!(
    merkle_to_sparse_conversion,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "merkle_to_sparse_conversion",
    || {
        let leaves = generate_words_merkle_std(256);
        let tree = MerkleTree::new(&leaves).unwrap();
        tree.get_path(NodeIndex::new(8, 128).unwrap()).unwrap()
    },
    |b: &mut Bencher<'_>, path: &MerklePath| {
        b.iter(|| {
            let _sparse = hint::black_box(
                miden_crypto::merkle::SparseMerklePath::try_from(hint::black_box(path.clone()))
                    .unwrap(),
            );
        });
    }
);

benchmark_with_setup_data!(
    sparse_to_merkle_conversion,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "sparse_to_merkle_conversion",
    || {
        let leaves = generate_words_merkle_std(256);
        let tree = MerkleTree::new(&leaves).unwrap();
        let path = tree.get_path(NodeIndex::new(8, 128).unwrap()).unwrap();
        miden_crypto::merkle::SparseMerklePath::from_sized_iter(path).unwrap()
    },
    |b: &mut Bencher<'_>, sparse_path: &miden_crypto::merkle::SparseMerklePath| {
        b.iter(|| {
            let _merkle: MerklePath = hint::black_box(sparse_path.clone().into());
        });
    }
);

// === Micro-benchmark: NonZero construction pattern comparison ===

fn nonzero_safe_vs_unsafe(c: &mut Criterion) {
    let depths: Vec<u8> = (1u8..=64u8).collect();
    let mut group = c.benchmark_group("nonzero_construction");
    group.measurement_time(DEFAULT_MEASUREMENT_TIME);
    group.sample_size(DEFAULT_SAMPLE_SIZE);

    // Safe construction
    group.bench_function("safe", |b| {
        b.iter(|| {
            for &depth in &depths {
                let _nz = core::num::NonZero::new(depth);
            }
        })
    });

    // Unsafe construction (current code at line 446)
    group.bench_function("unsafe", |b| {
        b.iter(|| {
            for &depth in &depths {
                // SAFETY: In the actual code, depth comes from RangeInclusive<1, _>
                // which guarantees depth >= 1
                let _nz = unsafe { core::num::NonZero::new_unchecked(depth) };
            }
        })
    });

    group.finish();
}

// === Benchmark Group Definition ===

criterion_group!(
    sparse_path_benches,
    sparse_path_from_sized_iter,
    sparse_path_iteration_full,
    compare_path_iteration,
    sparse_path_with_empty_nodes,
    sparse_path_at_depth,
    merkle_to_sparse_conversion,
    sparse_to_merkle_conversion,
    nonzero_safe_vs_unsafe,
);

criterion_main!(sparse_path_benches);
