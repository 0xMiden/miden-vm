//! PartialMerkleTree construction and operation benchmarks.

use std::hint;

use criterion::{BatchSize, Bencher, Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Word,
    merkle::{NodeIndex, PartialMerkleTree},
};

mod common;
use common::data::{WordPattern, generate_word_pattern};

// === PartialMerkleTree Construction Benchmarks ===

benchmark_multi!(
    partial_merkle_tree_with_leaves,
    "partial_merkle_tree_with_leaves",
    &[64, 256, 1024, 4096, 8192],
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

criterion_group!(partial_mt_benches, partial_merkle_tree_with_leaves,);

criterion_main!(partial_mt_benches);
