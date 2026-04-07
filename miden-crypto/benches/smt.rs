//! Comprehensive Sparse Merkle Tree (SMT) operation benchmarks
//!
//! This module benchmarks all public APIs of the SMT implementations
//! with a focus on tree creation, updates, proofs, and mutations.
//!
//! # Organization
//!
//! The benchmarks are organized by:
//! 1. Full SMT benchmarks (Smt struct)
//! 2. Simple SMT benchmarks (SimpleSmt const-generic)
//! 3. SMT subtree construction benchmarks
//! 4. Proof verification benchmarks
//! 5. Mutation computation and application
//! 6. Batch operations
//!
//! # Benchmarking Strategy
//!
//! - Tree creation benchmarks use `benchmark_with_setup_data!` for efficient setup
//! - Multi-size benchmarks use `benchmark_multi!` for scalability testing
//! - Batch operations use `benchmark_batch!` for performance analysis
//!
//! # Adding New SMT Benchmarks
//!
//! To add benchmarks for new SMT operations:
//! 1. Add the operation to the appropriate benchmark group
//! 2. Follow naming conventions: `smt_<struct>_<operation>_<parameter>`
//! 3. Use the appropriate macro for benchmark type
//! 4. Update input size arrays if needed

use std::hint;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Felt, ONE, Word,
    merkle::smt::{LeafIndex, SimpleSmt, Smt, SmtLeaf, SubtreeLeaf, build_subtree_for_bench},
};

mod common;
use common::*;

// === Test Data Generation ===
use crate::{
    config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE},
    data::{
        WordPattern, generate_simple_smt_entries_sequential as generate_simple_smt_entries,
        generate_smt_entries_mixed, generate_smt_entries_sequential as generate_smt_entries,
        generate_test_keys_sequential as generate_test_keys, generate_value, generate_word,
        generate_word_pattern,
    },
};

// === Full Smt Benchmarks ===

// Smt::new() tree creation
benchmark_with_setup! {
    smt_new,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "new",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            // Prevent dead code elimination of tree creation
            hint::black_box(Smt::new());
        })
    },
}

// Smt::with_entries() tree creation with initial data
benchmark_with_setup_data! {
    smt_with_entries,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "with_entries",
    || {
        generate_smt_entries(256)
    },
    |b: &mut criterion::Bencher, entries: &Vec<(Word, Word)>| {
        b.iter(|| {
            // Prevent dead code elimination of tree creation with entries
            hint::black_box(Smt::with_entries(entries.clone()).unwrap());
        })
    },
}

// Smt root computation
benchmark_with_setup_data! {
    smt_root,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "root",
    || {
        let entries: Vec<(Word, Word)> = generate_smt_entries(256);
        Smt::with_entries(entries).unwrap()
    },
    |b: &mut criterion::Bencher, smt: &Smt| {
        b.iter(|| {
            hint::black_box(smt.root());
        })
    },
}

// Smt get_value operations
benchmark_with_setup_data! {
    smt_get_value,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "get_value",
    || {
        let entries = generate_smt_entries(256);
        let keys: Vec<Word> = generate_test_keys(100);
        let smt = Smt::with_entries(entries).unwrap();
        (smt, keys)
    },
    |b: &mut criterion::Bencher, (smt, keys): &(Smt, Vec<Word>)| {
        b.iter(|| {
            for key in keys {
                hint::black_box(smt.get_value(key));
            }
        })
    },
}

// Smt insert operations with multiple input sizes
benchmark_batch! {
    smt_insert,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, insert_count: usize| {
        let entries = generate_smt_entries(256);
        let mut smt = Smt::with_entries(entries).unwrap();
        let new_key = Word::new([Felt::new_unchecked(999), Felt::new_unchecked(1000), Felt::new_unchecked(1001), Felt::new_unchecked(1002)]);
        let new_value = Word::new([Felt::new_unchecked(1003), Felt::new_unchecked(1004), Felt::new_unchecked(1005), Felt::new_unchecked(1006)]);

        b.iter(|| {
            for _ in 0..insert_count {
                smt.insert(new_key, new_value).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// Smt open operations (proof generation)
benchmark_with_setup_data! {
    smt_open,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "open",
    || {
        let entries = generate_smt_entries(256);
        let keys = generate_test_keys(10);
        let smt = Smt::with_entries(entries).unwrap();
        (smt, keys)
    },
    |b: &mut criterion::Bencher, (smt, keys): &(Smt, Vec<Word>)| {
        b.iter(|| {
            for key in keys {
                hint::black_box(smt.open(key));
            }
        })
    },
}

// Smt num_leaves and num_entries accessors
benchmark_with_setup_data! {
    smt_counters,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "counters",
    || {
        let entries = generate_smt_entries(512);
        Smt::with_entries(entries).unwrap()
    },
    |b: &mut criterion::Bencher, smt: &Smt| {
        b.iter(|| {
            hint::black_box(smt.num_leaves());
            hint::black_box(smt.num_entries());
        })
    },
}

// Multi-size Smt tree creation
benchmark_multi! {
    smt_creation_sizes,
    "creation-sizes",
    &[16, 64, 256, 1024, 4096, 65536, 1_048_576],
    |b: &mut criterion::Bencher, num_entries: &usize| {
        b.iter_batched(
            || {
                if *num_entries <= 4096 {
                    generate_smt_entries(*num_entries)
                } else {
                    // Use mixed pattern for larger datasets to be more realistic
                    generate_smt_entries_mixed(*num_entries)
                }
            },
            |entries| {
                Smt::with_entries(hint::black_box(entries)).unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    }
}

// === SimpleSmt Benchmarks ===

// SimpleSmt::new() tree creation
benchmark_with_setup! {
    simple_smt_new,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "new",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            // Prevent dead code elimination of tree creation
            hint::black_box(SimpleSmt::<32>::new().unwrap());
        })
    },
}

// SimpleSmt::with_leaves() tree creation with initial data
benchmark_with_setup_data! {
    simple_smt_with_leaves,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "with_leaves",
    || {
        generate_simple_smt_entries(256)
    },
    |b: &mut criterion::Bencher, entries: &Vec<(u64, Word)>| {
        b.iter(|| {
            // Prevent dead code elimination of tree creation with leaves
            hint::black_box(SimpleSmt::<32>::with_leaves(entries.clone()).unwrap());
        })
    },
}

// SimpleSmt root computation
benchmark_with_setup_data! {
    simple_smt_root,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "root",
    || {
        let entries = generate_simple_smt_entries(256);
        SimpleSmt::<32>::with_leaves(entries).unwrap()
    },
    |b: &mut criterion::Bencher, smt: &SimpleSmt<32>| {
        b.iter(|| {
            hint::black_box(smt.root());
        })
    },
}

// SimpleSmt get_leaf operations
benchmark_with_setup_data! {
    simple_smt_get_leaf,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "get_leaf",
    || {
        let entries = generate_simple_smt_entries(256);
        let indices: Vec<LeafIndex<32>> = (0..100)
            .map(|i| LeafIndex::<32>::new(i).unwrap())
            .collect();
        let smt = SimpleSmt::<32>::with_leaves(entries).unwrap();
        (smt, indices)
    },
    |b: &mut criterion::Bencher, (smt, indices): &(SimpleSmt<32>, Vec<LeafIndex<32>>)| {
        b.iter(|| {
            for index in indices {
                hint::black_box(smt.get_leaf(index));
            }
        })
    },
}

// SimpleSmt insert operations with multiple input sizes
benchmark_batch! {
    simple_smt_insert,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, insert_count: usize| {
        let entries = generate_simple_smt_entries(256);
        let mut smt = SimpleSmt::<32>::with_leaves(entries).unwrap();
        let new_index = LeafIndex::<32>::new(999).unwrap();
        let new_value = Word::new([Felt::new_unchecked(1000), Felt::new_unchecked(1001), Felt::new_unchecked(1002), Felt::new_unchecked(1003)]);

        b.iter(|| {
            for _ in 0..insert_count {
                smt.insert(new_index, new_value);
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// SimpleSmt open operations
benchmark_with_setup_data! {
    simple_smt_open,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "open",
    || {
        let entries = generate_simple_smt_entries(256);
        let indices: Vec<LeafIndex<32>> = (0..10)
            .map(|i| LeafIndex::<32>::new(i).unwrap())
            .collect();
        let smt = SimpleSmt::<32>::with_leaves(entries).unwrap();
        (smt, indices)
    },
    |b: &mut criterion::Bencher, (smt, indices): &(SimpleSmt<32>, Vec<LeafIndex<32>>)| {
        b.iter(|| {
            for index in indices {
                hint::black_box(smt.open(index));
            }
        })
    },
}

// SimpleSmt leaves iteration
benchmark_with_setup_data! {
    simple_smt_leaves,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "leaves",
    || {
        let entries = generate_simple_smt_entries(256);
        SimpleSmt::<32>::with_leaves(entries).unwrap()
    },
    |b: &mut criterion::Bencher, smt: &SimpleSmt<32>| {
        b.iter(|| {
            // Prevent dead code elimination of leaves counting
            hint::black_box(smt.leaves().count());
        })
    },
}

// === Mutation Benchmarks ===

// Smt compute_mutations
benchmark_with_setup_data! {
    smt_compute_mutations,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "compute_mutations",
    || {
        let entries = generate_smt_entries(256);
        let smt = Smt::with_entries(entries).unwrap();
        let new_entries = generate_smt_entries(32);
        (smt, new_entries)
    },
    |b: &mut criterion::Bencher, (smt, new_entries): &(Smt, Vec<(Word, Word)>)| {
        b.iter(|| {
            hint::black_box(smt.compute_mutations(new_entries.clone()).unwrap());
        })
    },
}

// Smt apply_mutations with multiple input sizes
benchmark_batch! {
    smt_apply_mutations,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, mutation_count: usize| {
        let base_entries = generate_smt_entries(256);
        let mut smt = Smt::with_entries(base_entries).unwrap();

        b.iter(|| {
            for _ in 0..mutation_count {
                let new_entries = generate_smt_entries(32);
                let mutations = smt.compute_mutations(new_entries).unwrap();
                smt.apply_mutations(mutations).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// === Batch Operations Benchmarks ===

// Batch Smt updates
benchmark_batch! {
    smt_batch_updates,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, update_count: usize| {
        let entries = generate_smt_entries(256);
        let mut smt = Smt::with_entries(entries).unwrap();
        let update_pairs: Vec<(Word, Word)> = (0..update_count)
            .map(|i| {
                let key = generate_word_pattern((1000 + i) as u64, WordPattern::Sequential);
                let value = generate_word_pattern((1004 + i) as u64, WordPattern::Sequential);
                (key, value)
            })
            .collect();

        b.iter(|| {
            for (key, value) in &update_pairs {
                smt.insert(*key, *value).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// Batch SimpleSmt updates
benchmark_batch! {
    simple_smt_batch_updates,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, update_count: usize| {
        let entries = generate_simple_smt_entries(256);
        let mut smt = SimpleSmt::<32>::with_leaves(entries).unwrap();
        let updates: Vec<(LeafIndex<32>, Word)> = (0..update_count)
            .map(|i| {
                let index = LeafIndex::<32>::new(1000u64 + i as u64).unwrap();
                let value = Word::new([
                    Felt::new_unchecked((1000 + i) as u64),
                    Felt::new_unchecked((1001 + i) as u64),
                    Felt::new_unchecked((1002 + i) as u64),
                    Felt::new_unchecked((1003 + i) as u64),
                ]);
                (index, value)
            })
            .collect();

        b.iter(|| {
            for (index, value) in &updates {
                smt.insert(*index, *value);
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// === SMT Subtree Benchmarks ===

const PAIR_COUNTS: [u64; 5] = [1, 64, 128, 192, 256];

// SMT subtree construction with even distribution
benchmark_multi! {
    smt_subtree_even,
    "subtree8-even",
    &PAIR_COUNTS,
    |b: &mut criterion::Bencher, &pair_count: &u64| {
        let mut seed = [0u8; 32];

        b.iter_batched(
            || {
                let entries: Vec<(Word, Word)> = (0..pair_count)
                    .map(|n| {
                        // A single depth-8 subtree can have a maximum of 255 leaves.
                        let leaf_index = ((n as f64 / pair_count as f64) * 255.0) as u64;
                        let key = Word::new([
                            generate_value(&mut seed),
                            ONE,
                            Felt::new_unchecked(n),
                            Felt::new_unchecked(leaf_index),
                        ]);
                        let value = generate_word(&mut seed);
                        (key, value)
                    })
                    .collect();

                let mut leaves: Vec<_> = entries
                    .iter()
                    .map(|(key, value)| {
                        let leaf = SmtLeaf::new_single(*key, *value);
                        let col = leaf.index().position();
                        let hash = leaf.hash();
                        SubtreeLeaf { col, hash }
                    })
                    .collect();
                leaves.sort();
                leaves.dedup_by_key(|leaf| leaf.col);
                leaves
            },
            |leaves| {
                let (subtree, _) = build_subtree_for_bench(
                    hint::black_box(leaves),
                    hint::black_box(8),  // SMT_DEPTH
                    hint::black_box(8),   // SMT_DEPTH
                );
                assert!(!subtree.is_empty());
            },
            criterion::BatchSize::SmallInput,
        );
    }
}

// SMT subtree construction with random distribution
benchmark_multi! {
    smt_subtree_random,
    "subtree8-rand",
    &PAIR_COUNTS,
    |b: &mut criterion::Bencher, &pair_count: &u64| {
        let mut seed = [0u8; 32];

        b.iter_batched(
            || {
                let entries: Vec<(Word, Word)> = (0..pair_count)
                    .map(|i| {
                        let leaf_index: u8 = generate_value(&mut seed);
                        let key = Word::new([ONE, ONE, Felt::new_unchecked(i), Felt::new_unchecked(leaf_index as u64)]);
                        let value = generate_word(&mut seed);
                        (key, value)
                    })
                    .collect();

                let mut leaves: Vec<_> = entries
                    .iter()
                    .map(|(key, value)| {
                        let leaf = SmtLeaf::new_single(*key, *value);
                        let col = leaf.index().position();
                        let hash = leaf.hash();
                        SubtreeLeaf { col, hash }
                    })
                    .collect();
                leaves.sort();
                leaves.dedup_by_key(|leaf| leaf.col);
                leaves
            },
            |leaves| {
                let (subtree, _) = build_subtree_for_bench(
                    hint::black_box(leaves),
                    hint::black_box(8),  // SMT_DEPTH
                    hint::black_box(8),   // SMT_DEPTH
                );
                assert!(!subtree.is_empty());
            },
            criterion::BatchSize::SmallInput,
        );
    }
}

// === Benchmark Group Configuration ===

criterion_group!(
    smt_benchmark_group,
    // Full Smt benchmarks
    smt_new,
    smt_with_entries,
    smt_root,
    smt_get_value,
    smt_insert,
    smt_open,
    smt_counters,
    smt_creation_sizes,
    // SimpleSmt benchmarks
    simple_smt_new,
    simple_smt_with_leaves,
    simple_smt_root,
    simple_smt_get_leaf,
    simple_smt_insert,
    simple_smt_open,
    simple_smt_leaves,
    // SMT subtree benchmarks
    smt_subtree_even,
    smt_subtree_random,
    // Mutation benchmarks
    smt_compute_mutations,
    smt_apply_mutations,
    // Batch operations
    smt_batch_updates,
    simple_smt_batch_updates,
);

criterion_main!(smt_benchmark_group);
