//! Data generation utilities for consistent benchmark inputs
//!
//! This module provides generic functions for generating test data
//! across all benchmark modules to ensure reproducible and consistent results.
//!
//! # Word Patterns
//!
//! The module provides several predefined word patterns for different use cases:
//! - `MerkleStandard`: [i, ONE, ONE, i] - common in Merkle tree benchmarks
//! - `Sequential`: [i, i+1, i+2, i+3] - sequential pattern
//! - `SpreadSequential`: [i, i+4, i+8, i+12] - spread sequential
//! - `Random`: using PRNG for more varied data
//!
//! # Usage Pattern
//!
//! ```rust
//! use miden_crypto::{Felt, benches::common::data::*};
//!
//! // Generate test data using generic functions
//! let small_data = generate_byte_array_sequential(100);
//! let medium_data = generate_felt_array_sequential(1000);
//! let random_data = generate_byte_array_random(1024);
//!
//! // Generate words using specific patterns
//! let merkle_words = generate_words_merkle_std(256);
//! let sequential_words = generate_words_pattern(100, WordPattern::Sequential);
//! let mixed_entries = generate_smt_entries_mixed(128); // More realistic distribution
//! ```

use std::iter;

use miden_crypto::{
    Felt, ONE, Word,
    rand::test_utils::{prng_array, rand_value},
};

// === Byte Array Generation ===

/// Generate byte array of specified size with sequential data
pub fn generate_byte_array_sequential(size: usize) -> Vec<u8> {
    (0..size).map(|i| i as u8).collect()
}

/// Generate byte array of specified size with random data
pub fn generate_byte_array_random(size: usize) -> Vec<u8> {
    iter::from_fn(|| Some(rand_value::<u8>())).take(size).collect()
}

// === Field Element Generation ===

/// Generate field element array with sequential values
pub fn generate_felt_array_sequential(size: usize) -> Vec<Felt> {
    (0..size).map(|i| Felt::new_unchecked(i as u64)).collect()
}

/// Generate byte array of specified size with random data
pub fn generate_felt_array_random(size: usize) -> Vec<Felt> {
    iter::from_fn(|| Some(Felt::new_unchecked(rand_value::<u64>())))
        .take(size)
        .collect()
}

// === Word and Value Generation ===

/// Common word patterns for benchmarking
#[derive(Clone, Copy, Debug)]
pub enum WordPattern {
    /// Pattern: [i, ONE, ONE, i] - common in Merkle tree benchmarks
    MerkleStandard,
    /// Pattern: [i, i+1, i+2, i+3] - sequential pattern
    Sequential,
    /// Pattern: [i, i+4, i+8, i+12] - spread sequential
    SpreadSequential,
    /// Pattern using random generation
    Random,
}

/// Generate a Word from seed using PRNG
pub fn generate_word(seed: &mut [u8; 32]) -> Word {
    *seed = prng_array(*seed);
    let nums: [u64; 4] = prng_array(*seed);
    Word::new([
        Felt::new_unchecked(nums[0]),
        Felt::new_unchecked(nums[1]),
        Felt::new_unchecked(nums[2]),
        Felt::new_unchecked(nums[3]),
    ])
}

/// Generate a generic value from seed using PRNG
pub fn generate_value<T: miden_crypto::rand::Randomizable + std::fmt::Debug + Clone>(
    seed: &mut [u8; 32],
) -> T {
    *seed = prng_array(*seed);
    let value: [T; 1] = miden_crypto::rand::test_utils::prng_array(*seed);
    value[0].clone()
}

/// Generate word using specified pattern
pub fn generate_word_pattern(i: u64, pattern: WordPattern) -> Word {
    match pattern {
        WordPattern::MerkleStandard => {
            Word::new([Felt::new_unchecked(i), ONE, ONE, Felt::new_unchecked(i)])
        },
        WordPattern::Sequential => Word::new([
            Felt::new_unchecked(i),
            Felt::new_unchecked(i + 1),
            Felt::new_unchecked(i + 2),
            Felt::new_unchecked(i + 3),
        ]),
        WordPattern::SpreadSequential => Word::new([
            Felt::new_unchecked(i),
            Felt::new_unchecked(i + 4),
            Felt::new_unchecked(i + 8),
            Felt::new_unchecked(i + 12),
        ]),
        WordPattern::Random => {
            let mut seed = [0u8; 32];
            seed[0..8].copy_from_slice(&i.to_le_bytes());
            generate_word(&mut seed)
        },
    }
}

/// Generate vector of words using specified pattern
pub fn generate_words_pattern(count: usize, pattern: WordPattern) -> Vec<Word> {
    (0..count as u64).map(|i| generate_word_pattern(i, pattern)).collect()
}

/// Generate vector of words using the common Merkle standard pattern
pub fn generate_words_merkle_std(count: usize) -> Vec<Word> {
    generate_words_pattern(count, WordPattern::MerkleStandard)
}

/// Prepare key-value entries for SMT benchmarks
pub fn prepare_smt_entries(pair_count: u64, seed: &mut [u8; 32]) -> Vec<(Word, Word)> {
    let entries: Vec<(Word, Word)> = (0..pair_count)
        .map(|i| {
            let count = pair_count as f64;
            let idx = ((i as f64 / count) * (count)) as u64;
            let key = Word::new([
                generate_value(seed),
                ONE,
                Felt::new_unchecked(i),
                Felt::new_unchecked(idx),
            ]);
            let value = generate_word(seed);
            (key, value)
        })
        .collect();
    entries
}

/// Generate test key-value pairs for SMT benchmarks (sequential)
pub fn generate_smt_entries_sequential(count: usize) -> Vec<(Word, Word)> {
    (0..count as u64)
        .map(|i| {
            let key = generate_word_pattern(i, WordPattern::Sequential);
            let value = generate_word_pattern(i + 4, WordPattern::Sequential);
            (key, value)
        })
        .collect()
}

/// Generate test entries for SimpleSmt benchmarks (sequential)
pub fn generate_simple_smt_entries_sequential(count: usize) -> Vec<(u64, Word)> {
    (0..count)
        .map(|i| {
            let key = i as u64;
            let value = generate_word_pattern(i as u64, WordPattern::Sequential);
            (key, value)
        })
        .collect()
}

/// Generate test keys for lookup operations (sequential)
pub fn generate_test_keys_sequential(count: usize) -> Vec<Word> {
    generate_words_pattern(count, WordPattern::Sequential)
}

/// More complex SMT entries using mixed patterns for realistic testing
pub fn generate_smt_entries_mixed(count: usize) -> Vec<(Word, Word)> {
    (0..count as u64)
        .map(|i| {
            // Use different patterns for keys based on index to create more realistic distribution
            let key_pattern = match rand_value::<u8>() % 4 {
                0 => WordPattern::Sequential,
                1 => WordPattern::SpreadSequential,
                2 => WordPattern::MerkleStandard,
                _ => WordPattern::Random,
            };

            // Values use offset sequential pattern
            let value = generate_word_pattern(i + 1000, WordPattern::Sequential);
            let key = generate_word_pattern(i, key_pattern);

            (key, value)
        })
        .collect()
}

/// Generate SMT entries with clustered distribution (more realistic access patterns)
pub fn generate_smt_entries_clustered(count: usize, clusters: usize) -> Vec<(Word, Word)> {
    let cluster_size = count / clusters;
    (0..count as u64)
        .map(|i| {
            let cluster_id = (i as usize / cluster_size) as u64;
            let cluster_offset = i % cluster_size as u64;

            // Keys are clustered around specific base values
            let base = cluster_id * 10000;
            let key = generate_word_pattern(base + cluster_offset, WordPattern::Sequential);
            let value = generate_word_pattern(i, WordPattern::SpreadSequential);

            (key, value)
        })
        .collect()
}
