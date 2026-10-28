//! Simplified hash function benchmarks
//!
//! This module focuses on the two key operations across all hash functions:
//! 1. merge() - 2-to-1 hash merge (single permutation)
//! 2. hash_elements() - Sequential hashing of field elements (especially 100 elements)
//!
//! # Organization
//!
//! The benchmarks are organized by hash algorithm:
//! - Eidos
//! - Blake3 variants (256, 192)
//! - Keccak256
//!
//! Each algorithm has two benchmarks:
//! - `hash_<algo>_merge` - 2-to-1 merge operation
//! - `hash_<algo>_sequential_felt` - Sequential hashing of field elements

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::hash::{
    HasherExt,
    blake::{Blake3_192, Blake3_256},
    eidos::Eidos,
    keccak::Keccak256,
};

// Import common utilities
mod common;
use common::data::{generate_byte_array_random, generate_felt_array_sequential};

// Import config constants
use crate::common::config::HASH_ELEMENT_COUNTS;

// === Eidos Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_eidos_merge, "eidos", |b: &mut criterion::Bencher| {
    let input1 = Eidos::hash(&generate_byte_array_random(32));
    let input2 = Eidos::hash(&generate_byte_array_random(32));
    b.iter(|| Eidos::merge(black_box(&[input1, input2])))
});

// Sequential hashing of Felt elements
benchmark_hash_felt!(
    hash_eidos_sequential_felt,
    "eidos",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Eidos::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// === Blake3 Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_blake3_merge, "blake3_256", |b: &mut criterion::Bencher| {
    let input1 = Blake3_256::hash(&generate_byte_array_random(32));
    let input2 = Blake3_256::hash(&generate_byte_array_random(32));
    let digest_inputs: [<Blake3_256 as HasherExt>::Digest; 2] = [input1, input2];
    b.iter(|| Blake3_256::merge(black_box(&digest_inputs)))
});

// Sequential hashing of Felt elements
benchmark_hash_felt!(
    hash_blake3_sequential_felt,
    "blake3_256",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Blake3_256::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// === Blake3_192 Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_blake3_192_merge, "blake3_192", |b: &mut criterion::Bencher| {
    let input1 = Blake3_192::hash(&generate_byte_array_random(32));
    let input2 = Blake3_192::hash(&generate_byte_array_random(32));
    let digest_inputs: [<Blake3_192 as HasherExt>::Digest; 2] = [input1, input2];
    b.iter(|| Blake3_192::merge(black_box(&digest_inputs)))
});

// Sequential hashing of Felt elements
benchmark_hash_felt!(
    hash_blake3_192_sequential_felt,
    "blake3_192",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Blake3_192::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// === Keccak256 benches ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_keccak_256_merge, "keccak_256", |b: &mut criterion::Bencher| {
    let input1 = Keccak256::hash(&generate_byte_array_random(32));
    let input2 = Keccak256::hash(&generate_byte_array_random(32));
    let digest_inputs: [<Keccak256 as HasherExt>::Digest; 2] = [input1, input2];
    b.iter(|| Keccak256::merge(black_box(&digest_inputs)))
});

// Sequential hashing of Felt elements
benchmark_hash_felt!(
    hash_keccak_256_sequential_felt,
    "keccak_256",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Keccak256::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

criterion_group!(
    hash_benchmark_group,
    // Eidos benchmarks
    hash_eidos_merge,
    hash_eidos_sequential_felt,
    // Blake3 benchmarks
    hash_blake3_merge,
    hash_blake3_sequential_felt,
    // Blake3_192 benchmarks
    hash_blake3_192_merge,
    hash_blake3_192_sequential_felt,
    // Keccak256 benchmarks
    hash_keccak_256_merge,
    hash_keccak_256_sequential_felt,
);

criterion_main!(hash_benchmark_group);
