//! Simplified hash function benchmarks
//!
//! This module focuses on the two key operations across all hash functions:
//! 1. merge() - 2-to-1 hash merge (single permutation)
//! 2. hash_elements() - Sequential hashing of field elements (especially 100 elements)
//!
//! # Organization
//!
//! The benchmarks are organized by hash algorithm:
//! - RPO256
//! - RPX256
//! - Poseidon2
//! - Eidos
//! - Blake3 variants (256, 192, 160)
//! - Keccak256
//!
//! Each algorithm has two benchmarks:
//! - `hash_<algo>_merge` - 2-to-1 merge operation
//! - `hash_<algo>_sequential_felt` - Sequential hashing of field elements

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_crypto::hash::{
    HasherExt,
    blake::{Blake3_192, Blake3_256},
    eidos::{Eidos, benchmarks},
    keccak::Keccak256,
    poseidon2::Poseidon2,
    rpo::Rpo256,
    rpx::Rpx256,
};

// Import common utilities
mod common;
use common::data::{generate_byte_array_random, generate_felt_array_sequential};

// Import config constants
use crate::common::config::HASH_ELEMENT_COUNTS;

// === RPO256 Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_rpo256_merge, "rpo256", |b: &mut criterion::Bencher| {
    let input1 = Rpo256::hash(&generate_byte_array_random(32));
    let input2 = Rpo256::hash(&generate_byte_array_random(32));
    b.iter(|| Rpo256::merge(black_box(&[input1, input2])))
});

// Sequential hashing of Felt elements
benchmark_hash_felt!(
    hash_rpo256_sequential_felt,
    "rpo256",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Rpo256::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// === RPX256 Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_rpx256_merge, "rpx256", |b: &mut criterion::Bencher| {
    let input1 = Rpx256::hash(&generate_byte_array_random(32));
    let input2 = Rpx256::hash(&generate_byte_array_random(32));
    b.iter(|| Rpx256::merge(black_box(&[input1, input2])))
});

// Sequential hashing of Felt elements
benchmark_hash_felt!(
    hash_rpx256_sequential_felt,
    "rpx256",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Rpx256::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// === Poseidon2 Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_poseidon2_merge, "poseidon2", |b: &mut criterion::Bencher| {
    let input1 = Poseidon2::hash(&generate_byte_array_random(32));
    let input2 = Poseidon2::hash(&generate_byte_array_random(32));
    b.iter(|| Poseidon2::merge(black_box(&[input1, input2])))
});

// Sequential hashing of Felt elements
benchmark_hash_felt!(
    hash_poseidon2_sequential_felt,
    "poseidon2",
    HASH_ELEMENT_COUNTS,
    |b: &mut criterion::Bencher, count| {
        let elements = generate_felt_array_sequential(count);
        b.iter(|| Poseidon2::hash_elements(black_box(&elements)))
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
);

// === Eidos Hash Benchmarks ===

// 2-to-1 hash merge
benchmark_hash_merge!(hash_eidos_merge, "eidos", |b: &mut criterion::Bencher| {
    let input1 = Eidos::hash(&[1; 32]);
    let input2 = Eidos::hash(&[2; 32]);
    b.iter(|| black_box(Eidos::merge(black_box(&[input1, input2]))))
});

fn hash_eidos_sequential_felt(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash-eidos-sequential-felt");
    for &count in HASH_ELEMENT_COUNTS {
        let elements = generate_felt_array_sequential(count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::new("felt", count), &elements, |b, elements| {
            b.iter(|| black_box(Eidos::hash_elements(black_box(elements))))
        });
    }
    group.finish();
}

fn hash_eidos_arm(c: &mut Criterion) {
    let cv = core::array::from_fn(|i| i as u32 + 1);
    let block = core::array::from_fn(|i| i as u32 + 17);
    let mut raw = c.benchmark_group("hash-eidos-raw");
    raw.bench_function("compress", |b| {
        b.iter(|| black_box(benchmarks::compress_raw(black_box(cv), black_box(block))))
    });
    raw.bench_function("xof", |b| {
        b.iter(|| black_box(benchmarks::compress_raw_xof(black_box(cv), black_box(block))))
    });
    raw.finish();

    let mut bytes = c.benchmark_group("hash-eidos-sequential-bytes");
    for count in [1, 64, 65, 1024, 8192] {
        let input = common::data::generate_byte_array_sequential(count);
        bytes.throughput(Throughput::Bytes(count as u64));
        bytes.bench_with_input(BenchmarkId::new("bytes", count), &input, |b, input| {
            b.iter(|| black_box(Eidos::hash(black_box(input))))
        });
    }
    bytes.finish();

    let cv = core::array::from_fn(|word| {
        core::array::from_fn(|lane| miden_crypto::Felt::from_u32((word * 16 + lane + 1) as u32))
    });
    let block = core::array::from_fn(|word| {
        core::array::from_fn(|lane| miden_crypto::Felt::from_u32((word * 16 + lane + 65) as u32))
    });
    let mut out = cv;
    let mut packed = c.benchmark_group("hash-eidos-packed-felt");
    for count in [1, 2, 4, 8, 16] {
        packed.throughput(Throughput::Elements(count as u64));
        packed.bench_with_input(BenchmarkId::new("active", count), &count, |b, &count| {
            b.iter(|| {
                benchmarks::compress_packed_counted(
                    black_box(&cv),
                    black_box(&block),
                    black_box(&mut out),
                    black_box(count),
                );
                black_box(&out);
            })
        });
    }
    packed.finish();

    let mut pow = c.benchmark_group("hash-eidos-pow");
    for buffer_len in [0, 7] {
        let snapshot = benchmarks::WitnessBatch::new(
            miden_crypto::Word::from([miden_crypto::Felt::from_u32(1); 4]),
            [miden_crypto::Felt::from_u32(2); 8],
            buffer_len,
        );
        for count in [1, 2, 4, 8, 16] {
            pow.throughput(Throughput::Elements(count as u64));
            pow.bench_with_input(
                BenchmarkId::new(format!("buffer-{buffer_len}"), count),
                &count,
                |b, &count| {
                    b.iter(|| {
                        black_box(black_box(&snapshot).check(
                            black_box(1234),
                            black_box(count),
                            black_box(0xff),
                        ))
                    })
                },
            );
        }
    }
    pow.finish();
}

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
    // RPO256 benchmarks
    hash_rpo256_merge,
    hash_rpo256_sequential_felt,
    // RPX256 benchmarks
    hash_rpx256_merge,
    hash_rpx256_sequential_felt,
    // Poseidon2 benchmarks
    hash_poseidon2_merge,
    hash_poseidon2_sequential_felt,
    // Eidos benchmarks
    hash_eidos_merge,
    hash_eidos_sequential_felt,
    hash_eidos_arm,
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
