//! Comprehensive Word operation benchmarks
//!
//! This module benchmarks all Word operations implemented in the library
//! with a focus on type conversions, serialization, and ordering.
//!
//! # Organization
//!
//! The benchmarks are organized by:
//! 1. Word creation and basic operations
//! 2. Type conversions (bool, u8, u16, u32, u64)
//! 3. Serialization and deserialization
//! 4. Ordering (lexicographic)
//! 5. Batch operations
//!
//! # Adding New Word Benchmarks
//!
//! To add benchmarks for new Word operations:
//! 1. Add the operation to the imports
//! 2. Add parameterized benchmark functions following the naming convention
//! 3. Add to the appropriate benchmark group
//! 4. Update input size arrays in config.rs if needed

use criterion::{Criterion, criterion_group, criterion_main};
// Import Word modules
use miden_crypto::{Felt, Word};

// Import common utilities
mod common;
use common::*;

// Import configuration constants
use crate::config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE, FIELD_BATCH_SIZES};

/// Configuration for Word testing
const TEST_WORDS: [Word; 10] = [
    Word::new([
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ]),
    Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ]),
    Word::new([
        Felt::new_unchecked(0),
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ]),
    Word::new([
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
    ]),
    Word::new([
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(1),
    ]),
    Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(1),
        Felt::new_unchecked(1),
        Felt::new_unchecked(1),
    ]),
    Word::new([
        Felt::new_unchecked(u64::MAX),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ]),
    Word::new([
        Felt::new_unchecked(0),
        Felt::new_unchecked(u64::MAX),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ]),
    Word::new([
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(u64::MAX),
        Felt::new_unchecked(0),
    ]),
    Word::new([
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(u64::MAX),
    ]),
];

// === Word Creation and Basic Operations ===

// Word creation from field elements
benchmark_with_setup_data! {
    word_new,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "new_from_elements",
    || {
        let test_elements: Vec<[Felt; 4]> = (0u64..100)
            .map(|i| {
                [
                    Felt::new_unchecked(i),
                    Felt::new_unchecked(i + 1),
                    Felt::new_unchecked(i + 2),
                    Felt::new_unchecked(i + 3),
                ]
            })
            .collect();
        test_elements
    },
    |b: &mut criterion::Bencher, test_elements: &Vec<[Felt; 4]>| {
        b.iter(|| {
            for elements in test_elements {
                let _word = Word::new(*elements);
            }
        })
    },
}

// Accessing word elements
benchmark_with_setup! {
    word_access_elements,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "as_elements",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            for word in &TEST_WORDS {
                let _elements = word.as_elements();
            }
        })
    },
}

// Accessing word as bytes
benchmark_with_setup! {
    word_access_bytes,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "as_bytes",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            for word in &TEST_WORDS {
                let _bytes = word.as_bytes();
            }
        })
    },
}

// === Type Conversion Benchmarks ===

// Basic type conversions (bool, u8, u16, u32, u64)
benchmark_word_conversions!(
    word_convert_basic,
    &[0u8, 1u8, 2u8, 3u8, 4u8], // Type indices: 0=bool, 1=u8, 2=u16, 3=u32, 4=u64
    &TEST_WORDS
);

// Conversion to u64 array using Into trait
benchmark_with_setup! {
    word_convert_u64,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "from_to_u64",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            for word in &TEST_WORDS {
                let _result: [u64; 4] = (*word).into();
            }
        })
    },
}

// Conversion to Felt array
benchmark_with_setup! {
    word_convert_felt,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "from_to_felt",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            for word in &TEST_WORDS {
                let _result: [Felt; 4] = (*word).into();
            }
        })
    },
}

// Conversion to byte array
benchmark_with_setup! {
    word_convert_bytes,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "from_to_bytes",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            for word in &TEST_WORDS {
                let _result: [u8; 32] = (*word).into();
            }
        })
    },
}

// === Serialization Benchmarks ===

// Hex serialization
benchmark_with_setup! {
    word_to_hex,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "to_hex",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            for word in &TEST_WORDS {
                let _hex = word.to_hex();
            }
        })
    },
}

// Vector conversion
benchmark_with_setup! {
    word_to_vec,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "to_vec",
    || {},
    |b: &mut criterion::Bencher| {
        b.iter(|| {
            for word in &TEST_WORDS {
                let _vec = word.to_vec();
            }
        })
    },
}

// === Ordering Benchmarks ===

// Word ordering comparisons (lexicographic)
benchmark_with_setup_data! {
    word_cmp,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "cmp",
    || {
        TEST_WORDS.to_vec()
    },
    |b: &mut criterion::Bencher, words: &Vec<Word>| {
        b.iter(|| {
            for i in 0..words.len() {
                for j in i..words.len() {
                    let _result = words[i].cmp(&words[j]);
                }
            }
        })
    },
}

// Word equality comparison
benchmark_with_setup_data! {
    word_eq,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "eq",
    || {
        TEST_WORDS.to_vec()
    },
    |b: &mut criterion::Bencher, words: &Vec<Word>| {
        b.iter(|| {
            for i in 0..words.len() {
                for j in 0..words.len() {
                    let _result = words[i] == words[j];
                }
            }
        })
    },
}

// === Batch Operations Benchmarks ===

// Batch processing of words as elements
benchmark_batch! {
    word_batch_elements,
    FIELD_BATCH_SIZES,
    |b: &mut criterion::Bencher, count: usize| {
        let words: Vec<Word> = (0..count)
            .map(|i| {
                Word::new([
                    Felt::new_unchecked(i as u64),
                    Felt::new_unchecked((i + 1) as u64),
                    Felt::new_unchecked((i + 2) as u64),
                    Felt::new_unchecked((i + 3) as u64),
                ])
            })
            .collect();

        b.iter(|| {
            let _elements = Word::words_as_elements(&words);
        })
    },
    |count| Some(criterion::Throughput::Elements(count as u64))
}

// === Benchmark Group Configuration ===

criterion_group!(
    word_benchmark_group,
    // Word creation and basic operations
    word_new,
    word_access_elements,
    word_access_bytes,
    // Type conversion benchmarks (consolidated)
    word_convert_basic,
    word_convert_u64,
    word_convert_felt,
    word_convert_bytes,
    // Serialization benchmarks
    word_to_hex,
    word_to_vec,
    // Ordering benchmarks
    word_cmp,
    word_eq,
    // Batch operations benchmarks
    word_batch_elements,
);

criterion_main!(word_benchmark_group);
