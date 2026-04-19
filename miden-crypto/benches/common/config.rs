//! Benchmark configuration constants and settings
//!
//! This module contains all configuration constants used across benchmark modules
//! to ensure consistency and make it easy to adjust benchmark parameters.

use std::time::Duration;

// === Core Configuration ===
/// Default measurement time for most benchmarks
pub const DEFAULT_MEASUREMENT_TIME: Duration = Duration::from_secs(20);

/// Sample size for statistical significance
pub const DEFAULT_SAMPLE_SIZE: usize = 100;

// === Hash Function Configuration ===
/// Input sizes for hash function testing (in bytes)
pub const HASH_INPUT_SIZES: &[usize] = &[
    1,     // Single byte
    2,     // Very small input
    4,     // Tiny input
    8,     // Small input
    16,    // Small buffer
    32,    // Word size
    64,    // Double word
    128,   // 128 bytes
    256,   // 1KB / 32 Felt elements
    512,   // 512 bytes
    1024,  // 1KB
    2048,  // 2KB
    4096,  // 4KB
    8192,  // 8KB
    16384, // 16KB
];

/// Element counts for sequential hashing tests
/// Focused on the key benchmark size (100 elements) with a few representative sizes
pub const HASH_ELEMENT_COUNTS: &[usize] = &[
    1,    // Single element (minimal case)
    100,  // Primary benchmark target - typical use case
    1000, // Larger scale test
];

/// Input sizes for merge operations (in bytes)
pub const MERGE_INPUT_SIZES: &[usize] = &[
    1,   // Single byte inputs
    2,   // Tiny inputs
    4,   // Small inputs
    8,   // Very small inputs
    16,  // Small inputs
    32,  // Word size
    64,  // Double word
    128, // 128 bytes
    256, // 1KB
    512, // 512 bytes
];

// === Field Operations Configuration ===
/// Field element counts for batch operations
pub const FIELD_BATCH_SIZES: &[usize] = &[
    1,    // Single operation
    10,   // Small batch
    100,  // Medium batch
    1000, // Large batch
];

// === Randomness Configuration ===
/// Output sizes for PRNG testing (in elements)
pub const PRNG_OUTPUT_SIZES: &[usize] = &[
    1,    // Single element
    32,   // Word size
    100,  // Small array
    1000, // Medium array
];

// === Encryption Configuration ===
// Plaintext sizes in bytes
pub const DATA_SIZES: &[usize] = &[16, 64, 256, 1024, 4096, 16384, 65536, 262144];

// Plaintext sizes in field elements
pub const FELT_SIZES: &[usize] = &[
    4,     // 32 bytes equivalent
    16,    // 128 bytes equivalent
    64,    // 512 bytes equivalent
    256,   // 2KB equivalent
    1024,  // 8KB equivalent
    4096,  // 32KB equivalent
    16384, // 128KB equivalent
];
