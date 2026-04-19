//! Goldilocks + BLAKE3 (32-byte digest) test configuration.

use alloc::vec;

use miden_stateful_hasher::ChainingHasher;
use p3_blake3::Blake3;
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_symmetric::CompressionFunctionFromHasher;

pub use super::{Felt, PackedFelt, QuadFelt};

/// Chaining state / digest width in bytes.
pub const WIDTH: usize = 32;

/// Digest size in bytes.
pub const DIGEST: usize = 32;

/// Chaining sponge over BLAKE3 on serialized field elements (LMCS `StatefulHasher`).
pub type Sponge = ChainingHasher<Blake3>;

/// 2-to-1 compression via BLAKE3.
pub type Compress = CompressionFunctionFromHasher<Blake3, 2, DIGEST>;

/// Fiat-Shamir challenger over serialized field elements.
pub type Challenger = SerializingChallenger64<Felt, HashChallenger<u8, Blake3, DIGEST>>;

/// Sponge + compressor for Merkle construction.
pub fn test_components() -> (Sponge, Compress) {
    (ChainingHasher::new(Blake3), CompressionFunctionFromHasher::new(Blake3))
}

/// Fresh hash challenger (empty initial state).
pub fn test_challenger() -> Challenger {
    SerializingChallenger64::new(HashChallenger::<u8, Blake3, DIGEST>::new(vec![], Blake3))
}

// =============================================================================
// LMCS layer
// =============================================================================

/// LMCS configured with Goldilocks + Blake3.
pub type Lmcs = crate::lmcs::config::LmcsConfig<Felt, u8, Sponge, Compress, WIDTH, DIGEST>;

crate::testing::define_lmcs_test_helpers!();

/// Create a test LMCS instance.
pub fn test_lmcs() -> Lmcs {
    let (sponge, compress) = test_components();
    crate::lmcs::config::LmcsConfig::new(sponge, compress)
}
