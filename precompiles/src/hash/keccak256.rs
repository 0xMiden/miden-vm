//! Keccak-256 deferred precompile.

use alloc::vec::Vec;

use miden_crypto::hash::keccak::Keccak256;

use super::{HashFunction, HashPrecompile};

/// [`HashFunction`] spec for Keccak-256: a 256-bit digest (one 8-felt chunk).
#[derive(Debug, Default, Clone, Copy)]
pub struct Keccak256Hash;

impl HashFunction for Keccak256Hash {
    const NAME: &'static str = "keccak256";
    const DIGEST_FELTS: usize = 8;

    fn hash(input: &[u8]) -> Vec<u8> {
        <[u8; 32]>::from(Keccak256::hash(input)).to_vec()
    }
}

/// The Keccak-256 deferred precompile, installed by [`registry`](crate::registry).
pub type Keccak256Precompile = HashPrecompile<Keccak256Hash>;

#[cfg(test)]
mod tests {
    use super::Keccak256Hash;
    use crate::hash::assert_hash_precompile;

    #[test]
    fn suite() {
        assert_hash_precompile::<Keccak256Hash>();
    }
}
