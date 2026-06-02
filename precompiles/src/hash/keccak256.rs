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

/// The Keccak-256 deferred precompile, installed by [`registry`](crate::registry) and wrapped in
/// MASM under `miden::precompiles::crypto::hashes::keccak256`.
pub type Keccak256Precompile = HashPrecompile<Keccak256Hash>;

#[cfg(test)]
mod tests {
    use super::Keccak256Hash;
    use crate::hash::{HashPrecompile, assert_hash_precompile, masm_const};

    #[test]
    fn suite() {
        assert_hash_precompile::<Keccak256Hash>();
    }

    #[test]
    fn masm_pinned_ids_match_derived_ids() {
        const MASM: &str = include_str!("../../asm/crypto/hashes/keccak256.masm");
        assert_eq!(
            masm_const(MASM, "PRECOMPILE_ID"),
            HashPrecompile::<Keccak256Hash>::id().as_canonical_u64(),
        );
        assert_eq!(
            masm_const(MASM, "DIGEST_TAG_ID"),
            HashPrecompile::<Keccak256Hash>::DIGEST_TAG_ID as u64,
        );
        assert_eq!(
            masm_const(MASM, "EQ_TAG_ID"),
            HashPrecompile::<Keccak256Hash>::EQ_TAG_ID as u64,
        );
    }
}
