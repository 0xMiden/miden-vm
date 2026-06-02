//! SHA-512 deferred precompile.

use alloc::vec::Vec;

use miden_crypto::hash::sha2::Sha512;

use super::{HashFunction, HashPrecompile};

/// [`HashFunction`] spec for SHA-512: a 512-bit digest carried as a 16-felt `Chunks(2)` node.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha512Hash;

impl HashFunction for Sha512Hash {
    const NAME: &'static str = "sha512";
    const DIGEST_FELTS: usize = 16;

    fn hash(input: &[u8]) -> Vec<u8> {
        <[u8; 64]>::from(Sha512::hash(input)).to_vec()
    }
}

/// The SHA-512 deferred precompile, installed by [`registry`](crate::registry) and wrapped in MASM
/// under `miden::precompiles::crypto::hashes::sha512`.
pub type Sha512Precompile = HashPrecompile<Sha512Hash>;

#[cfg(test)]
mod tests {
    use super::Sha512Hash;
    use crate::hash::{HashPrecompile, assert_hash_precompile, masm_const};

    #[test]
    fn suite() {
        assert_hash_precompile::<Sha512Hash>();
    }

    #[test]
    fn masm_pinned_ids_match_derived_ids() {
        const MASM: &str = include_str!("../../asm/crypto/hashes/sha512.masm");
        assert_eq!(
            masm_const(MASM, "PRECOMPILE_ID"),
            HashPrecompile::<Sha512Hash>::id().as_canonical_u64(),
        );
        assert_eq!(
            masm_const(MASM, "DIGEST_TAG_ID"),
            HashPrecompile::<Sha512Hash>::DIGEST_TAG_ID as u64,
        );
        assert_eq!(masm_const(MASM, "EQ_TAG_ID"), HashPrecompile::<Sha512Hash>::EQ_TAG_ID as u64,);
    }
}
