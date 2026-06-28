//! SHA-512 deferred precompile.

use alloc::vec::Vec;

use miden_crypto::hash::sha2::Sha512;

use super::{HashFunction, HashPrecompile};

/// [`HashFunction`] spec for SHA-512: a 512-bit digest carried as 16 u32-packed felts.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha512Hash;

impl HashFunction for Sha512Hash {
    const NAME: &'static str = "sha512";
    const DIGEST_FELTS: usize = 16;

    fn hash(input: &[u8]) -> Vec<u8> {
        <[u8; 64]>::from(Sha512::hash(input)).to_vec()
    }
}

/// The SHA-512 deferred precompile, installed by [`registry`](crate::registry).
pub type Sha512Precompile = HashPrecompile<Sha512Hash>;

#[cfg(test)]
mod tests {
    use super::Sha512Hash;
    use crate::hash::assert_hash_precompile;

    #[test]
    fn suite() {
        assert_hash_precompile::<Sha512Hash>();
    }
}
