//! SHA-256 precompile for deferred evaluation.

use alloc::vec::Vec;

use miden_core::program::domain::Sha256PrecompileDomain;
use miden_crypto::hash::{
    eidos::{DomainTag, EidosDomain},
    sha2::Sha256,
};

use super::{HashFunction, HashPrecompile};

/// [`HashFunction`] spec for SHA-256: a 256-bit digest (one 8-felt chunk).
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256Hash;

impl HashFunction for Sha256Hash {
    const NAME: &'static str = "sha256";
    const DOMAIN: DomainTag = Sha256PrecompileDomain::TAG;
    const DIGEST_FELTS: usize = 8;

    fn hash(input: &[u8]) -> Vec<u8> {
        <[u8; 32]>::from(Sha256::hash(input)).to_vec()
    }
}

/// The SHA-256 precompile, installed by [`registry`](crate::registry).
pub type Sha256Precompile = HashPrecompile<Sha256Hash>;

#[cfg(test)]
mod tests {
    use super::Sha256Hash;
    use crate::hash::assert_hash_precompile;

    #[test]
    fn suite() {
        assert_hash_precompile::<Sha256Hash>();
    }
}
