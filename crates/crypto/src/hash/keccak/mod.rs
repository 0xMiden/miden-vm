use core::mem::size_of;

use sha3::Digest as Sha3Digest;

use super::{
    Felt, HasherExt,
    digest::{DIGEST256_BYTES, Digest256},
};
use crate::field::BasedVectorSpace;

#[cfg(test)]
mod tests;

// RE-EXPORTS
// ================================================================================================

/// Re-export of the Keccak hasher from Plonky3 for use in the prover config downstream.
pub use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};

// KECCAK256 DIGEST
// ================================================================================================

/// Keccak-256 digest (32 bytes).
///
/// This is a type alias to the generic `Digest256` type.
pub type Keccak256Digest = Digest256;

// KECCAK256 HASHER
// ================================================================================================

/// Keccak256 hash function
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Keccak256;

impl HasherExt for Keccak256 {
    type Digest = Keccak256Digest;

    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = sha3::Keccak256::new();
        for slice in slices {
            hasher.update(slice);
        }
        Keccak256Digest::from(<[u8; DIGEST256_BYTES]>::from(hasher.finalize()))
    }
}

impl Keccak256 {
    /// Keccak256 collision resistance is 128-bits for 32-bytes output.
    pub const COLLISION_RESISTANCE: u32 = 128;

    pub fn hash(bytes: &[u8]) -> Keccak256Digest {
        let mut hasher = sha3::Keccak256::new();
        hasher.update(bytes);
        Keccak256Digest::from(<[u8; DIGEST256_BYTES]>::from(hasher.finalize()))
    }

    pub fn merge(values: &[Keccak256Digest; 2]) -> Keccak256Digest {
        Self::hash(Keccak256Digest::digests_as_bytes(values))
    }

    pub fn merge_many(values: &[Keccak256Digest]) -> Keccak256Digest {
        let data = Keccak256Digest::digests_as_bytes(values);
        let mut hasher = sha3::Keccak256::new();
        hasher.update(data);
        Keccak256Digest::from(<[u8; DIGEST256_BYTES]>::from(hasher.finalize()))
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E>(elements: &[E]) -> Keccak256Digest
    where
        E: BasedVectorSpace<Felt>,
    {
        hash_elements(elements).into()
    }

    /// Hashes an iterator of byte slices.
    #[inline(always)]
    pub fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Keccak256Digest {
        <Self as HasherExt>::hash_iter(slices)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Hash the elements into bytes.
fn hash_elements<E>(elements: &[E]) -> [u8; DIGEST256_BYTES]
where
    E: BasedVectorSpace<Felt>,
{
    // don't leak assumptions from felt and check its actual implementation.
    let digest = {
        const FELT_BYTES: usize = size_of::<u64>();
        const { assert!(FELT_BYTES == 8, "buffer arithmetic assumes 8-byte field elements") };

        let mut hasher = sha3::Keccak256::new();
        // Keccak256 rate: 1600 bits (state) - 512 bits (capacity) = 1088 bits = 136 bytes
        let mut buf = [0_u8; 136];
        let mut buf_offset = 0;

        for elem in elements.iter() {
            for &felt in E::as_basis_coefficients_slice(elem) {
                buf[buf_offset..buf_offset + FELT_BYTES]
                    .copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
                buf_offset += FELT_BYTES;

                if buf_offset == 136 {
                    hasher.update(buf);
                    buf_offset = 0;
                }
            }
        }

        if buf_offset > 0 {
            hasher.update(&buf[..buf_offset]);
        }

        hasher.finalize()
    };
    digest.into()
}
