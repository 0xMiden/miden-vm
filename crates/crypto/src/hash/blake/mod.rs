use core::mem::size_of;

use super::{
    HasherExt,
    digest::{Digest, Digest192, Digest256},
};
use crate::{Felt, field::BasedVectorSpace};

#[cfg(test)]
mod tests;

// RE-EXPORTS
// ================================================================================================

/// Re-export of the Blake3 hasher from Plonky3 for use in the prover config downstream.
pub use p3_blake3::Blake3 as Blake3Hasher;

// TYPE ALIASES
// ================================================================================================

/// Alias for the generic `Digest` type, for consistency with other hash modules.
pub type Blake3Digest<const N: usize> = Digest<N>;

// BLAKE3 256-BIT OUTPUT
// ================================================================================================

/// 256-bit output blake3 hasher.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Blake3_256;

impl HasherExt for Blake3_256 {
    type Digest = Digest256;

    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = blake3::Hasher::new();
        for slice in slices {
            hasher.update(slice);
        }
        Digest::new(hasher.finalize().into())
    }
}

impl Blake3_256 {
    /// Blake3 collision resistance is 128-bits for 32-bytes output.
    pub const COLLISION_RESISTANCE: u32 = 128;

    pub fn hash(bytes: &[u8]) -> Digest256 {
        Digest::new(blake3::hash(bytes).into())
    }

    pub fn merge(values: &[Digest256; 2]) -> Digest256 {
        Self::hash(Digest::digests_as_bytes(values))
    }

    pub fn merge_many(values: &[Digest256]) -> Digest256 {
        Digest::new(blake3::hash(Digest::digests_as_bytes(values)).into())
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E: BasedVectorSpace<Felt>>(elements: &[E]) -> Digest256 {
        Digest::new(hash_elements(elements))
    }

    /// Hashes an iterator of byte slices.
    #[inline(always)]
    pub fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Digest256 {
        <Self as HasherExt>::hash_iter(slices)
    }
}

// BLAKE3 192-BIT OUTPUT
// ================================================================================================

/// 192-bit output blake3 hasher.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Blake3_192;

impl HasherExt for Blake3_192 {
    type Digest = Digest192;

    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = blake3::Hasher::new();
        for slice in slices {
            hasher.update(slice);
        }
        Digest::new(shrink_array(hasher.finalize().into()))
    }
}

impl Blake3_192 {
    /// Blake3 collision resistance is 96-bits for 24-bytes output.
    pub const COLLISION_RESISTANCE: u32 = 96;

    pub fn hash(bytes: &[u8]) -> Digest192 {
        Digest::new(shrink_array(blake3::hash(bytes).into()))
    }

    // Note: Same as Blake3_256 - these methods replaced trait delegations to remove Winterfell.
    pub fn merge_many(values: &[Digest192]) -> Digest192 {
        let bytes = Digest::digests_as_bytes(values);
        Digest::new(shrink_array(blake3::hash(bytes).into()))
    }

    pub fn merge(values: &[Digest192; 2]) -> Digest192 {
        Self::hash(Digest::digests_as_bytes(values))
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E: BasedVectorSpace<Felt>>(elements: &[E]) -> Digest192 {
        Digest::new(hash_elements(elements))
    }

    /// Hashes an iterator of byte slices.
    #[inline(always)]
    pub fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Digest192 {
        <Self as HasherExt>::hash_iter(slices)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Hash the elements into bytes and shrink the output.
fn hash_elements<const N: usize, E>(elements: &[E]) -> [u8; N]
where
    E: BasedVectorSpace<Felt>,
{
    let digest = {
        const FELT_BYTES: usize = size_of::<u64>();
        const { assert!(FELT_BYTES == 8, "buffer arithmetic assumes 8-byte field elements") };

        let mut hasher = blake3::Hasher::new();
        // BLAKE3 block size: 64 bytes
        let mut buf = [0_u8; 64];
        let mut buf_offset = 0;

        for elem in elements.iter() {
            for &felt in E::as_basis_coefficients_slice(elem) {
                buf[buf_offset..buf_offset + FELT_BYTES]
                    .copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
                buf_offset += FELT_BYTES;

                if buf_offset == 64 {
                    hasher.update(&buf);
                    buf_offset = 0;
                }
            }
        }

        if buf_offset > 0 {
            hasher.update(&buf[..buf_offset]);
        }

        hasher.finalize()
    };

    shrink_array(digest.into())
}

/// Shrinks an array.
///
/// Due to compiler optimizations, this function is zero-copy.
fn shrink_array<const M: usize, const N: usize>(source: [u8; M]) -> [u8; N] {
    const {
        assert!(M >= N, "size of destination should be smaller or equal than source");
    }
    core::array::from_fn(|i| source[i])
}
