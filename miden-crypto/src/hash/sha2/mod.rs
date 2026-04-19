//! SHA2 hash function wrappers (SHA-256 and SHA-512).

use core::mem::size_of;

use sha2::Digest as Sha2Digest;

use super::{
    Felt, HasherExt,
    digest::{DIGEST256_BYTES, DIGEST512_BYTES, Digest256, Digest512},
};
use crate::field::BasedVectorSpace;

#[cfg(test)]
mod tests;

// SHA256 DIGEST
// ================================================================================================

/// SHA-256 digest (32 bytes).
///
/// This is a type alias to the generic `Digest256` type.
pub type Sha256Digest = Digest256;

// SHA256 HASHER
// ================================================================================================

/// SHA-256 hash function.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Sha256;

impl HasherExt for Sha256 {
    type Digest = Sha256Digest;

    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = sha2::Sha256::new();
        for slice in slices {
            hasher.update(slice);
        }
        Sha256Digest::from(<[u8; DIGEST256_BYTES]>::from(hasher.finalize()))
    }
}

impl Sha256 {
    /// SHA-256 collision resistance is 128-bits for 32-bytes output.
    pub const COLLISION_RESISTANCE: u32 = 128;

    pub fn hash(bytes: &[u8]) -> Sha256Digest {
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        Sha256Digest::from(<[u8; DIGEST256_BYTES]>::from(hasher.finalize()))
    }

    pub fn merge(values: &[Sha256Digest; 2]) -> Sha256Digest {
        Self::hash(Sha256Digest::digests_as_bytes(values))
    }

    pub fn merge_many(values: &[Sha256Digest]) -> Sha256Digest {
        let data = Sha256Digest::digests_as_bytes(values);
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        Sha256Digest::from(<[u8; DIGEST256_BYTES]>::from(hasher.finalize()))
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E: BasedVectorSpace<Felt>>(elements: &[E]) -> Sha256Digest {
        Sha256Digest::from(hash_elements_256(elements))
    }

    /// Hashes an iterator of byte slices.
    #[inline(always)]
    pub fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Sha256Digest {
        <Self as HasherExt>::hash_iter(slices)
    }
}

// SHA512 DIGEST
// ================================================================================================

/// SHA-512 digest (64 bytes).
///
/// This is a type alias to the generic `Digest512` type.
pub type Sha512Digest = Digest512;

// SHA512 HASHER
// ================================================================================================

/// SHA-512 hash function.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Sha512;

impl HasherExt for Sha512 {
    type Digest = Sha512Digest;

    fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = sha2::Sha512::new();
        for slice in slices {
            hasher.update(slice);
        }
        Sha512Digest::from(<[u8; DIGEST512_BYTES]>::from(hasher.finalize()))
    }
}

impl Sha512 {
    /// Returns a hash of the provided sequence of bytes.
    #[inline(always)]
    pub fn hash(bytes: &[u8]) -> Sha512Digest {
        let mut hasher = sha2::Sha512::new();
        hasher.update(bytes);
        Sha512Digest::from(<[u8; DIGEST512_BYTES]>::from(hasher.finalize()))
    }

    /// Returns a hash of two digests. This method is intended for use in construction of
    /// Merkle trees and verification of Merkle paths.
    #[inline(always)]
    pub fn merge(values: &[Sha512Digest; 2]) -> Sha512Digest {
        Self::hash(Sha512Digest::digests_as_bytes(values))
    }

    /// Returns a hash of the provided digests.
    #[inline(always)]
    pub fn merge_many(values: &[Sha512Digest]) -> Sha512Digest {
        let data = Sha512Digest::digests_as_bytes(values);
        let mut hasher = sha2::Sha512::new();
        hasher.update(data);
        Sha512Digest::from(<[u8; DIGEST512_BYTES]>::from(hasher.finalize()))
    }

    /// Returns a hash of the provided field elements.
    #[inline(always)]
    pub fn hash_elements<E>(elements: &[E]) -> Sha512Digest
    where
        E: BasedVectorSpace<Felt>,
    {
        Sha512Digest::from(hash_elements_512(elements))
    }

    /// Hashes an iterator of byte slices.
    #[inline(always)]
    pub fn hash_iter<'a>(slices: impl Iterator<Item = &'a [u8]>) -> Sha512Digest {
        <Self as HasherExt>::hash_iter(slices)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Hash the elements into bytes for SHA-256.
fn hash_elements_256<E>(elements: &[E]) -> [u8; DIGEST256_BYTES]
where
    E: BasedVectorSpace<Felt>,
{
    let digest = {
        const FELT_BYTES: usize = size_of::<u64>();
        const { assert!(FELT_BYTES == 8, "buffer arithmetic assumes 8-byte field elements") };

        let mut hasher = sha2::Sha256::new();

        for elem in elements.iter() {
            for &felt in E::as_basis_coefficients_slice(elem) {
                let felt_bytes = felt.as_canonical_u64().to_le_bytes();
                hasher.update(felt_bytes);
            }
        }

        hasher.finalize()
    };
    digest.into()
}

/// Hash the elements into bytes for SHA-512.
fn hash_elements_512<E>(elements: &[E]) -> [u8; DIGEST512_BYTES]
where
    E: BasedVectorSpace<Felt>,
{
    let digest = {
        const FELT_BYTES: usize = size_of::<u64>();
        const { assert!(FELT_BYTES == 8, "buffer arithmetic assumes 8-byte field elements") };

        let mut hasher = sha2::Sha512::new();

        for elem in elements.iter() {
            for &felt in E::as_basis_coefficients_slice(elem) {
                let felt_bytes = felt.as_canonical_u64().to_le_bytes();
                hasher.update(felt_bytes);
            }
        }

        hasher.finalize()
    };
    digest.into()
}
