#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// EXPORTS
// ================================================================================================

pub use miden_crypto::{EMPTY_WORD, Felt, ONE, Word, ZERO};

/// The number of field elements in a Miden word.
pub const WORD_SIZE: usize = Word::NUM_ELEMENTS;

pub mod advice;
pub mod chiplets;
pub mod deferred;
pub mod events;
pub mod mast;
pub mod operations;
pub mod program;
pub mod proof;
pub mod utils;

pub mod field {
    pub use miden_crypto::field::*;

    pub type QuadFelt = BinomialExtensionField<super::Felt, 2>;
}

pub mod serde {
    use alloc::collections::VecDeque;

    pub use miden_crypto::utils::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    };

    /// Reads and validates a serialized length before it is used for allocation.
    pub fn read_bounded_len<R: ByteReader>(
        source: &mut R,
        label: &str,
        min_element_size: usize,
    ) -> Result<usize, DeserializationError> {
        let len = source.read_usize()?;
        validate_bounded_len(source, label, len, min_element_size)?;
        Ok(len)
    }

    /// Validates that a serialized length fits both the reader budget and remaining input.
    pub fn validate_bounded_len<R: ByteReader>(
        source: &R,
        label: &str,
        len: usize,
        min_element_size: usize,
    ) -> Result<(), DeserializationError> {
        let max_len = source.max_alloc(min_element_size);
        if len > max_len {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "{label} count {len} exceeds budget {max_len}"
            )));
        }

        let min_bytes = len.checked_mul(min_element_size).ok_or_else(|| {
            DeserializationError::InvalidValue(alloc::format!(
                "{label} count {len} overflows minimum serialized size {min_element_size}"
            ))
        })?;
        source.check_eor(min_bytes).map_err(|err| match err {
            DeserializationError::UnexpectedEOF => DeserializationError::InvalidValue(
                alloc::format!("{label} count {len} exceeds remaining input"),
            ),
            err => err,
        })
    }

    /// Serializable view over a [`VecDeque`].
    ///
    /// This uses the same wire shape as `Vec<T>`: a length prefix followed by items in iteration
    /// order.
    pub struct SerializableVecDeque<'a, T>(pub &'a VecDeque<T>);

    impl<T: Serializable> Serializable for SerializableVecDeque<'_, T> {
        fn write_into<W: ByteWriter>(&self, target: &mut W) {
            target.write_usize(self.0.len());
            for item in self.0 {
                item.write_into(target);
            }
        }
    }

    /// Reads a [`VecDeque`] encoded by [`SerializableVecDeque`].
    pub fn read_vec_deque<T: Deserializable, R: ByteReader>(
        source: &mut R,
    ) -> Result<VecDeque<T>, DeserializationError> {
        let len = read_bounded_len(source, "VecDeque", T::min_serialized_size())?;
        let mut values = VecDeque::with_capacity(len);
        for _ in 0..len {
            values.push_back(T::read_from(source)?);
        }
        Ok(values)
    }

    #[cfg(test)]
    mod tests {
        use alloc::{collections::VecDeque, vec::Vec};

        use super::{Deserializable, Serializable, SerializableVecDeque, read_vec_deque};

        #[test]
        fn vec_deque_round_trip_uses_vec_shape() {
            let values = VecDeque::from([1u32, 2, 3]);
            let mut bytes = Vec::new();
            SerializableVecDeque(&values).write_into(&mut bytes);

            let restored = read_vec_deque(&mut super::SliceReader::new(&bytes)).unwrap();
            assert_eq!(values, restored);

            let vec = Vec::<u32>::read_from_bytes(&bytes).unwrap();
            assert_eq!(vec, [1, 2, 3]);
        }
    }
}

pub mod crypto {
    pub mod merkle {
        pub use miden_crypto::merkle::{
            EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, MerkleTree, NodeIndex,
            PartialMerkleTree,
            mmr::{Mmr, MmrPeaks},
            smt::{LeafIndex, SMT_DEPTH, SimpleSmt, Smt, SmtProof, SmtProofError},
            store::{MerkleStore, StoreNode},
        };
    }

    pub mod hash {
        pub use miden_crypto::hash::{
            blake::{Blake3_256, Blake3Digest},
            keccak::Keccak256,
            poseidon2::Poseidon2,
            rpo::Rpo256,
            rpx::Rpx256,
            sha2::Sha256,
        };
    }

    pub mod random {
        pub use miden_crypto::rand::RandomCoin;
    }

    pub mod dsa {
        pub use miden_crypto::dsa::{ecdsa_k256_keccak, falcon512_poseidon2};
    }
}

pub mod prettier {
    pub use miden_formatting::{prettier::*, pretty_via_display, pretty_via_to_string};
}

// CONSTANTS
// ================================================================================================

/// The initial value for the frame pointer, corresponding to the start address for procedure
/// locals.
pub const FMP_INIT_VALUE: Felt = Felt::new_unchecked(2_u64.pow(31));

/// The address where the frame pointer is stored in memory.
pub const FMP_ADDR: Felt = Felt::new_unchecked(u32::MAX as u64 - 1_u64);
