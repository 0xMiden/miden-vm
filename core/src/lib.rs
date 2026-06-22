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
pub mod events;
pub mod mast;
pub mod operations;
pub mod precompile;
pub mod program;
pub mod proof;
pub mod utils;

pub mod field {
    pub use miden_crypto::field::*;

    pub type QuadFelt = BinomialExtensionField<super::Felt, 2>;
}

pub mod serde {
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
            sha2::{Sha256, Sha512},
        };
    }

    pub mod random {
        pub use miden_crypto::rand::RandomCoin;
    }

    pub mod dsa {
        pub use miden_crypto::dsa::{ecdsa_k256_keccak, eddsa_25519_sha512, falcon512_poseidon2};
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
