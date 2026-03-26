#![no_std]

#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod aead;
pub mod dsa;
pub mod ecdh;
pub mod hash;
pub mod ies;
pub mod merkle;
pub mod rand;
pub mod utils;

// RE-EXPORTS
// ================================================================================================
pub use miden_field::{Felt, Word, WordError, word};

pub mod field {
    //! Traits and utilities for working with the Goldilocks finite field (i.e.,
    //! [Felt](super::Felt)).

    pub use miden_field::{
        Algebra, BasedVectorSpace, BinomialExtensionField, BinomiallyExtendable,
        BinomiallyExtendableAlgebra, BoundedPowers, ExtensionField, Field,
        HasTwoAdicBinomialExtension, InjectiveMonomial, Packable, PermutationMonomial, Powers,
        PrimeCharacteristicRing, PrimeField, PrimeField64, QuotientMap, RawDataSerializable,
        TwoAdicField, batch_multiplicative_inverse,
    };

    pub use super::batch_inversion::batch_inversion_allow_zeros;
}

pub mod parallel {
    //! Conditional parallel iteration primitives.
    //!
    //! When the `concurrent` feature is enabled, this module re-exports parallel iterator
    //! traits from `p3-maybe-rayon` backed by rayon. Without `concurrent`, these traits
    //! fall back to sequential iteration.
    pub use p3_maybe_rayon::prelude::*;
}

pub mod stark {
    //! Lifted STARK proving system based on Plonky3.
    //!
    //! Sub-modules from `p3-miden-lifted-stark`:
    //! - [`proof`] — [`proof::StarkProof`], [`proof::StarkDigest`], [`proof::StarkOutput`],
    //!   [`proof::StarkTranscript`]
    //! - [`air`] — AIR traits, builders, symbolic types (includes all of `p3-air`)
    //! - [`fri`] — PCS parameters, DEEP + FRI types
    //! - [`lmcs`] — Lifted Merkle commitment scheme
    //! - [`transcript`] — Fiat-Shamir channels and transcript data
    //! - [`hasher`] — Stateful hasher primitives
    //! - [`prover`] — `prove_single` / `prove_multi`
    //! - [`verifier`] — `verify_single` / `verify_multi`
    //! - [`debug`] — Debug constraint checker for lifted AIRs
    //!
    //! Sub-modules from upstream Plonky3:
    //! - [`challenger`] — Challenge generation (Fiat-Shamir)
    //! - [`dft`] — DFT implementations
    //! - [`matrix`] — Dense matrix types
    //! - [`symmetric`] — Symmetric cryptographic primitives

    // Top-level types from lifted-stark
    pub use p3_miden_lifted_stark::{GenericStarkConfig, StarkConfig};
    // Lifted-stark sub-modules (re-exported as-is)
    pub use p3_miden_lifted_stark::{
        air, debug, fri, hasher, lmcs, proof, prover, transcript, verifier,
    };

    // Upstream Plonky3: challenger
    pub mod challenger {
        pub use p3_challenger::{
            CanFinalizeDigest, CanObserve, DuplexChallenger, FieldChallenger, GrindingChallenger,
            HashChallenger, SerializingChallenger64,
        };
    }

    // Upstream Plonky3: dft
    pub mod dft {
        pub use p3_dft::{NaiveDft, Radix2DitParallel, TwoAdicSubgroupDft};
    }

    // Upstream Plonky3: matrix
    pub mod matrix {
        pub use p3_matrix::{Matrix, dense::RowMajorMatrix};
    }

    // Upstream Plonky3: symmetric
    pub mod symmetric {
        pub use p3_symmetric::{
            CompressionFunctionFromHasher, CryptographicPermutation, PaddingFreeSponge,
            Permutation, SerializingHasher, TruncatedPermutation,
        };
    }
}

// TYPE ALIASES
// ================================================================================================

/// An alias for a key-value map.
///
/// When the `std` feature is enabled, this is an alias for [`std::collections::HashMap`].
/// Otherwise, this is an alias for [`alloc::collections::BTreeMap`].
#[cfg(feature = "std")]
pub type Map<K, V> = std::collections::HashMap<K, V>;

#[cfg(feature = "std")]
pub use std::collections::hash_map::Entry as MapEntry;
#[cfg(feature = "std")]
pub use std::collections::hash_map::IntoIter as MapIntoIter;

/// An alias for a key-value map.
///
/// When the `std` feature is enabled, this is an alias for [`std::collections::HashMap`].
/// Otherwise, this is an alias for [`alloc::collections::BTreeMap`].
#[cfg(not(feature = "std"))]
pub type Map<K, V> = alloc::collections::BTreeMap<K, V>;

#[cfg(not(feature = "std"))]
pub use alloc::collections::btree_map::Entry as MapEntry;
#[cfg(not(feature = "std"))]
pub use alloc::collections::btree_map::IntoIter as MapIntoIter;

/// An alias for a simple set.
///
/// When the `std` feature is enabled, this is an alias for [`std::collections::HashSet`].
/// Otherwise, this is an alias for [`alloc::collections::BTreeSet`].
#[cfg(feature = "std")]
pub type Set<V> = std::collections::HashSet<V>;

/// An alias for a simple set.
///
/// When the `std` feature is enabled, this is an alias for [`std::collections::HashSet`].
/// Otherwise, this is an alias for [`alloc::collections::BTreeSet`].
#[cfg(not(feature = "std"))]
pub type Set<V> = alloc::collections::BTreeSet<V>;

// CONSTANTS
// ================================================================================================

/// Number of field elements in a word.
pub const WORD_SIZE: usize = word::WORD_SIZE_FELTS;

/// Field element representing ZERO in the Miden base filed.
pub const ZERO: Felt = Felt::ZERO;

/// Field element representing ONE in the Miden base filed.
pub const ONE: Felt = Felt::ONE;

/// Array of field elements representing word of ZEROs in the Miden base field.
pub const EMPTY_WORD: Word = Word::new([ZERO; WORD_SIZE]);

// TRAITS
// ================================================================================================

/// Defines how to compute a commitment to an object represented as a sequence of field elements.
pub trait SequentialCommit {
    /// A type of the commitment which must be derivable from [Word].
    type Commitment: From<Word>;

    /// Computes the commitment to the object.
    ///
    /// The default implementation of this function uses Poseidon2 hash function to hash the
    /// sequence of elements returned from [Self::to_elements()].
    fn to_commitment(&self) -> Self::Commitment {
        hash::poseidon2::Poseidon2::hash_elements(&self.to_elements()).into()
    }

    /// Returns a representation of the object as a sequence of fields elements.
    fn to_elements(&self) -> alloc::vec::Vec<Felt>;
}

// BATCH INVERSION
// ================================================================================================

mod batch_inversion {
    use alloc::vec::Vec;

    use p3_maybe_rayon::prelude::*;

    use super::{Felt, ONE, ZERO, field::Field};

    /// Parallel batch inversion using Montgomery's trick, with zeros left unchanged.
    ///
    /// Processes chunks in parallel using rayon, each chunk using Montgomery's trick.
    pub fn batch_inversion_allow_zeros(values: &mut [Felt]) {
        const CHUNK_SIZE: usize = 1024;

        // We need to work with a copy since we're modifying in place
        let input: Vec<Felt> = values.to_vec();

        input.par_chunks(CHUNK_SIZE).zip(values.par_chunks_mut(CHUNK_SIZE)).for_each(
            |(input_chunk, output_chunk)| {
                batch_inversion_helper(input_chunk, output_chunk);
            },
        );
    }

    /// Montgomery's trick for batch inversion, handling zeros.
    fn batch_inversion_helper(values: &[Felt], result: &mut [Felt]) {
        debug_assert_eq!(values.len(), result.len());

        if values.is_empty() {
            return;
        }

        // Forward pass: compute cumulative products, skipping zeros
        let mut last = ONE;
        for (result, &value) in result.iter_mut().zip(values.iter()) {
            *result = last;
            if value != ZERO {
                last *= value;
            }
        }

        // Invert the final cumulative product
        last = last.inverse();

        // Backward pass: compute individual inverses
        for i in (0..values.len()).rev() {
            if values[i] == ZERO {
                result[i] = ZERO;
            } else {
                result[i] *= last;
                last *= values[i];
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_batch_inversion_allow_zeros() {
            let mut column = Vec::from([Felt::new(2), ZERO, Felt::new(4), Felt::new(5)]);
            batch_inversion_allow_zeros(&mut column);

            assert_eq!(column[0], Felt::new(2).inverse());
            assert_eq!(column[1], ZERO);
            assert_eq!(column[2], Felt::new(4).inverse());
            assert_eq!(column[3], Felt::new(5).inverse());
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {

    #[test]
    #[should_panic]
    fn debug_assert_is_checked() {
        // enforce the release checks to always have `RUSTFLAGS="-C debug-assertions"`.
        //
        // some upstream tests are performed with `debug_assert`, and we want to assert its
        // correctness downstream.
        //
        // for reference, check
        // https://github.com/0xMiden/miden-vm/issues/433
        debug_assert!(false);
    }

    #[test]
    #[should_panic]
    #[allow(arithmetic_overflow)]
    fn overflow_panics_for_test() {
        // overflows might be disabled if tests are performed in release mode. these are critical,
        // mandatory checks as overflows might be attack vectors.
        //
        // to enable overflow checks in release mode, ensure `RUSTFLAGS="-C overflow-checks"`
        let a = 1_u64;
        let b = 64;
        assert_ne!(a << b, 0);
    }
}
