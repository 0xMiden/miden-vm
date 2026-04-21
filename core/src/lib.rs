#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// ASSERT MATCHES MACRO
// ================================================================================================

/// This is an implementation of `std::assert_matches::assert_matches`
/// so it can be removed when that feature stabilizes upstream
#[macro_export]
macro_rules! assert_matches {
    ($left:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )? $(,)?) => {
        match $left {
            $( $pattern )|+ $( if $guard )? => {}
            ref left_val => {
                panic!(r#"
assertion failed: `(left matches right)`
    left: `{:?}`,
    right: `{}`"#, left_val, stringify!($($pattern)|+ $(if $guard)?));
            }
        }
    };

    ($left:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )?, $msg:literal $(,)?) => {
        match $left {
            $( $pattern )|+ $( if $guard )? => {}
            ref left_val => {
                panic!(concat!(r#"
assertion failed: `(left matches right)`
    left: `{:?}`,
    right: `{}`
"#, $msg), left_val, stringify!($($pattern)|+ $(if $guard)?));
            }
        }
    };

    ($left:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )?, $msg:literal, $($arg:tt)+) => {
        match $left {
            $( $pattern )|+ $( if $guard )? => {}
            ref left_val => {
                panic!(concat!(r#"
assertion failed: `(left matches right)`
    left: `{:?}`,
    right: `{}`
"#, $msg), left_val, stringify!($($pattern)|+ $(if $guard)?), $($arg)+);
            }
        }
    }
}

// EXPORTS
// ================================================================================================

pub use miden_crypto::{EMPTY_WORD, Felt, ONE, Word, ZERO};

/// The number of field elements in a Miden word.
pub const WORD_SIZE: usize = Word::NUM_ELEMENTS;

/// Compatibility wrapper for callers that relied on the old lexicographic word type.
///
/// As of `miden-crypto` 0.24, [`Word`] itself implements the lexicographic ordering semantics.
#[derive(Debug, Clone, Copy)]
pub struct LexicographicWord<T: Into<Word> = Word>(T);

impl<T: Into<Word>> LexicographicWord<T> {
    /// Creates a lexicographically ordered word wrapper.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Returns the wrapped value by reference.
    pub fn inner(&self) -> &T {
        &self.0
    }

    /// Returns the wrapped value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl From<[Felt; WORD_SIZE]> for LexicographicWord {
    fn from(value: [Felt; WORD_SIZE]) -> Self {
        Self(value.into())
    }
}

impl From<Word> for LexicographicWord {
    fn from(value: Word) -> Self {
        Self(value)
    }
}

impl<T: Into<Word>> From<LexicographicWord<T>> for Word {
    fn from(value: LexicographicWord<T>) -> Self {
        value.0.into()
    }
}

impl<T: Into<Word> + Copy> PartialEq for LexicographicWord<T> {
    fn eq(&self, other: &Self) -> bool {
        let self_word: Word = self.0.into();
        let other_word: Word = other.0.into();

        self_word == other_word
    }
}

impl<T: Into<Word> + Copy> Eq for LexicographicWord<T> {}

impl<T: Into<Word> + Copy> PartialOrd for LexicographicWord<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Into<Word> + Copy> Ord for LexicographicWord<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        let self_word: Word = self.0.into();
        let other_word: Word = other.0.into();

        self_word.cmp(&other_word)
    }
}

impl<T: Into<Word> + Copy> miden_crypto::utils::Serializable for LexicographicWord<T> {
    fn write_into<W: miden_crypto::utils::ByteWriter>(&self, target: &mut W) {
        let word: Word = self.0.into();

        miden_crypto::utils::Serializable::write_into(&word, target);
    }

    fn get_size_hint(&self) -> usize {
        let word: Word = self.0.into();

        miden_crypto::utils::Serializable::get_size_hint(&word)
    }
}

impl<T: Into<Word> + From<Word>> miden_crypto::utils::Deserializable for LexicographicWord<T> {
    fn read_from<R: miden_crypto::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_crypto::utils::DeserializationError> {
        let word = <Word as miden_crypto::utils::Deserializable>::read_from(source)?;

        Ok(Self::new(T::from(word)))
    }
}

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

    /// Pretty-print a list of [PrettyPrint] values as comma-separated items.
    pub fn pretty_print_csv<'a, T>(items: impl IntoIterator<Item = &'a T>) -> Document
    where
        T: PrettyPrint + 'a,
    {
        let mut doc = Document::Empty;
        for (i, item) in items.into_iter().enumerate() {
            if i > 0 {
                doc += const_text(", ");
            }
            doc += item.render();
        }
        doc
    }
}

// CONSTANTS
// ================================================================================================

/// The initial value for the frame pointer, corresponding to the start address for procedure
/// locals.
pub const FMP_INIT_VALUE: Felt = Felt::new_unchecked(2_u64.pow(31));

/// The address where the frame pointer is stored in memory.
pub const FMP_ADDR: Felt = Felt::new_unchecked(u32::MAX as u64 - 1_u64);
