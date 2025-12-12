#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

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

pub mod chiplets;
pub mod errors;

mod program;
pub use program::{Program, ProgramInfo};

mod kernel;
pub use kernel::Kernel;
pub use miden_crypto::{
    AlgebraicSponge, BasedVectorSpace, BinomialExtensionField, EMPTY_WORD, ExtensionField, Felt,
    Field, ONE, PrimeCharacteristicRing, PrimeField64, WORD_SIZE, Word, ZERO,
    batch_multiplicative_inverse, batch_multiplicative_inverse_general, word::LexicographicWord,
};
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
            blake::{Blake3_160, Blake3_192, Blake3_256, Blake3Digest},
            poseidon2::Poseidon2,
            rpo::Rpo256,
            rpx::Rpx256,
        };
    }

    pub mod random {
        pub use miden_crypto::rand::{RpoRandomCoin, RpxRandomCoin};
    }

    pub mod dsa {
        pub use miden_crypto::dsa::falcon512_rpo;
    }
}

pub type QuadFelt = BinomialExtensionField<Felt, 2>;

pub mod mast;

// pub use math::{
//     ExtensionOf,  StarkField, ToElements,
//     fields::{QuadExtension, f64::BaseElement as Felt},
//     polynom,
// };

pub use lazy_static::lazy_static;

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

mod operations;
pub use operations::{
    AssemblyOp, DebugOptions, Decorator, DecoratorList, Operation, opcode_constants::*,
};

// FIELD ELEMENT CONVERSION
// ================================================================================================

/// Converts a u64 value to a field element with validation.
///
/// # Errors
/// Returns an error if the value is not in the canonical range (i.e., >= field modulus).
pub fn felt_from_u64_checked(value: u64) -> Result<Felt, errors::InputError> {
    // Check against field modulus before conversion to avoid expensive as_int() call
    if value >= Felt::ORDER_U64 {
        return Err(errors::InputError::NotFieldElement(
            value,
            format!("value {} exceeds field modulus {}", value, Felt::ORDER_U64),
        ));
    }

    Ok(Felt::from_u64(value))
}

pub mod stack;
pub use stack::{StackInputs, StackOutputs};

mod event_id;
pub use event_id::EventId;

pub mod sys_events;

mod advice;
pub use advice::map::AdviceMap;

pub mod utils;
