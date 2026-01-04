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
pub use miden_crypto::{EMPTY_WORD, Felt, ONE, WORD_SIZE, Word, ZERO, word::LexicographicWord};

pub mod field {
    pub use miden_crypto::field::*;

    pub type QuadFelt = BinomialExtensionField<super::Felt, 2>;
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
            poseidon2::Poseidon2,
            rpo::Rpo256,
            rpx::Rpx256,
        };
    }

    pub mod random {
        pub use miden_crypto::rand::{RpoRandomCoin, RpxRandomCoin};
    }

    pub mod dsa {
        pub use miden_crypto::dsa::{ecdsa_k256_keccak, eddsa_25519_sha512, falcon512_rpo};
    }
}

pub mod mast;

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

pub mod stack;
pub use stack::{StackInputs, StackOutputs};

mod event_id;
pub use event_id::{EventId, EventName};

pub mod sys_events;

mod advice;
pub use advice::map::AdviceMap;

pub mod precompile;
pub mod utils;

// Re-export indexing functionality from the new standalone crate
pub use miden_utils_indexing::{
    DenseIdMap, Idx, IndexVec, IndexedVecError, LookupByIdx, newtype_id,
};

// CONSTANTS
// ================================================================================================

/// The initial value for the frame pointer, corresponding to the start address for procedure
/// locals.
pub const FMP_INIT_VALUE: Felt = Felt::new(2_u64.pow(31));

/// The address where the frame pointer is stored in memory.
pub const FMP_ADDR: Felt = Felt::new(u32::MAX as u64 - 1_u64);
