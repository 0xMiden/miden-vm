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
pub use miden_crypto::{EMPTY_WORD, ONE, WORD_SIZE, Word, ZERO, word::LexicographicWord};
pub mod crypto {
    pub mod merkle {
        pub use miden_crypto::merkle::{
            EmptySubtreeRoots, InnerNodeInfo, LeafIndex, MerkleError, MerklePath, MerkleStore,
            MerkleTree, Mmr, MmrPeaks, NodeIndex, PartialMerkleTree, SMT_DEPTH, SimpleSmt, Smt,
            SmtProof, SmtProofError, StoreNode,
        };
    }

    pub mod hash {
        pub use miden_crypto::hash::{
            Digest, ElementHasher, Hasher,
            blake::{Blake3_160, Blake3_192, Blake3_256, Blake3Digest},
            rpo::Rpo256,
            rpx::Rpx256,
        };
    }

    pub mod random {
        pub use miden_crypto::rand::{
            RandomCoin, RandomCoinError, RpoRandomCoin, RpxRandomCoin, WinterRandomCoin,
        };
    }

    pub mod dsa {
        pub use miden_crypto::dsa::rpo_falcon512;
    }
}

pub mod mast;

pub use winter_math::{
    ExtensionOf, FieldElement, StarkField, ToElements,
    fields::{QuadExtension, f64::BaseElement as Felt},
    polynom,
};
pub type QuadFelt = QuadExtension<Felt>;

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
    AssemblyOp, DebugOptions, Decorator, DecoratorIterator, DecoratorList, Operation,
    opcode_constants::*,
};

pub mod stack;
pub use stack::{StackInputs, StackOutputs};

pub mod sys_events;

mod advice;
pub use advice::map::AdviceMap;

pub mod utils;
