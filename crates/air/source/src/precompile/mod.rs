#[cfg(feature = "tooling")]
pub mod ace;
pub mod air;
pub mod ec;
pub mod fixed;
pub mod hash;
pub mod logup;
pub mod math;
pub mod memory;
pub mod primitives;
pub mod relations;
pub mod security;
pub mod stark_config;
pub mod transcript;
pub mod uint;
pub mod utils;

pub use miden_core::deferred::PvmAirVariant;
pub mod proof;

pub use air::{Air as ChipletAir, Air, MultiAir as ChipletMultiAir, MultiAir, NUM_CHIPLETS};

/// Public statement of the precompile relation: its ordered aggregate root.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PublicInputs {
    root: miden_core::Word,
}

impl PublicInputs {
    pub const fn new(root: miden_core::Word) -> Self {
        Self { root }
    }
    pub const fn root(&self) -> miden_core::Word {
        self.root
    }
    pub fn to_air_inputs(&self) -> alloc::vec::Vec<miden_core::Felt> {
        self.root.as_elements().to_vec()
    }
}
