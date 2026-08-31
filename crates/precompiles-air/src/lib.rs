#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod air;
pub mod ec;
pub mod fixed;
pub mod hash;
pub mod logup;
pub mod math;
pub mod preprocessed;
pub mod primitives;
pub mod protocol;
pub mod relations;
pub mod security;
pub mod stark_config;
pub mod transcript;
pub mod uint;
pub mod utils;

pub use air::{ChipletAir, ChipletMultiAir, NUM_CHIPLETS};
pub use protocol::PVM_RELATION_DIGEST;
