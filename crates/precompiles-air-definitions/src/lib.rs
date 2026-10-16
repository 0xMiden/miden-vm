#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod air;
pub mod ec;
pub mod fixed;
pub mod geometry;
pub mod hash;
pub mod logup;
pub mod math;
pub mod memory;
pub mod primitives;
pub mod relation;
pub mod relations;
pub mod transcript;
pub mod uint;
pub mod utils;

pub use air::{ChipletAir, ChipletMultiAir, NUM_CHIPLETS};

pub mod policy;

pub mod ace;
