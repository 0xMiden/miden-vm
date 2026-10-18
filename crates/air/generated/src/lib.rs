#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

/// Production precompile relation; dispatch delegates to authored equations in this version.
pub mod precompile;
/// Generated production VM relation.
pub mod vm;

// Public schema remains source-owned. Explicit production names replace source wildcard names.
pub use miden_air_source::*;
pub use miden_stark::air::MultiAir;
pub use vm::{
    AIRS, Air, Air as MidenAir, MIDEN_AIR_COUNT, MultiAir as MidenMultiAir, PROOF_ORDER_COUNT,
    ProofOrder, PublicInputs,
};

pub mod config;
pub use vm::ace;
