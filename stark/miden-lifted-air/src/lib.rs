//! AIR traits for the Miden lifted STARK protocol.
//!
//! This crate provides:
//! - [`LiftedAir`]: Super-trait for AIR definitions (inherits upstream + adds aux trace support and
//!   periodic column data)
//! - [`LiftedAirBuilder`]: Super-trait for constraint builders
//! - [`auxiliary`]: Auxiliary trace types (builder, cross-AIR identity checking).

#![no_std]

extern crate alloc;

mod air;
pub mod auxiliary;
mod builder;
mod util;

pub use air::{AirStructureError, LiftedAir, TracePart};
pub use auxiliary::{AuxBuilder, ReducedAuxValues, ReductionError, VarLenPublicInputs};
pub use builder::LiftedAirBuilder;
pub use util::log2_strict_u8;

mod empty_window;

pub use empty_window::EmptyWindow;
// Re-export upstream p3-air types so downstream crates never need to depend on p3-air
// directly.
pub use p3_air::{
    Air, AirBuilder, AirBuilderWithContext, BaseAir, ExtensionBuilder, FilteredAirBuilder,
    PeriodicAirBuilder, PermutationAirBuilder, RowWindow, WindowAccess,
};

/// Symbolic constraint analysis types from upstream p3-air.
pub mod symbolic {
    pub use p3_air::symbolic::*;
}

/// AIR constraint utility functions from upstream p3-air.
pub mod utils {
    pub use p3_air::utils::*;
}
