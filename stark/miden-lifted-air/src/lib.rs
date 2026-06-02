//! AIR traits for the Miden lifted STARK protocol.
//!
//! This crate provides:
//! - [`LiftedAir`]: super-trait for AIR definitions (inherits upstream + adds aux trace support and
//!   periodic column data)
//! - [`LiftedAirBuilder`]: super-trait for constraint builders
//! - [`MultiAir`]: trusted statement definition for a multi-AIR proof
//! - [`Statement`]: validated per-proof caller inputs over a `MultiAir`
//! - [`ProverStatement`]: validated proving input — a `Statement` plus per-AIR main witness traces
//! - [`debug`]: panic-based AIR structural checks for tests / setup

#![no_std]

extern crate alloc;

mod air;
mod builder;
pub mod debug;
mod statement;
mod util;

pub use air::{ConstraintDegrees, LiftedAir, MultiAir, ReductionError};
pub use builder::LiftedAirBuilder;
// Re-export upstream p3-air types so downstream crates never need to depend on p3-air
// directly.
pub use p3_air::{
    Air, AirBuilder, AirBuilderWithContext, BaseAir, ExtensionBuilder, FilteredAirBuilder,
    PeriodicAirBuilder, PermutationAirBuilder, RowWindow, WindowAccess,
};
pub use statement::{InstanceError, ProverStatement, Statement};
pub use util::{log2_ceil_u8, log2_strict_u8};

/// Symbolic constraint analysis types from upstream p3-air.
pub mod symbolic {
    pub use p3_air::symbolic::*;
}

/// AIR constraint utility functions from upstream p3-air.
pub mod utils {
    pub use p3_air::utils::*;
}
