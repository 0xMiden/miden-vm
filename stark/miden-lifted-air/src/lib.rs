//! AIR traits for the Miden lifted STARK protocol.
//!
//! This crate provides:
//! - [`LiftedAir`]: super-trait for AIR definitions (inherits upstream + adds aux trace support and
//!   periodic column data)
//! - [`LiftedAirBuilder`]: super-trait for constraint builders
//! - [`MultiAir`]: the circuit — the AIR collection (`airs`) plus `eval_external`,
//!   `build_aux_traces`, `observe`, and the `max_aux_inputs` budget
//! - [`Statement`]: validated per-proof inputs over a `MultiAir` — [`Statement::new`] rejects bad
//!   inputs at construction with a typed [`InstanceError`]
//! - [`ProverStatement`]: validated prover-side companion — a `Statement` plus per-AIR main traces,
//!   trace shape checked by [`ProverStatement::new`]
//! - [`debug`]: panic-based structural checks for tests / setup ([`debug::assert_multi_air_valid`],
//!   [`debug::check_builder_shape`])

#![no_std]

extern crate alloc;

mod air;
mod builder;
pub mod debug;
mod statement;
mod util;

pub use air::{ConstraintDegrees, LiftedAir, MultiAir, ReductionError};
pub use builder::LiftedAirBuilder;
pub use statement::{InstanceError, ProverStatement, Statement};
pub use util::{log2_ceil_u8, log2_strict_u8};

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
