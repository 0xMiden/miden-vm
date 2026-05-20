//! AIR traits for the Miden lifted STARK protocol.
//!
//! This crate provides:
//! - [`LiftedAir`]: super-trait for AIR definitions (inherits upstream + adds aux trace support and
//!   periodic column data)
//! - [`LiftedAirBuilder`]: super-trait for constraint builders
//! - [`Instance`]: caller-supplied description of a multi-AIR statement — the AIRs, shared
//!   `air_inputs`, optional `aux_inputs`, the cross-AIR `eval_external`, and a Fiat-Shamir
//!   `observe` hook
//! - [`ProverInstance`]: prover-only companion to [`Instance`] adding per-AIR main traces and an
//!   aux-trace builder
//! - [`validate`]: runtime checks returned as typed [`validate::InstanceError`] from `prove` and
//!   `verify`
//! - [`debug`]: panic-based structural checks for tests / setup ([`debug::assert_airs_valid`],
//!   [`debug::check_builder_shape`], …)

#![no_std]

extern crate alloc;

mod air;
mod builder;
pub mod debug;
mod instance;
mod util;
pub mod validate;

pub use air::{ConstraintDegrees, LiftedAir};
pub use builder::LiftedAirBuilder;
pub use instance::{Instance, ProverInstance, ReductionError};
pub use util::{log2_ceil_u8, log2_strict_u8};
pub use validate::{
    InstanceError, validate_inputs, validate_instance, validate_prover_instance,
    validate_with_heights,
};

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
