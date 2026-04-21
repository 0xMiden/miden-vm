//! Miden-side wiring for the LogUp lookup-argument module.
//!
//! Holds the Miden-specific pieces: the aggregator [`MidenLookupAir`] + its
//! [`MainLookupAir`](main_air::MainLookupAir) / [`ChipletLookupAir`](chiplet_air::ChipletLookupAir)
//! sub-AIRs, the eight bus emitters in [`buses`], the
//! [`MidenLookupAuxBuilder`] `AuxBuilder` wrapper, and the Miden-side extension-trait impls
//! pinning the generic [`ConstraintLookupBuilder`](crate::lookup::ConstraintLookupBuilder) /
//! [`ProverLookupBuilder`](crate::lookup::ProverLookupBuilder) adapters to the Miden
//! `LookupBuilder<F = Felt>` trait.
//!
//! The field-polymorphic core (traits, adapters, accumulators, debug walkers) lives in
//! [`crate::lookup`].

#![allow(dead_code, unused_imports)]

pub mod aux_builder;
pub(crate) mod buses;
pub mod chiplet_air;
mod extension_impls;
pub mod main_air;
pub mod messages;
pub mod miden_air;

pub use aux_builder::MidenLookupAuxBuilder;
pub use messages::{BusId, MIDEN_MAX_MESSAGE_WIDTH};
pub use miden_air::MidenLookupAir;
