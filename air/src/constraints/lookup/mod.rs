//! Miden-side wiring for the LogUp lookup-argument module.
//!
//! Holds the Miden-specific pieces: the aggregator [`MidenLookupAir`] + its
//! [`MainLookupAir`](main_air::MainLookupAir) / [`ChipletLookupAir`](chiplet_air::ChipletLookupAir)
//! sub-AIRs, the eight bus emitters in [`buses`], the bus-id constants in [`bus_id`], the
//! [`MidenLookupAuxBuilder`] `AuxBuilder` wrapper, and the Miden-side extension-trait impls
//! pinning the generic [`ConstraintLookupBuilder`](crate::lookup::ConstraintLookupBuilder) /
//! [`ProverLookupBuilder`](crate::lookup::ProverLookupBuilder) adapters to the Miden
//! `LookupBuilder<F = Felt>` trait.
//!
//! The field-polymorphic core (traits, adapters, accumulators, debug walkers) lives in
//! [`crate::lookup`].

#![allow(dead_code, unused_imports)]

pub mod aux_builder;
pub mod bus_id;
pub(crate) mod buses;
pub mod chiplet_air;
#[cfg(any(test, feature = "bus-debug"))]
pub mod debug;
mod extension_impls;
pub mod main_air;
pub mod miden_air;

pub use aux_builder::MidenLookupAuxBuilder;
pub use bus_id::NUM_BUS_IDS;
pub use miden_air::MidenLookupAir;
