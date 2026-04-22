//! Miden-side wiring for the LogUp lookup-argument module.
//!
//! Holds the Miden-specific pieces: the [`MainLookupAir`](main_air::MainLookupAir) and
//! [`ChipletLookupAir`](chiplet_air::ChipletLookupAir) sub-AIRs, the eight bus emitters in
//! [`buses`], the shared [`emit_miden_boundary`](miden_air::emit_miden_boundary) /
//! [`MIDEN_COLUMN_SHAPE`](miden_air::MIDEN_COLUMN_SHAPE) /
//! [`NUM_LOGUP_COMMITTED_FINALS`](miden_air::NUM_LOGUP_COMMITTED_FINALS) constants, and the
//! Miden-side extension-trait impls pinning the generic
//! [`ConstraintLookupBuilder`](crate::lookup::ConstraintLookupBuilder) /
//! [`ProverLookupBuilder`](crate::lookup::ProverLookupBuilder) adapters to the Miden
//! `LookupBuilder<F = Felt>` trait.
//!
//! The `LookupAir` and `AuxBuilder` trait impls themselves live on
//! [`crate::ProcessorAir`]; the field-polymorphic core (traits, adapters, accumulators,
//! debug walkers) lives in [`crate::lookup`].

pub(crate) mod buses;
pub mod chiplet_air;
mod extension_impls;
pub mod main_air;
pub mod messages;
pub mod miden_air;

pub use messages::{BusId, MIDEN_MAX_MESSAGE_WIDTH};
