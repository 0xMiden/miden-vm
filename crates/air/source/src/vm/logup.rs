//! Miden VM-specific LogUp lookup argument: bus identifiers and bus message types.
//!
//! [`crate::vm::MidenAir`] is the single `LiftedAir`/`LookupAir` type for the multi-AIR
//! statement; it dispatches per-trace work to Core, Chiplets, Eidos compression, and
//! byte-pair lookup AIRs.
//! [`crate::vm::statement`] supplies the authored cross-AIR reduction and statement binding.
//! The generic LogUp framework lives in [`miden_stark::lookup`].

pub use crate::vm::constraints::lookup::{
    BusId, MIDEN_MAX_MESSAGE_WIDTH, messages::*, miden_air::NUM_LOGUP_COMMITTED_FINALS,
};
