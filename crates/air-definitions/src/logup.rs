//! Miden VM-specific LogUp lookup argument: bus identifiers and bus message types.
//!
//! [`crate::MidenAir`] is the single `LiftedAir`/`LookupAir` type for the multi-AIR
//! statement; it dispatches per-trace work to Core, Chiplets, Eidos compression, and
//! byte-pair lookup AIRs.
//! [`crate::MidenMultiAir`] is the `MultiAir` carrying the cross-AIR reduction.
//! The generic LogUp framework lives in [`crate::lookup`].

pub use crate::constraints::lookup::{
    BusId, MIDEN_MAX_MESSAGE_WIDTH, messages::*, miden_air::NUM_LOGUP_COMMITTED_FINALS,
};
