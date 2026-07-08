//! Miden VM LogUp lookup argument wiring.
//!
//! ## What lives here
//!
//! - [`main_air`]: main-trace lookup columns and their shared row context.
//! - [`chiplet_air`]: chiplet-trace lookup columns and their shared row context.
//! - [`miden_air`]: boundary corrections and committed-final metadata.
//! - [`messages`]: denominator encodings and bus identifiers.
//! - [`buses`]: per-bus emitters used by the main and chiplet lookup AIRs.
//! - [`extension_impls`]: adapter-specific builder hooks for constraint, prover, and debug paths.

pub(crate) mod buses;
pub mod chiplet_air;
mod extension_impls;
pub mod main_air;
pub mod messages;
pub mod miden_air;
pub mod poseidon2_permutation_air;

pub use messages::{BusId, MIDEN_MAX_MESSAGE_WIDTH};
