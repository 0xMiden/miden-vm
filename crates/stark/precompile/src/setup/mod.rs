//! Concrete STARK setup and runtime estimates for the precompile relation.
//!
//! Accepted identity pins, immutable PCS policy, compiled relation metadata, and the embedded
//! circuit remain owned by `miden-air`. This module constructs and caches the corresponding
//! runtime configurations without recapturing the AIRs.

pub(crate) mod commitments;
pub mod config;
#[cfg(feature = "prover")]
pub mod memory;
#[cfg(any(test, feature = "prover"))]
pub mod preprocessed;
pub mod security;
