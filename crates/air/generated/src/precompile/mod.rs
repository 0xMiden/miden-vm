//! Production AIR and proof protocol for the precompile VM.
//!
//! The precompile relation continues to evaluate its handwritten AIRs directly. Their
//! definitions and trace schemas live in [`miden_air_source::precompile`]. Production identity
//! pins and security metadata live here; protocol configuration and runtime setup remain here
//! until backend consolidation.

pub use miden_air_source::precompile::{ChipletAir, NUM_CHIPLETS};

pub mod air;
pub mod memory;
pub mod preprocessed;
pub mod protocol;
pub mod security;
pub mod stark_config;

pub use air::ChipletMultiAir;
pub use protocol::PVM_RELATION_DIGEST;
