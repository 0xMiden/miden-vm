//! SHA-256 compression and invocation trace generators.

pub use miden_precompiles_air::hash::sha256::NUM_MAIN_COLS;
#[cfg(test)]
pub use miden_precompiles_air::hash::sha256::Sha256Air;

pub mod compression;
pub mod io;
pub mod trace;
