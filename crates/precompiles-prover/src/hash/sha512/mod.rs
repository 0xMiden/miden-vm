//! SHA-512 compression and invocation trace generators.

pub use miden_precompiles_air::hash::sha512::NUM_MAIN_COLS;
#[cfg(test)]
pub use miden_precompiles_air::hash::sha512::Sha512Air;

pub mod compression;
pub mod io;
pub mod trace;
