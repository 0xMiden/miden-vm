#[cfg(test)]
mod testing;
mod trace;

pub use miden_air_definitions::precompiles::hash::sha256::compression::*;

#[cfg(test)]
pub use testing::{generate_trace, generate_trace_padded_to};
pub use trace::*;
