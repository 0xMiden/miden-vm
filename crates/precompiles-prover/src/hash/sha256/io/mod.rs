//! Trace construction for SHA-256 padding, chaining, and assertion binding.

#[cfg(test)]
mod testing;
mod trace;

pub use miden_air::precompiles::hash::sha256::io::*;
#[cfg(test)]
pub use testing::{generate_trace, generate_trace_padded_to};
pub use trace::Sha256IoRequires;
pub(crate) use trace::populate_rows;
