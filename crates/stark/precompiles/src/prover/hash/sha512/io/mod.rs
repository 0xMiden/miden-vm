//! Trace construction for SHA-512 padding, chaining, and assertion binding.

#[cfg(test)]
mod testing;
mod trace;

pub use miden_air_definitions::precompiles::hash::sha512::io::*;
#[cfg(test)]
pub use testing::{generate_trace, generate_trace_padded_to};
pub use trace::Sha512IoRequires;
pub(crate) use trace::populate_rows;
