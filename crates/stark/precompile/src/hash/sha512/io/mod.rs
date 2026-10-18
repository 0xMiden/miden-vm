//! Trace construction for SHA-512 padding, chaining, and assertion binding.

pub use miden_precompiles_air::hash::sha512::io::*;

mod trace;
pub use trace::Sha512IoRequires;
pub(crate) use trace::populate_rows;
#[cfg(test)]
pub use trace::{generate_trace, generate_trace_padded_to};
