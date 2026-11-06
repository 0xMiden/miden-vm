//! Pseudo-random element generation.

mod eidos_coin;
pub use eidos_coin::EidosRandomCoin;

// Test utilities for generating deterministic random data.
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;
