//! Pseudo-random element generation.

use rand::Rng;

use crate::{Felt, Word};

mod eidos_coin;
pub use eidos_coin::EidosRandomCoin;

/// Eidos-based random coin used by Miden.
pub type RandomCoin = EidosRandomCoin;

// Test utilities for generating deterministic random data.
#[cfg(any(test, feature = "testing"))]
pub mod test_utils;

/// Pseudo-random element generator.
///
/// An instance can be used to draw, uniformly at random, base field elements as well as [Word]s.
pub trait FeltRng: Rng {
    /// Draw, uniformly at random, a base field element.
    fn draw_element(&mut self) -> Felt;

    /// Draw, uniformly at random, a [Word].
    fn draw_word(&mut self) -> Word;
}
