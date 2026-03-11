//! Unified bus challenge encoding.
//!
//! Provides [`Challenges`], a single struct for encoding multiset/LogUp bus messages
//! as `alpha + <beta, message>`. This type is used by:
//!
//! - **AIR constraints** (symbolic expressions): `Challenges<AB::ExprEF>`
//! - **Processor aux trace builders** (concrete field elements): `Challenges<E>`
//! - **Verifier** (`reduced_aux_values`): `Challenges<EF>`
//!
//! See [`super::bus_message`] for the standard coefficient index layout.

use core::ops::{AddAssign, Mul};

use miden_core::field::PrimeCharacteristicRing;

use super::MAX_MESSAGE_WIDTH;

/// Encodes multiset/LogUp contributions as **alpha + <beta, message>**.
///
/// - `alpha`: randomness base
/// - `beta_powers`: precomputed powers `[beta^0, beta^1, ..., beta^(MAX_MESSAGE_WIDTH-1)]`
///
/// The challenges are derived from permutation randomness:
/// - `alpha = challenges[0]`
/// - `beta  = challenges[1]`
///
/// Precomputed once and passed by reference to all bus components.
pub struct Challenges<EF: PrimeCharacteristicRing> {
    pub alpha: EF,
    pub beta_powers: [EF; MAX_MESSAGE_WIDTH],
}

impl<EF: PrimeCharacteristicRing> Challenges<EF> {
    /// Builds `alpha` and precomputed `beta` powers.
    pub fn new(alpha: EF, beta: EF) -> Self {
        let mut beta_powers = core::array::from_fn(|_| EF::ONE);
        for i in 1..MAX_MESSAGE_WIDTH {
            beta_powers[i] = beta_powers[i - 1].clone() * beta.clone();
        }
        Self { alpha, beta_powers }
    }

    /// Encodes as **alpha + sum(beta_powers\[i\] * elem\[i\])** with K consecutive elements.
    #[inline(always)]
    pub fn encode<BF, const K: usize>(&self, elems: [BF; K]) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
        BF: Clone,
    {
        const { assert!(K <= MAX_MESSAGE_WIDTH, "Message length exceeds beta_powers capacity") };
        let mut acc = self.alpha.clone();
        for (i, elem) in elems.iter().enumerate() {
            acc += self.beta_powers[i].clone() * elem.clone();
        }
        acc
    }

    /// Encodes as **alpha + sum(beta_powers\[layout\[i\]\] * values\[i\])** using sparse positions.
    #[inline(always)]
    pub fn encode_sparse<BF, const K: usize>(&self, layout: [usize; K], values: [BF; K]) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
        BF: Clone,
    {
        let mut acc = self.alpha.clone();
        for i in 0..K {
            let idx = layout[i];
            debug_assert!(
                idx < self.beta_powers.len(),
                "encode_sparse index {} exceeds beta_powers length ({})",
                idx,
                self.beta_powers.len()
            );
            acc += self.beta_powers[idx].clone() * values[i].clone();
        }
        acc
    }
}
