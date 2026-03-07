//! Unified bus challenge encoding.
//!
//! Provides [`Challenges`], a single struct for encoding multiset/LogUp bus messages
//! as `alpha + <beta, message>`. This type is used by:
//!
//! - **AIR constraints** (symbolic expressions): `Challenges<AB::ExprEF, N>`
//! - **Processor aux trace builders** (concrete field elements): `Challenges<E, N>`
//! - **Verifier** (`reduced_aux_values`): `Challenges<EF, N>`
//!
//! See [`super::bus_message`] for the standard coefficient index layout.

use core::ops::{AddAssign, Mul};

use miden_core::field::PrimeCharacteristicRing;

/// Encodes multiset/LogUp contributions as **alpha + <beta, message>**.
///
/// - `alpha`: randomness base
/// - `beta_powers`: precomputed powers `[beta^0, beta^1, ..., beta^(N-1)]`
///
/// The challenges are derived from permutation randomness:
/// - `alpha = challenges[0]`
/// - `beta  = challenges[1]`
pub struct Challenges<EF: PrimeCharacteristicRing, const N: usize> {
    pub alpha: EF,
    pub beta_powers: [EF; N],
}

impl<EF: PrimeCharacteristicRing, const N: usize> Challenges<EF, N> {
    /// Builds `alpha` and precomputed `beta` powers.
    pub fn new(alpha: EF, beta: EF) -> Self {
        let mut beta_powers = core::array::from_fn(|_| EF::ONE);
        for i in 1..N {
            beta_powers[i] = beta_powers[i - 1].clone() * beta.clone();
        }
        Self { alpha, beta_powers }
    }

    /// Builds from a raw challenges slice where `[0] = alpha`, `[1] = beta`.
    pub fn from_raw(challenges: &[EF]) -> Self {
        assert!(challenges.len() >= 2, "need at least alpha and beta");
        Self::new(challenges[0].clone(), challenges[1].clone())
    }

    /// Builds from a permutation randomness slice where elements convert into `EF`.
    ///
    /// This is the primary constructor for AIR constraint builders, where randomness
    /// is provided as `&[AB::RandomVar]` and each element converts `Into<AB::ExprEF>`.
    pub fn from_randomness<R: Into<EF> + Copy>(challenges: &[R]) -> Self {
        assert!(challenges.len() >= 2, "need at least alpha and beta challenges");
        Self::new(challenges[0].into(), challenges[1].into())
    }

    /// Encodes as **alpha + sum(beta_powers\[i\] * elem\[i\])** with K consecutive elements.
    #[inline(always)]
    pub fn encode<BF, const K: usize>(&self, elems: [BF; K]) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
        BF: Clone,
    {
        const { assert!(K <= N, "Message length exceeds beta_powers capacity") };
        let mut acc = self.alpha.clone();
        for (i, elem) in elems.iter().enumerate() {
            acc += self.beta_powers[i].clone() * elem.clone();
        }
        acc
    }

    /// Alias for [`Self::encode`] used by AIR constraint builders.
    #[inline(always)]
    pub fn encode_dense<BF, const K: usize>(&self, elems: [BF; K]) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
        BF: Clone,
    {
        self.encode(elems)
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
