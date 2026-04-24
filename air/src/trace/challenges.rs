//! Unified bus challenge encoding with per-bus domain separation.
//!
//! Provides [`Challenges`], a single struct for encoding multiset/LogUp bus messages
//! as `bus_prefix[bus] + <beta, message>`. Each bus interaction type gets a unique
//! prefix to ensure domain separation.
//!
//! This type is used by:
//!
//! - **AIR constraints** (symbolic expressions): `Challenges<AB::ExprEF>`
//! - **Processor aux trace builders** (concrete field elements): `Challenges<E>`
//! - **Verifier** (`reduced_aux_values`): `Challenges<EF>`
//!
//! See [`super::bus_message`] for the standard coefficient index layout.
//! See [`super::bus_types`] for the bus interaction type constants.

use core::ops::{AddAssign, Mul};

use miden_core::field::PrimeCharacteristicRing;

use super::{MAX_MESSAGE_WIDTH, bus_types::NUM_BUS_TYPES};

/// Encodes multiset/LogUp contributions as **bus_prefix\[bus\] + \<beta, message\>**.
///
/// - `alpha`: randomness base (kept public for direct access by range checker etc.)
/// - `beta_powers`: precomputed powers `[beta^0, beta^1, ..., beta^(MAX_MESSAGE_WIDTH-1)]`
/// - `bus_prefix`: per-bus domain separation constants `bus_prefix[i] = alpha + (i+1) *
///   beta^MAX_MESSAGE_WIDTH`
///
/// The challenges are derived from permutation randomness:
/// - `alpha = challenges[0]`
/// - `beta  = challenges[1]`
///
/// Precomputed once and passed by reference to all bus components.
pub struct Challenges<EF: PrimeCharacteristicRing> {
    pub alpha: EF,
    pub beta_powers: [EF; MAX_MESSAGE_WIDTH],
    /// Per-bus prefix: `bus_prefix[i] = alpha + (i+1) * gamma`
    /// where `gamma = beta^MAX_MESSAGE_WIDTH` and `(i+1)` is the domain separator.
    pub bus_prefix: [EF; NUM_BUS_TYPES],
}

impl<EF: PrimeCharacteristicRing> Challenges<EF> {
    /// Builds `alpha`, precomputed `beta` powers, and per-bus prefixes.
    pub fn new(alpha: EF, beta: EF) -> Self {
        let mut beta_powers = core::array::from_fn(|_| EF::ONE);
        for i in 1..MAX_MESSAGE_WIDTH {
            beta_powers[i] = beta_powers[i - 1].clone() * beta.clone();
        }
        // gamma = beta^MAX_MESSAGE_WIDTH (one power beyond the message range)
        let gamma = beta_powers[MAX_MESSAGE_WIDTH - 1].clone() * beta;
        let bus_prefix =
            core::array::from_fn(|i| alpha.clone() + gamma.clone() * EF::from_u32((i as u32) + 1));
        Self { alpha, beta_powers, bus_prefix }
    }

    /// Encodes as **bus_prefix\[bus\] + sum(beta_powers\[i\] * elem\[i\])** with K consecutive
    /// elements.
    ///
    /// The `bus` parameter is the bus index used for domain separation.
    #[inline(always)]
    pub fn encode<BF, const K: usize>(&self, bus: usize, elems: [BF; K]) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
    {
        const { assert!(K <= MAX_MESSAGE_WIDTH, "Message length exceeds beta_powers capacity") };
        debug_assert!(
            bus < NUM_BUS_TYPES,
            "Bus index {bus} exceeds NUM_BUS_TYPES ({NUM_BUS_TYPES})"
        );
        let mut acc = self.bus_prefix[bus].clone();
        for (i, elem) in elems.into_iter().enumerate() {
            acc += self.beta_powers[i].clone() * elem;
        }
        acc
    }

    /// Encodes as **bus_prefix\[bus\] + sum(beta_powers\[layout\[i\]\] * values\[i\])** using
    /// sparse positions.
    ///
    /// The `bus` parameter is the bus index used for domain separation.
    #[inline(always)]
    pub fn encode_sparse<BF, const K: usize>(
        &self,
        bus: usize,
        layout: [usize; K],
        values: [BF; K],
    ) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
    {
        debug_assert!(
            bus < NUM_BUS_TYPES,
            "Bus index {bus} exceeds NUM_BUS_TYPES ({NUM_BUS_TYPES})"
        );
        let mut acc = self.bus_prefix[bus].clone();
        for (idx, value) in layout.into_iter().zip(values) {
            debug_assert!(
                idx < self.beta_powers.len(),
                "encode_sparse index {} exceeds beta_powers length ({})",
                idx,
                self.beta_powers.len()
            );
            acc += self.beta_powers[idx].clone() * value;
        }
        acc
    }
}
