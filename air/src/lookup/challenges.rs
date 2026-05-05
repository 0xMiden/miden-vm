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
//! See [`super::message`] for the standard coefficient index layout.

use alloc::{boxed::Box, vec::Vec};
use core::ops::{AddAssign, Mul};

use miden_core::field::PrimeCharacteristicRing;

/// Encodes multiset/LogUp contributions as **bus_prefix\[bus\] + \<beta, message\>**.
///
/// - `alpha`: randomness base (kept public for direct access by range checker etc.)
/// - `beta_powers`: precomputed powers **shifted by one** so `beta_powers[k] = beta^(k+1)` for `k =
///   0..max_message_width`. The shift reserves the `β⁰ = 1` slot for the bus identifier in
///   [`bus_prefix`](Self::bus_prefix) so payloads never collide with it.
/// - `bus_prefix`: per-bus domain separation constants `bus_prefix[i] = alpha + (i+1)` (a pure
///   scalar offset — no β power involved).
///
/// The challenges are derived from permutation randomness:
/// - `alpha = challenges[0]`
/// - `beta  = challenges[1]`
///
/// Widths (`beta_powers.len()` and `bus_prefix.len()`) come from the [`LookupAir`]'s
/// `max_message_width()` / `num_bus_ids()` at construction time. The struct is built
/// once and read-only thereafter — `Box<[EF]>` over `Vec<EF>` drops the unused
/// capacity word and signals fixed length.
///
/// # Soundness
///
/// Encoding a message as `α + (bus+1) + Σ_k β^(k+1)·payload[k]` is injective as a
/// polynomial map in `(α, β)` over all `(bus, payload)` tuples: `(bus+1)` sits alone at
/// the `β⁰` coefficient (payloads occupy `β¹…β^W`), so any two distinct tuples differ in
/// at least one monomial and the Schwartz–Zippel collision bound applies.
///
/// [`LookupAir`]: crate::lookup::LookupAir
pub struct Challenges<EF: PrimeCharacteristicRing> {
    pub alpha: EF,
    /// Powers `[beta^1, beta^2, ..., beta^max_message_width]` (shifted by one so `β⁰ = 1`
    /// is reserved for the bus identifier).
    pub beta_powers: Box<[EF]>,
    /// Per-bus domain separation: `bus_prefix[i] = alpha + (i+1)`, a scalar offset.
    pub bus_prefix: Box<[EF]>,
}

impl<EF: PrimeCharacteristicRing> Challenges<EF> {
    /// Builds `alpha`, precomputed shifted `beta` powers, and per-bus prefixes sized from
    /// the [`LookupAir`]'s `max_message_width()` / `num_bus_ids()`.
    ///
    /// `beta_powers` holds `max_message_width` entries, with `beta_powers[k] = beta^(k+1)`.
    /// `bus_prefix` holds `num_bus_ids` entries, each the pure scalar `alpha + (i+1)`.
    ///
    /// [`LookupAir`]: crate::lookup::LookupAir
    pub fn new(alpha: EF, beta: EF, max_message_width: usize, num_bus_ids: usize) -> Self {
        assert!(max_message_width > 0, "max_message_width must be non-zero");

        // `beta_powers[k] = beta^(k+1)`. Start the table at β¹ so the `β⁰ = 1` slot is
        // reserved for the scalar bus identifier in `bus_prefix`.
        let mut beta_powers: Vec<EF> = Vec::with_capacity(max_message_width);
        beta_powers.push(beta.clone());
        for i in 1..max_message_width {
            beta_powers.push(beta_powers[i - 1].clone() * beta.clone());
        }
        let beta_powers = beta_powers.into_boxed_slice();

        let bus_prefix: Box<[EF]> =
            (0..num_bus_ids).map(|i| alpha.clone() + EF::from_u32((i as u32) + 1)).collect();

        Self { alpha, beta_powers, bus_prefix }
    }

    /// Encodes as **bus_prefix\[bus\] + sum(beta_powers\[i\] * elem\[i\])** with K consecutive
    /// elements.
    ///
    /// The `bus` parameter selects the bus interaction type for domain separation.
    #[inline(always)]
    pub fn encode<BF, const K: usize>(&self, bus: usize, elems: [BF; K]) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
    {
        debug_assert!(
            K <= self.beta_powers.len(),
            "Message length {K} exceeds beta_powers capacity ({})",
            self.beta_powers.len(),
        );
        debug_assert!(
            bus < self.bus_prefix.len(),
            "Bus index {bus} exceeds bus_prefix length ({})",
            self.bus_prefix.len(),
        );
        let mut acc = self.bus_prefix[bus].clone();
        for (i, elem) in elems.into_iter().enumerate() {
            acc += self.beta_powers[i].clone() * elem;
        }
        acc
    }

    /// Returns **sum(beta_powers\[offset + i\] * elems\[i\])**.
    ///
    /// Unlike [`Self::encode`], this does **not** add a bus prefix — callers compose it
    /// with their own prefix and other contributions when a single message absorbs
    /// multiple slices at different β offsets (e.g. addr at β⁰, payload at β²).
    #[inline(always)]
    pub fn inner_product_at<BF: Clone>(&self, offset: usize, elems: &[BF]) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
    {
        debug_assert!(
            offset + elems.len() <= self.beta_powers.len(),
            "inner_product_at range {}..{} exceeds beta_powers length ({})",
            offset,
            offset + elems.len(),
            self.beta_powers.len(),
        );
        let mut acc = EF::ZERO;
        for (i, elem) in elems.iter().enumerate() {
            acc += self.beta_powers[offset + i].clone() * elem.clone();
        }
        acc
    }

    /// Encodes as **bus_prefix\[bus\] + sum(beta_powers\[layout\[i\]\] * values\[i\])** using
    /// sparse positions.
    ///
    /// The `bus` parameter selects the bus interaction type for domain separation.
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
            bus < self.bus_prefix.len(),
            "Bus index {bus} exceeds bus_prefix length ({})",
            self.bus_prefix.len(),
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
