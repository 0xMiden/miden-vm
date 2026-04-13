//! Precomputed verifier challenges for the new lookup-argument API.
//!
//! Introduced as part of Amendment A of the lookup-air refactor (see
//! `docs/src/design/lookup_air_plan.md`). This replaces the older
//! `crate::trace::Challenges<EF>` for every code path that goes through
//! the `lookup/` module; `trace::Challenges` stays intact until Task #9
//! because the un-ported `logup*` files still reference it.
//!
//! ## Encoding scheme
//!
//! A bus message is encoded as
//!
//! ```text
//!     encode(bus, v) = bus_prefix[bus] + Σ_{k=0..width} β^k · v[k]
//! ```
//!
//! where `bus_prefix[i] = α + (i + 1) · β^W` and `W = max_message_width`.
//! Each bus's prefix is precomputed once at builder construction and
//! indexed by the coarse bus ID (one of the `BUS_*` constants in
//! [`super::bus_id`]). Messages on the shared chiplet bus carry their
//! operation label at `β⁰` of the payload; buses whose prefix already
//! uniquely identifies them (`BUS_RANGE_CHECK`, `BUS_ACE_WIRING`, …)
//! simply omit the label slot and start the payload at `β⁰`.
//!
//! ## Sizing
//!
//! Both tables are `Box<[EF]>` so the module never pins a compile-time
//! `MAX_MESSAGE_WIDTH` constant. The sizes come from the calling
//! adapter, which reads them out of a [`LookupAir`](super::LookupAir)
//! at builder-construction time. The coarse bus enumeration is captured
//! separately by [`bus_id::NUM_BUS_IDS`](super::bus_id::NUM_BUS_IDS),
//! which Task #6's `MidenLookupAir` will return from `num_bus_ids()`.

use alloc::{boxed::Box, vec::Vec};

use miden_core::field::PrimeCharacteristicRing;

/// Precomputed verifier challenges for the new lookup argument.
///
/// Construct via [`LookupChallenges::new`]. The struct is held by value
/// on the [`ConstraintLookupBuilder`](super::constraint::ConstraintLookupBuilder)
/// (and Task #4's prover-path counterpart); per-column / per-group
/// handles borrow it by shared reference so no extra cloning happens
/// inside the inner loop.
pub struct LookupChallenges<EF> {
    /// `bus_prefix[i] = α + (i + 1) · β^W`, where `W = max_message_width`.
    /// Length = `num_bus_ids`. Indexed by a message's coarse bus ID
    /// (one of the `BUS_*` constants in [`super::bus_id`]).
    pub bus_prefix: Box<[EF]>,

    /// `β⁰, β¹, …, β^(W-1)`. Length = `max_message_width`.
    ///
    /// `β^W` is intentionally **not** stored here — it is the step
    /// between successive [`Self::bus_prefix`] entries and never needs
    /// to be consumed on its own. Bus authors that reach for
    /// `beta_powers()` through
    /// [`EncodedLookupGroup`](super::EncodedLookupGroup) therefore see a
    /// slice that matches the payload width exactly.
    pub beta_powers: Box<[EF]>,
}

impl<EF> LookupChallenges<EF>
where
    EF: PrimeCharacteristicRing + Clone,
{
    /// Build a fresh challenge table.
    ///
    /// - Computes `β⁰, β¹, …, β^(W-1)` into `beta_powers`.
    /// - Uses the next power `β^W` (never exposed) as the per-bus step: `bus_prefix[0] = α + β^W`,
    ///   `bus_prefix[i+1] = bus_prefix[i] + β^W`, matching `bus_prefix[i] = α + (i + 1) · β^W`.
    ///
    /// The caller is responsible for passing `max_message_width` ≥ the
    /// widest payload any message in the AIR emits, and
    /// `num_bus_ids` ≥ the coarse bus count (one of the `BUS_*`
    /// constants plus one). Both sizes come from
    /// [`LookupAir`](super::LookupAir) in practice.
    pub fn new(alpha: EF, beta: EF, max_message_width: usize, num_bus_ids: usize) -> Self {
        // Materialise β⁰ .. β^(W-1). `cur` then advances to β^W, which is
        // reused below as the step between successive bus prefixes but
        // never exposed.
        let mut beta_powers = Vec::with_capacity(max_message_width);
        let mut cur = EF::ONE;
        for _ in 0..max_message_width {
            beta_powers.push(cur.clone());
            cur = cur.clone() * beta.clone();
        }
        // `cur` now holds β^W — the per-bus step.

        // Build bus_prefix[i] = α + (i + 1) · β^W iteratively. The first
        // entry is α + β^W (NOT bare α), matching the vm-constraints
        // convention.
        let mut bus_prefix = Vec::with_capacity(num_bus_ids);
        let mut prefix = alpha + cur.clone();
        for _ in 0..num_bus_ids {
            bus_prefix.push(prefix.clone());
            prefix += cur.clone();
        }

        Self {
            bus_prefix: bus_prefix.into_boxed_slice(),
            beta_powers: beta_powers.into_boxed_slice(),
        }
    }
}
