//! `LookupMessage` trait — the new bus-message contract used by the
//! closure-based `LookupAir` / `LookupBuilder` API.
//!
//! Task #1 of the lookup-air refactor (see
//! `docs/src/design/lookup_air_plan.md`) introduced the trait in
//! isolation. Task #11's Amendment A rework replaced the "label at β⁰"
//! slot with a precomputed per-bus-prefix table. Amendment B
//! (Task #12) then collapses the three-method `bus_id` / `width` /
//! `write_into` split into a single
//! [`encode`](LookupMessage::encode) method: each message now owns its
//! full encoding loop against a borrowed
//! [`LookupChallenges`](super::LookupChallenges), which removes the
//! adapter scratch buffer chain entirely (see Amendment B §B.2 in the
//! plan).
//!
//! ## Encoding contract
//!
//! Given a reference to [`LookupChallenges<EF>`](super::LookupChallenges),
//! a message produces the denominator
//!
//! ```text
//!     bus_prefix[bus] + Σ_{k=0..width} β^k · values[k]
//! ```
//!
//! where `bus_prefix[i] = α + (i + 1) · β^W` is precomputed at builder
//! construction time and `W` is the `max_message_width` declared by
//! the enclosing [`LookupAir`](super::LookupAir). The per-message loop
//! runs over `β⁰ … β^(width-1)` only. Messages on the shared chiplet
//! bus place their operation label at `β⁰` of the payload; messages on
//! a dedicated bus (range check, ACE wiring, …) whose prefix already
//! identifies them start the payload at `β⁰` directly.
//!
//! The bus identifier is a coarse 9-entry enumeration defined in
//! [`super::bus_id`]. Messages pick their bus ID either from a stored
//! association (e.g. all `HasherMsg` / `MemoryMsg` / `BitwiseMsg`
//! variants route to [`BUS_CHIPLETS`](super::bus_id::BUS_CHIPLETS)) or
//! from a central constant (`BUS_RANGE_CHECK`, `BUS_ACE_WIRING`, …)
//! inside their `encode` body.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use super::LookupChallenges;

// TRAIT
// ================================================================================================

/// A bus message: encodes itself as a LogUp denominator against a
/// borrowed [`LookupChallenges`] table.
///
/// `E` is the base-field expression type (typically `AB::Expr` on the
/// constraint path and `F` on the prover path); `EF` is the matching
/// extension-field expression type (`AB::ExprEF` / `EF` respectively).
/// The [`Algebra<E>`] bound on `EF` lets each message multiply a base-
/// field payload by an `EF`-typed β-power without manually lifting.
///
/// Implementors look up their own bus identifier (a coarse `BUS_*`
/// constant from [`super::bus_id`]), start the accumulator from
/// `challenges.bus_prefix[bus_id as usize].clone()`, and fold each
/// payload value against `challenges.beta_powers[k].clone()` with
/// straight-line arithmetic. Shared-bus messages (all chiplet ops
/// route to [`BUS_CHIPLETS`](super::bus_id::BUS_CHIPLETS)) place their
/// operation label at `β⁰` of the payload; dedicated-bus messages
/// start the payload at `β⁰` directly.
pub trait LookupMessage<E, EF>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Encode this message as a denominator:
    ///
    /// ```text
    ///     bus_prefix[bus_id] + Σ_{k=0..width} β^k · values[k]
    /// ```
    ///
    /// Implementors should
    ///
    /// 1. determine their coarse `bus_id` (a [`super::bus_id`] constant),
    /// 2. clone `challenges.bus_prefix[bus_id as usize]` into the accumulator,
    /// 3. fold each payload value `v[k]` in as `challenges.beta_powers[k].clone() * v[k].clone()`,
    /// 4. return the accumulator.
    ///
    /// # Panics
    ///
    /// May panic if `bus_id as usize >= challenges.bus_prefix.len()`
    /// or if the payload width exceeds `challenges.beta_powers.len()` —
    /// both are contract violations that the enclosing
    /// [`LookupAir`](super::LookupAir) must prevent by declaring a
    /// large enough `num_bus_ids()` / `max_message_width()`.
    fn encode(&self, challenges: &LookupChallenges<EF>) -> EF;
}
