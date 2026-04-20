//! `LookupMessage` trait — the bus-message contract used by the closure-based
//! `LookupAir` / `LookupBuilder` API.
//!
//! Each message owns its full encoding loop against a borrowed
//! [`Challenges`](crate::lookup::Challenges).
//!
//! ## Encoding contract
//!
//! Given a reference to [`Challenges<EF>`](crate::lookup::Challenges), a message produces
//! the denominator
//!
//! ```text
//!     bus_prefix[bus] + Σ_{k=0..width} β^k · values[k]
//! ```
//!
//! where `bus_prefix[i] = α + (i + 1) · β^W` is precomputed at builder construction time
//! and `W = MAX_MESSAGE_WIDTH`. Interaction-specific bus prefixes provide domain separation;
//! payloads then begin directly at `β⁰`.
//!
//! The bus identifier is the [`crate::constraints::logup_msg::BusId`] enum — each variant
//! maps to a distinct `bus_prefix[bus as usize]` additive base.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::lookup::Challenges;

// TRAIT
// ================================================================================================

/// A bus message: encodes itself as a LogUp denominator against a borrowed
/// [`Challenges`] table.
///
/// `E` is the base-field expression type (typically `AB::Expr` on the constraint path and
/// `F` on the prover path); `EF` is the matching extension-field expression type
/// (`AB::ExprEF` / `EF` respectively). The [`Algebra<E>`] bound on `EF` lets each message
/// multiply a base-field payload by an `EF`-typed β-power without manually lifting.
///
/// Implementors look up their [`BusId`](crate::constraints::logup_msg::BusId), start the
/// accumulator from `challenges.bus_prefix[bus as usize]`, and fold each payload value
/// against `challenges.beta_powers[k]` with straight-line arithmetic.
pub trait LookupMessage<E, EF>: core::fmt::Debug
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Encode this message as a LogUp denominator. See module docs for the encoding contract.
    fn encode(&self, challenges: &Challenges<EF>) -> EF;
}
