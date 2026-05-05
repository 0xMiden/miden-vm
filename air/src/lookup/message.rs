//! `LookupMessage` trait — the bus-message contract used by the closure-based
//! `LookupAir` / `LookupBuilder` API.
//!
//! Each message owns its full encoding loop against a borrowed
//! [`Challenges`].
//!
//! ## Encoding contract
//!
//! Given a reference to [`Challenges<EF>`](crate::lookup::Challenges), a message produces
//! the denominator
//!
//! ```text
//!     bus_prefix[bus] + Σ_{k=0..width} β^(k+1) · values[k]
//! ```
//!
//! where `bus_prefix[i] = α + (i + 1)` is a pure scalar offset precomputed at builder
//! construction time — no β power is involved. Payloads occupy `β¹..β^W`
//! (`W = MAX_MESSAGE_WIDTH`), leaving the `β⁰ = 1` slot for the scalar bus identifier so
//! distinct `(bus, payload)` tuples cannot collide.
//!
//! The [`Challenges::beta_powers`](crate::lookup::Challenges::beta_powers) table is shifted
//! to match: `beta_powers[k] = β^(k+1)`, so message bodies can keep writing
//! `challenges.beta_powers[k] * values[k]` as if `k` were the payload index.
//!
//! The bus identifier is a `usize` chosen by the caller (typically an enum variant cast
//! to `usize`); it picks out `bus_prefix[bus]` as the additive base.

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
/// Implementors pick a bus identifier, start the accumulator from
/// `challenges.bus_prefix[bus]`, and fold each payload value against
/// `challenges.beta_powers[k]` with straight-line arithmetic.
pub trait LookupMessage<E, EF>: core::fmt::Debug
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Encode this message as a LogUp denominator. See module docs for the encoding contract.
    fn encode(&self, challenges: &Challenges<EF>) -> EF;
}
