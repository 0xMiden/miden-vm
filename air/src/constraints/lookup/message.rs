//! `LookupMessage` trait — the bus-message contract used by the closure-based
//! `LookupAir` / `LookupBuilder` API.
//!
//! Each message owns its full encoding loop against a borrowed
//! [`Challenges`](crate::trace::Challenges).
//!
//! ## Encoding contract
//!
//! Given a reference to [`Challenges<EF>`](crate::trace::Challenges), a message produces
//! the denominator
//!
//! ```text
//!     bus_prefix[bus] + Σ_{k=0..width} β^k · values[k]
//! ```
//!
//! where `bus_prefix[i] = α + (i + 1) · β^W` is precomputed at builder construction time
//! and `W = MAX_MESSAGE_WIDTH`. Messages on the shared chiplet bus place their operation
//! label at `β⁰` of the payload; messages on a dedicated bus (range check, ACE wiring, …)
//! whose prefix already identifies them start the payload at `β⁰` directly.
//!
//! The bus identifier is a coarse 9-entry enumeration defined in
//! [`crate::trace::bus_types`]. The compatibility shim [`super::bus_id`] re-exports the
//! same constants under the legacy `BUS_*` names.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::trace::Challenges;

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
/// Implementors look up their bus identifier (a `BUS_*` constant from [`super::bus_id`] or
/// a [`bus_types`](crate::trace::bus_types) constant), start the accumulator from
/// `challenges.bus_prefix[bus_id]`, and fold each payload value against
/// `challenges.beta_powers[k]` with straight-line arithmetic.
pub trait LookupMessage<E, EF>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Encode this message as a LogUp denominator. See module docs for the encoding contract.
    fn encode(&self, challenges: &Challenges<EF>) -> EF;
}
