//! Bus-message encoding contract for the closure-based lookup API.
//!
//! Each message encodes itself against borrowed [`Challenges`].
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
//! and `W = MAX_MESSAGE_WIDTH`. The `(i + 1) · β^W` term separates bus domains, so
//! payload values can start at `β⁰`.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::lookup::Challenges;

// TRAIT
// ================================================================================================

/// A bus message that encodes itself as a LogUp denominator.
///
/// `E` is the base-field expression type (typically `AB::Expr` on the constraint path and
/// `F` on the prover path); `EF` is the matching extension-field expression type. Implementors
/// start from the selected bus prefix and fold each payload value against
/// `challenges.beta_powers[k]`.
pub trait LookupMessage<E, EF>: core::fmt::Debug
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Encode this message as a LogUp denominator. See module docs for the encoding contract.
    fn encode(&self, challenges: &Challenges<EF>) -> EF;
}
