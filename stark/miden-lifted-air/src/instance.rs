//! [`Instance`] and [`ProverInstance`] — the air-side descriptions of a
//! multi-AIR statement.
//!
//! [`Instance`] is the data both prover and verifier consume: the AIRs in
//! this proof (in instance order, via [`Instance::airs`]), the shared
//! `air_inputs`, optional `aux_inputs` consumed only by `eval_external`,
//! the cross-AIR `eval_external` check, and a Fiat-Shamir `observe` hook.
//!
//! [`ProverInstance`] is the prover-only companion that contains an
//! [`Instance`] and adds per-AIR main traces plus a `build_aux_traces` hook.
//!
//! Ordering is not part of either trait's surface: every list is in
//! **instance order** (the position returned by [`Instance::airs`]), and the
//! stark crate derives the proof's wire-format AIR ordering internally (via
//! `TraceOrder`).

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};

use p3_challenger::CanObserve;
use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

use crate::LiftedAir;

/// Boxed error returned by [`Instance::eval_external`].
///
/// Each `Instance` impl defines its own concrete error type and boxes it
/// into this alias.
pub type ReductionError = Box<dyn core::error::Error + Send + Sync>;

/// Description of a multi-AIR statement.
///
/// A single `Instance` impl is passed to both the prover and the verifier.
/// It carries:
///
/// - [`Self::airs`]: the AIRs in this proof, in instance order. Heterogeneous AIRs are expressed
///   via caller-defined enum wrappers (see `miden-bench`'s `LiftedBenchAir`).
/// - [`Self::air_inputs`]: the public values seen by every AIR. Each AIR's
///   [`num_public_values`](crate::BaseAir::num_public_values) must equal `air_inputs().len()`.
/// - [`Self::aux_inputs`]: extra public data consumed only by [`Self::eval_external`].
/// - [`Self::eval_external`]: cross-AIR external assertions (bus protocols, multiset equalities,
///   …). The default emits no assertions and refuses to be called with non-empty
///   [`Self::aux_inputs`].
/// - [`Self::observe`]: Fiat-Shamir absorption. The default observes `air_inputs`, then
///   `aux_inputs`, then each AIR's log trace height in instance order.
pub trait Instance<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// AIR type for this instance. Heterogeneous AIRs are expressed via
    /// caller-defined enum wrappers — see `miden-bench`'s `LiftedBenchAir`
    /// for the template.
    type Air: LiftedAir<F, EF>;

    /// AIRs in the proof. This method *defines* what the rest of the trait
    /// (and the stark crate) calls **instance order**: every other slice
    /// indexed by AIR — `aux_values`, `log_trace_heights`, the prover's
    /// traces — uses this position. The slice length is the number of AIR
    /// instances in the proof.
    fn airs(&self) -> &[&Self::Air];

    /// Public values shared by every AIR in the proof.
    fn air_inputs(&self) -> &[F];

    /// Auxiliary public inputs consumed only by [`Self::eval_external`].
    ///
    /// The framework imposes no schema on this slice — overrides of
    /// [`Self::eval_external`] decode it however they like and report
    /// malformed inputs via [`ReductionError`].
    ///
    /// Default: empty. The default [`Self::eval_external`] rejects any
    /// proof whose `aux_inputs` is non-empty, since it would otherwise
    /// silently ignore caller-supplied data.
    fn aux_inputs(&self) -> &[F] {
        &[]
    }

    /// Evaluate cross-AIR external assertions.
    ///
    /// Returns a flat vector of extension-field values, each of which must
    /// equal zero for the proof to be accepted. This method only produces
    /// the values; the caller decides how to check them — either entry by
    /// entry (precise non-zero index reporting) or by random linear
    /// combination (one check covers all entries).
    ///
    /// The caller (verifier) is responsible for ensuring the supplied
    /// `aux_values` and `log_trace_heights` describe the same statement as
    /// the AIR list returned by [`Self::airs`]. The framework enforces only
    /// `aux_values.len() == self.airs().len()` and the per-AIR contract
    /// checks (public values length, periodic columns); semantic agreement
    /// between this method and the AIR bodies is the implementer's
    /// responsibility.
    ///
    /// # Arguments
    /// - `challenges`: shared extension-field challenge pool. Each AIR uses a prefix of length
    ///   `air.num_randomness()`.
    /// - `aux_values`: per-AIR aux values, in instance order. `aux_values[i]` is the aux values for
    ///   `self.airs()[i]`.
    /// - `log_trace_heights`: per-AIR log₂ trace heights, in instance order. Already absorbed into
    ///   Fiat-Shamir before this method runs.
    ///
    /// # Errors
    ///
    /// Use [`ReductionError`] to report malformed inputs (e.g. an
    /// [`Self::aux_inputs`] slice shorter than expected) rather than
    /// panicking on out-of-bounds indexing.
    ///
    /// Default: rejects non-empty [`Self::aux_inputs`] (likely a bug — caller
    /// supplied data that nothing consumes); otherwise emits no assertions.
    fn eval_external(
        &self,
        _challenges: &[EF],
        _aux_values: &[&[EF]],
        _log_trace_heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        if !self.aux_inputs().is_empty() {
            return Err("default `eval_external` received non-empty `aux_inputs` — override \
                 `eval_external` to consume them"
                .into());
        }
        Ok(Vec::new())
    }

    /// Absorb the instance into the Fiat-Shamir challenger.
    ///
    /// Default order: `air_inputs`, then `aux_inputs`, then each AIR's log
    /// trace height in instance order. Overrides must preserve this ordering
    /// unless they account for the change on both prover and verifier.
    ///
    /// # Soundness gap (TODO)
    ///
    /// The default binds inputs and trace heights but does NOT canonically
    /// bind [`Self::airs`] or [`Self::eval_external`] into Fiat-Shamir.
    /// Until the symbolic-graph binding lands (tracked in
    /// <https://github.com/0xMiden/crypto/issues/970>), callers MUST still
    /// manually observe AIR
    /// configurations and `eval_external` identity into the challenger
    /// before calling the prover or verifier. A caller who changes an AIR's
    /// `eval` body or `eval_external` body without changing the inputs
    /// produces a proof the verifier cannot distinguish from the old logic.
    fn observe<C: CanObserve<F>>(&self, challenger: &mut C, log_trace_heights: &[u8]) {
        for &v in self.air_inputs() {
            challenger.observe(v);
        }
        for &v in self.aux_inputs() {
            challenger.observe(v);
        }
        for &h in log_trace_heights {
            challenger.observe(F::from_u8(h));
        }
    }
}

// ============================================================================
// ProverInstance trait
// ============================================================================

/// Prover-side companion to [`Instance`] adding per-AIR traces and aux-trace
/// construction.
///
/// `ProverInstance` *contains* an [`Instance`] (via the
/// [`Self::Instance`](ProverInstance::Instance) associated type and the
/// [`instance`](ProverInstance::instance) accessor) rather than inheriting
/// from it. That lets a prover wrapper reuse an existing verifier-side
/// [`Instance`] without re-implementing every method. The trait surface
/// carries no ordering information: traces are returned in instance order and
/// the stark prover derives the proof's AIR ordering internally via
/// `TraceOrder`.
///
/// # Future
///
/// This trait will gain `preprocessed_traces` and `preprocessed_ldes` methods
/// to support preprocessed (fixed) data and its low-degree extension.
pub trait ProverInstance<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// The verifier-side [`Instance`] this prover wraps.
    type Instance: Instance<F, EF>;

    /// Borrow the wrapped verifier-side instance. Both prover and verifier
    /// must observe the same data, which is what this accessor returns.
    fn instance(&self) -> &Self::Instance;

    /// Per-AIR main traces, in instance order. Must match
    /// [`Instance::airs`] in length and order.
    fn traces(&self) -> &[&RowMajorMatrix<F>];

    /// Build every AIR's auxiliary trace and aux values in a single call.
    ///
    /// `challenges` is sized to the maximum `num_randomness()` across all
    /// AIRs in the proof; implementors should consume the prefix matching
    /// each AIR's `num_randomness()`.
    ///
    /// # Returns
    ///
    /// `(aux_traces, aux_values)` with one entry per AIR in instance order:
    /// - `aux_traces[i]` has width `airs[i].aux_width()` and height matching the main trace
    /// - `aux_values[i]` has length `airs[i].num_aux_values()`; committed to the Fiat-Shamir
    ///   transcript and consumed by [`Instance::eval_external`].
    fn build_aux_traces(&self, challenges: &[EF]) -> (Vec<RowMajorMatrix<EF>>, Vec<Vec<EF>>);
}
