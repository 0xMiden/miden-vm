//! Auxiliary trace builder trait and adapter.
//!
//! [`AuxTraceBuilder`] breaks the circular dependency between the `air` and
//! `processor` crates: the trait is defined here, implemented in `processor`,
//! and injected by the `prover`.
//!
//! [`AuxTraceAdapter`] bridges a local `AuxTraceBuilder` to the upstream
//! [`AuxBuilder`](p3_miden_lifted_air::AuxBuilder) trait expected by the
//! lifted prover.

use alloc::vec::Vec;

use miden_core::{field::ExtensionField, utils::RowMajorMatrix};
use p3_miden_lifted_air::AuxBuilder;

use crate::Felt;

/// Trait for building auxiliary traces from main trace and challenges.
///
/// # Why This Trait Exists
///
/// This trait serves to avoid circular dependencies:
/// - The actual aux building logic lives in the `processor` crate
/// - But `processor` already depends on `air` for trace types and constraints
/// - Direct coupling would create: `air` → `processor` → `air`
///
/// The trait breaks the cycle:
/// - `air` defines the interface (this trait)
/// - `processor` implements the interface (concrete aux builders)
/// - `prover` wraps the implementation in [`AuxTraceAdapter`]
///
/// The trait works with row-major matrices (i.e., Plonky3 format).
///
/// Returns `RowMajorMatrix<EF>` (extension field) — the lifted prover handles
/// the EF→F flattening internally.
pub trait AuxTraceBuilder<EF>: Send + Sync {
    /// Builds auxiliary trace in row-major format from the main trace.
    ///
    /// Takes the main trace in row-major format (as provided by Plonky3) and
    /// returns the auxiliary trace also in row-major format, over the extension field.
    fn build_aux_columns(
        &self,
        main_trace: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> RowMajorMatrix<EF>;
}

/// Adapter bridging a local [`AuxTraceBuilder`] to the upstream
/// [`AuxBuilder`] trait required by the lifted prover.
pub struct AuxTraceAdapter<B>(pub B);

impl<EF, B> AuxBuilder<Felt, EF> for AuxTraceAdapter<B>
where
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let _span = tracing::info_span!("build_aux_trace").entered();
        let aux_trace = self.0.build_aux_columns(main, challenges);
        // The prover sends aux_values into the Fiat-Shamir transcript, and the
        // verifier reads back exactly `aux_width()` extension field elements.
        // We use the last row of the aux trace as aux_values. These are used by
        // reduced_aux_values() for cross-AIR identity checking in multi-table
        // proofs. Currently reduced_aux_values() returns identity, so the actual
        // values don't affect correctness — but the count must match aux_width().
        let width = aux_trace.width;
        let last_row = aux_trace.values[aux_trace.values.len() - width..].to_vec();
        (aux_trace, last_row)
    }
}
