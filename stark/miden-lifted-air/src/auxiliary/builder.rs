//! The `AuxBuilder` trait for constructing auxiliary traces.
//!
//! This trait decouples auxiliary trace *building* from the AIR definition,
//! allowing the prover to supply a separate builder per instance.

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

/// Builder for constructing the auxiliary trace from a main trace and challenges.
///
/// Decoupled from [`LiftedAir`](crate::LiftedAir) so that prover-side trace
/// construction is not part of the AIR trait. Each prover instance can supply
/// its own `AuxBuilder`.
pub trait AuxBuilder<F: Field, EF: ExtensionField<F>> {
    /// Build the auxiliary trace and return aux values.
    ///
    /// # Arguments
    /// - `main`: The main trace matrix
    /// - `challenges`: Extension-field challenges for aux trace construction
    ///
    /// # Returns
    /// `(aux_trace, aux_values)` where:
    /// - `aux_trace`: The auxiliary trace matrix (EF columns)
    /// - `aux_values`: Extension-field scalars committed to the Fiat-Shamir transcript. Their
    ///   meaning is AIR-defined — typically the aux trace's last row, but the protocol does not
    ///   require this. The AIR's [`eval`](crate::LiftedAir::eval) should constrain how they relate
    ///   to the committed trace, and [`reduced_aux_values`](crate::LiftedAir::reduced_aux_values)
    ///   uses them for cross-AIR bus identity checking.
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<F>,
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>);
}
