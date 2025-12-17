//! Auxiliary trace builder trait for dependency inversion.
//!
//! This trait allows ProcessorAir to build auxiliary traces without depending
//! on the processor crate, avoiding circular dependencies.

use crate::Felt;

/// Trait for building auxiliary traces from main trace and challenges.
///
/// # Why This Trait Exists
///
/// This trait serves to avoid circular dependencies:
/// - `ProcessorAir` (in this crate) needs to build auxiliary traces during proving
/// - The actual aux building logic lives in the `processor` crate
/// - But `processor` already depends on `air` for trace types and constraints
/// - Direct coupling would create: `air` → `processor` → `air`
///
/// The trait breaks the cycle:
/// - `air` defines the interface (this trait)
/// - `processor` implements the interface (concrete aux builders)
/// - `prover` injects the implementation: `ProcessorAir::with_aux_builder(impl)`
///
/// The trait works with row-major matrices (i.e., Plonky3 format).
pub trait AuxTraceBuilder<EF>: Send + Sync {
    /// Builds auxiliary trace in row-major format from the main trace.
    ///
    /// Takes the main trace in row-major format (as provided by Plonky3) and
    /// returns the auxiliary trace also in row-major format.
    fn build_aux_columns(
        &self,
        main_trace: &p3_matrix::dense::RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> p3_matrix::dense::RowMajorMatrix<Felt>;
}

/// Dummy implementation for () to support ProcessorAir without aux trace builders (e.g., in
/// verifier). This implementation should never be called since ProcessorAir::build_aux_trace
/// returns None when aux_builder is None.
impl<EF> AuxTraceBuilder<EF> for () {
    fn build_aux_columns(
        &self,
        _main_trace: &p3_matrix::dense::RowMajorMatrix<Felt>,
        _challenges: &[EF],
    ) -> p3_matrix::dense::RowMajorMatrix<Felt> {
        panic!("No aux trace builder configured - this should never be called")
    }
}
