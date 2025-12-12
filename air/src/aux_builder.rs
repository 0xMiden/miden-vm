//! Auxiliary trace builder trait for dependency inversion.
//!
//! This trait allows ProcessorAir to build auxiliary traces without depending
//! on the processor crate, avoiding circular dependencies.

use miden_core::Felt;
use p3_matrix::dense::RowMajorMatrix;

/// Trait for building auxiliary traces from main trace and challenges.
///
/// This trait is implemented by the processor's AuxTraceBuilders and allows
/// ProcessorAir to build auxiliary traces without directly depending on processor internals.
///
/// Generic over extension field to support different extension degrees.
pub trait AuxTraceBuilder<EF>: Send + Sync {
    /// Builds the auxiliary trace from the main trace and random challenges.
    ///
    /// Returns the aux trace as a row-major matrix in base field representation.
    fn build_aux_trace(
        &self,
        main_trace: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> RowMajorMatrix<Felt>;
}

/// Dummy implementation for () to support ProcessorAir without aux trace builders (e.g., in verifier).
/// This implementation should never be called since ProcessorAir::build_aux_trace returns None
/// when aux_builder is None.
impl<EF> AuxTraceBuilder<EF> for () {
    fn build_aux_trace(
        &self,
        _main_trace: &RowMajorMatrix<Felt>,
        _challenges: &[EF],
    ) -> RowMajorMatrix<Felt> {
        panic!("No aux trace builder configured - this should never be called")
    }
}
