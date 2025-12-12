//! Auxiliary trace builder trait for dependency inversion.
//!
//! This trait allows ProcessorAir to build auxiliary traces without depending
//! on the processor crate, avoiding circular dependencies.

use alloc::vec::Vec;

use crate::trace::main_trace::MainTrace;

/// Trait for building auxiliary traces from main trace and challenges.
///
/// This trait is implemented by the processor's AuxTraceBuilders and allows
/// ProcessorAir to build auxiliary traces without directly depending on processor internals.
///
/// Generic over extension field to support different extension degrees.
pub trait AuxTraceBuilder<EF>: Send + Sync {
    /// Builds auxiliary columns in extension field format from the main trace.
    ///
    /// Returns a vector of extension field columns (one Vec per aux column).
    fn build_aux_columns(&self, main_trace: &MainTrace, challenges: &[EF]) -> Vec<Vec<EF>>;
}

/// Dummy implementation for () to support ProcessorAir without aux trace builders (e.g., in
/// verifier). This implementation should never be called since ProcessorAir::build_aux_trace
/// returns None when aux_builder is None.
impl<EF> AuxTraceBuilder<EF> for () {
    fn build_aux_columns(&self, _main_trace: &MainTrace, _challenges: &[EF]) -> Vec<Vec<EF>> {
        panic!("No aux trace builder configured - this should never be called")
    }
}
