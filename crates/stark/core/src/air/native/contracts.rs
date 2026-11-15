//! Mathematical source and concrete auxiliary witness capabilities.

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;

use super::{AirSpec, Frame, Inputs, LiftedAirBuilder};

/// An authored relation, independent of witness construction and prepared execution.
///
/// Source configuration must remain immutable while its analyzed form is reused. `Sync` alone
/// does not establish this: dimensions, equation structure, assertion class/order and addressing
/// must depend only on configuration, never on input values or the selected expression backend.
pub trait LiftedAir: Sync {
    type F: Field;

    fn spec(&self) -> AirSpec<'_, Self::F>;

    /// Construct the fixed matrix declared by [`Self::spec`] for setup ownership.
    ///
    /// Setup validates presence and dimensions and caches the result. Capture, descriptor
    /// construction, verification and row evaluation must not invoke this factory.
    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Self::F>> {
        None
    }

    fn eval<B: LiftedAirBuilder<F = Self::F>>(
        &self,
        frame: &Frame<'_, B>,
        inputs: Inputs<'_, B>,
        sink: &mut B,
    );
}

/// Caller-owned inputs for one concrete auxiliary-witness construction.
///
/// Public values, statement inputs and the shared challenge prefix retain instance order. The
/// optional preprocessed matrix is borrowed from setup's cache; it is not rebuilt by the witness.
#[derive(Debug)]
pub struct AuxTraceInputs<'a, F, EF> {
    pub main: &'a RowMajorMatrix<F>,
    pub preprocessed: Option<&'a RowMajorMatrix<F>>,
    pub public_values: &'a [F],
    pub statement: &'a [F],
    pub challenges: &'a [EF],
}

impl<F, EF> Copy for AuxTraceInputs<'_, F, EF> {}

impl<F, EF> Clone for AuxTraceInputs<'_, F, EF> {
    fn clone(&self) -> Self {
        *self
    }
}

/// Constructed auxiliary columns and exported boundary values, in source-declared order.
#[derive(Debug)]
pub struct AuxTrace<EF> {
    pub columns: RowMajorMatrix<EF>,
    pub exports: Vec<EF>,
}

/// Concrete fallible witness construction, required by proving but not source inspection.
pub trait ProverAir<EF: ExtensionField<Self::F>>: LiftedAir {
    type Error: core::error::Error + Send + Sync + 'static;

    /// Build the declared auxiliary matrix and exports from the exact supplied inputs.
    ///
    /// Source-specific recoverable construction failures are returned as errors. Lookup arithmetic
    /// assumes nonzero divisors. Successful
    /// output dimensions and export ordering are trusted construction invariants checked by the
    /// caller. Temporary legacy tuple facades cannot propagate errors and retain their existing
    /// panic boundary until native runtime activation.
    fn build_aux_trace(
        &self,
        inputs: AuxTraceInputs<'_, Self::F, EF>,
    ) -> Result<AuxTrace<EF>, Self::Error>;
}
