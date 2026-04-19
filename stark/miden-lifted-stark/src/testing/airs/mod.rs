//! Example AIRs wrapped for the lifted STARK prover.
//!
//! Each module adapts an upstream Plonky3 AIR into a `LiftedAir` so it can be proven
//! and verified with the lifted STARK protocol.

use alloc::{vec, vec::Vec};

use miden_lifted_air::AuxBuilder;
use p3_field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

#[cfg(feature = "testing")]
pub mod blake3;
#[cfg(feature = "testing")]
pub mod keccak;
pub mod miden;
#[cfg(feature = "testing")]
pub mod poseidon2;

/// Aux builder that produces an all-zero auxiliary trace.
///
/// Every `LiftedAir` must have at least one aux column, so this builder
/// satisfies the requirement with minimal cost.
///
/// Use [`ZeroAuxBuilder::dummy()`] for AIRs with `num_aux_values() == 0`
/// (1-column all-zero trace, no aux values).
pub struct ZeroAuxBuilder {
    pub num_aux_cols: usize,
    pub num_aux_values: usize,
}

impl ZeroAuxBuilder {
    /// 1-column all-zero auxiliary trace with no aux values.
    ///
    /// Suitable for AIRs where `num_aux_values() == 0`.
    pub fn dummy() -> Self {
        Self { num_aux_cols: 1, num_aux_values: 0 }
    }
}

impl<F: Field, EF: ExtensionField<F>> AuxBuilder<F, EF> for ZeroAuxBuilder {
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<F>,
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        let height = main.height();
        let values = EF::zero_vec(height * self.num_aux_cols);
        let aux_trace = RowMajorMatrix::new(values, self.num_aux_cols);
        let aux_values = vec![EF::ZERO; self.num_aux_values];
        (aux_trace, aux_values)
    }
}
