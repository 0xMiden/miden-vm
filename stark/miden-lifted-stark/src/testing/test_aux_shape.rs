//! Tests that `MultiAir::build_aux_traces` shape mismatches surface via
//! [`crate::debug::assert_aux_traces_shape`].
//!
//! The prover proper trusts the output of `build_aux_traces` — the
//! contract is enforced (in debug builds / tests) by calling
//! `assert_aux_traces_shape` from the harness.

use alloc::{vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    MultiAir, ProverStatement, Statement,
    air::{BaseAir, LiftedAir, LiftedAirBuilder},
    debug::assert_aux_traces_shape,
    testing::configs::goldilocks_poseidon2::{Felt, QuadFelt, test_challenger},
};

#[derive(Clone, Copy, Debug)]
struct BadAuxWidthAir;

impl BaseAir<Felt> for BadAuxWidthAir {
    fn width(&self) -> usize {
        1
    }
}

impl LiftedAir<Felt, QuadFelt> for BadAuxWidthAir {
    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        0
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, _builder: &mut AB) {}
}

/// `MultiAir` that returns 2 EF aux columns when `BadAuxWidthAir` declares 1.
struct BadMultiAir {
    airs: Vec<BadAuxWidthAir>,
}

impl MultiAir<Felt, QuadFelt> for BadMultiAir {
    type Air = BadAuxWidthAir;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }

    fn build_aux_traces(
        &self,
        traces: &[&RowMajorMatrix<Felt>],
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        _challenges: &[QuadFelt],
    ) -> (Vec<RowMajorMatrix<QuadFelt>>, Vec<Vec<QuadFelt>>) {
        let mut traces_out = Vec::with_capacity(traces.len());
        let mut values_out = Vec::with_capacity(traces.len());
        for &t in traces {
            let height = p3_matrix::Matrix::height(t);
            // Return 2 columns when aux_width() declares 1.
            let aux = RowMajorMatrix::new(vec![QuadFelt::ZERO; height * 2], 2);
            traces_out.push(aux);
            values_out.push(vec![QuadFelt::ZERO, QuadFelt::ZERO]);
        }
        (traces_out, values_out)
    }
}

#[test]
#[should_panic(expected = "AIR 0: aux trace width = 2, but air.aux_width() = 1")]
fn aux_width_mismatch_panics_in_debug_check() {
    let trace = RowMajorMatrix::new(vec![Felt::ZERO, Felt::ONE, Felt::ONE, Felt::ZERO], 1);
    let statement =
        Statement::new(BadMultiAir { airs: vec![BadAuxWidthAir] }, Vec::new(), Vec::new()).unwrap();
    let prover_statement = ProverStatement::new(statement, vec![trace]).unwrap();

    assert_aux_traces_shape(&prover_statement, test_challenger());
}
