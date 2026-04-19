//! Tests that the prover rejects aux trace width mismatches.

use alloc::{vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    air::{AuxBuilder, BaseAir, LiftedAir, LiftedAirBuilder},
    prove_single,
    testing::configs::goldilocks_poseidon2::{Felt, QuadFelt, test_challenger, test_config},
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

    fn num_var_len_public_inputs(&self) -> usize {
        0
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, _builder: &mut AB) {}
}

/// AuxBuilder that returns 2 EF columns when BadAuxWidthAir declares 1.
struct BadAuxBuilder;

impl AuxBuilder<Felt, QuadFelt> for BadAuxBuilder {
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let height = main.height();
        // Return 2 QuadFelt columns when aux_width() declares 1
        let aux = RowMajorMatrix::new(vec![QuadFelt::ZERO; height * 2], 2);
        (aux, vec![QuadFelt::ZERO, QuadFelt::ZERO])
    }
}

#[test]
#[should_panic(expected = "aux trace width mismatch")]
fn aux_width_mismatch_panics() {
    let config = test_config();
    let air = BadAuxWidthAir;

    let trace = RowMajorMatrix::new(vec![Felt::ZERO, Felt::ONE, Felt::ONE, Felt::ZERO], 1);
    let public_values = vec![];

    let _result =
        prove_single(&config, &air, &trace, &public_values, &[], &BadAuxBuilder, test_challenger());
}
