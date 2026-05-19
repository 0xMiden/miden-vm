//! Tests that the prover rejects aux trace width mismatches.

use alloc::{vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    Instance, ProverInstance,
    air::{BaseAir, LiftedAir, LiftedAirBuilder},
    prove,
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

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, _builder: &mut AB) {}
}

/// Inputs that return 2 EF aux columns when BadAuxWidthAir declares 1.
struct BadInputs<'a> {
    airs: Vec<&'a BadAuxWidthAir>,
    traces: Vec<&'a RowMajorMatrix<Felt>>,
}

impl Instance<Felt, QuadFelt> for BadInputs<'_> {
    type Air = BadAuxWidthAir;

    fn airs(&self) -> &[&Self::Air] {
        &self.airs
    }

    fn air_inputs(&self) -> &[Felt] {
        &[]
    }
}

impl<'a> ProverInstance<Felt, QuadFelt> for BadInputs<'a> {
    type Instance = Self;

    fn instance(&self) -> &Self {
        self
    }

    fn traces(&self) -> &[&RowMajorMatrix<Felt>] {
        &self.traces
    }

    fn build_aux_traces(
        &self,
        _challenges: &[QuadFelt],
    ) -> (Vec<RowMajorMatrix<QuadFelt>>, Vec<Vec<QuadFelt>>) {
        let mut traces_out = Vec::with_capacity(self.traces.len());
        let mut values_out = Vec::with_capacity(self.traces.len());
        for &t in &self.traces {
            let height = t.height();
            // Return 2 columns when aux_width() declares 1
            let aux = RowMajorMatrix::new(vec![QuadFelt::ZERO; height * 2], 2);
            traces_out.push(aux);
            values_out.push(vec![QuadFelt::ZERO, QuadFelt::ZERO]);
        }
        (traces_out, values_out)
    }
}

#[test]
#[should_panic(expected = "aux trace width mismatch")]
fn aux_width_mismatch_panics() {
    let config = test_config();
    let air = BadAuxWidthAir;

    let trace = RowMajorMatrix::new(vec![Felt::ZERO, Felt::ONE, Felt::ONE, Felt::ZERO], 1);
    let inputs = BadInputs { airs: vec![&air], traces: vec![&trace] };

    let _result = prove(&config, &inputs, test_challenger());
}
