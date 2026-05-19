//! Tests external assertions (multiset and logup bus identities encoded as polynomial
//! assertions over public inputs).

use alloc::{vec, vec::Vec};

use miden_lifted_air::ReductionError;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    Instance, ProverInstance,
    air::{AirBuilder, BaseAir, ExtensionBuilder, LiftedAir, LiftedAirBuilder, WindowAccess},
    prove,
    testing::configs::goldilocks_poseidon2::{
        Felt, QuadFelt, generate_pow4_trace, test_challenger, test_config,
    },
    verify,
};

// ---------------------------------------------------------------------------
// BusTestAir: exercises external assertions with multiset + logup bus-style
// identities.
//
// Main trace: 1 column, power-of-4 chain.
// Aux trace: 2 constant columns (all rows identical):
//   col 0: 1/(pi_0 + challenge[0])  — inverse for multiset bus
//   col 1: pi_1 + challenge[1]      — accumulator for logup bus
//
// `BusInputs::eval_external` (must all equal zero):
//   assert_0 (multiset): aux_values[0] * (c0 + pi_0) - 1 == 0
//   assert_1 (logup):    (aux_values[1] - c1) - pi_1     == 0
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct BusTestAir;

impl BaseAir<Felt> for BusTestAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        3 // [start, pi_0, pi_1]
    }
}

impl LiftedAir<Felt, QuadFelt> for BusTestAir {
    fn num_randomness(&self) -> usize {
        2
    }

    fn aux_width(&self) -> usize {
        2
    }

    fn num_aux_values(&self) -> usize {
        2
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let pv0 = builder.public_values()[0];
        let pv1 = builder.public_values()[1];
        let pv2 = builder.public_values()[2];

        let main = builder.main();
        let (local, next) = (main.current_slice(), main.next_slice());

        // Main trace: power-of-4 chain
        builder.when_first_row().assert_eq(local[0], pv0);
        let main_pow4: AB::Expr = local[0].into().exp_power_of_2(2);
        builder.when_transition().assert_eq(next[0], main_pow4);

        let c0: AB::RandomVar = builder.permutation_randomness()[0];
        let c1: AB::RandomVar = builder.permutation_randomness()[1];
        let av0: AB::PermutationVar = builder.permutation_values()[0].clone();
        let av1: AB::PermutationVar = builder.permutation_values()[1].clone();

        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();

        let pi_0: AB::ExprEF = Into::<AB::Expr>::into(pv1).into();
        let pi_1: AB::ExprEF = Into::<AB::Expr>::into(pv2).into();
        let c0: AB::ExprEF = c0.into();
        let c1: AB::ExprEF = c1.into();

        let a0: AB::ExprEF = aux_local[0].into();
        builder.when_first_row().assert_eq_ext(a0 * (pi_0 + c0), AB::ExprEF::ONE);

        let a1: AB::ExprEF = aux_local[1].into();
        builder.when_first_row().assert_eq_ext(a1, pi_1 + c1);

        builder
            .when_transition()
            .assert_eq_ext::<AB::ExprEF, AB::ExprEF>(aux_next[0].into(), aux_local[0].into());
        builder
            .when_transition()
            .assert_eq_ext::<AB::ExprEF, AB::ExprEF>(aux_next[1].into(), aux_local[1].into());

        builder
            .when_last_row()
            .assert_eq_ext::<AB::ExprEF, AB::ExprEF>(aux_local[0].into(), av0.into());
        builder
            .when_last_row()
            .assert_eq_ext::<AB::ExprEF, AB::ExprEF>(aux_local[1].into(), av1.into());
    }
}

// ---------------------------------------------------------------------------
// Inputs: shared `air_inputs` (start, pi_0, pi_1), an `aux_inputs` slice
// absorbed into Fiat-Shamir before the proof, and an `eval_external` that
// emits the multiset + logup assertions.
// ---------------------------------------------------------------------------

struct BusInputs<'a> {
    trace: &'a RowMajorMatrix<Felt>,
    air_inputs: &'a [Felt],
    aux_inputs: Vec<Felt>,
    pi_0: Felt,
    pi_1: Felt,
    airs_slice: [&'a BusTestAir; 1],
    traces_slice: [&'a RowMajorMatrix<Felt>; 1],
}

impl<'a> BusInputs<'a> {
    fn new(
        air: &'a BusTestAir,
        trace: &'a RowMajorMatrix<Felt>,
        air_inputs: &'a [Felt],
        pi_0: Felt,
        pi_1: Felt,
    ) -> Self {
        Self::with_aux_inputs(air, trace, air_inputs, pi_0, pi_1, vec![pi_0, pi_1])
    }

    fn with_aux_inputs(
        air: &'a BusTestAir,
        trace: &'a RowMajorMatrix<Felt>,
        air_inputs: &'a [Felt],
        pi_0: Felt,
        pi_1: Felt,
        aux_inputs: Vec<Felt>,
    ) -> Self {
        Self {
            trace,
            air_inputs,
            aux_inputs,
            pi_0,
            pi_1,
            airs_slice: [air],
            traces_slice: [trace],
        }
    }
}

impl Instance<Felt, QuadFelt> for BusInputs<'_> {
    type Air = BusTestAir;

    fn airs(&self) -> &[&Self::Air] {
        &self.airs_slice
    }

    fn air_inputs(&self) -> &[Felt] {
        self.air_inputs
    }

    fn aux_inputs(&self) -> &[Felt] {
        &self.aux_inputs
    }

    fn eval_external(
        &self,
        challenges: &[QuadFelt],
        aux_values: &[&[QuadFelt]],
        _log_trace_heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        let aux = aux_values.first().ok_or("expected aux values for the instance")?;

        let pi_0 = *self.aux_inputs.first().ok_or("missing pi_0")?;
        let pi_1 = *self.aux_inputs.get(1).ok_or("missing pi_1")?;
        let pi_0 = QuadFelt::from(pi_0);
        let pi_1 = QuadFelt::from(pi_1);

        let multiset = aux[0] * (challenges[0] + pi_0) - QuadFelt::ONE;
        let logup = (aux[1] - challenges[1]) - pi_1;

        Ok(vec![multiset, logup])
    }
}

impl<'a> ProverInstance<Felt, QuadFelt> for BusInputs<'a> {
    type Instance = Self;

    fn instance(&self) -> &Self {
        self
    }

    fn traces(&self) -> &[&RowMajorMatrix<Felt>] {
        &self.traces_slice
    }

    fn build_aux_traces(
        &self,
        challenges: &[QuadFelt],
    ) -> (Vec<RowMajorMatrix<QuadFelt>>, Vec<Vec<QuadFelt>>) {
        let height = self.trace.height();
        let c0 = challenges[0];
        let c1 = challenges[1];

        let col0_val = (QuadFelt::from(self.pi_0) + c0).inverse();
        let col1_val = QuadFelt::from(self.pi_1) + c1;

        let mut values = Vec::with_capacity(height * 2);
        for _ in 0..height {
            values.push(col0_val);
            values.push(col1_val);
        }

        (vec![RowMajorMatrix::new(values, 2)], vec![vec![col0_val, col1_val]])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn bus_identity_check() {
    let config = test_config();

    let pi_0 = Felt::from_u64(42);
    let pi_1 = Felt::from_u64(67);
    let start = Felt::from_u64(2);
    let height = 8;

    let air = BusTestAir;
    let trace = generate_pow4_trace(start, height);
    let air_inputs = vec![start, pi_0, pi_1];

    let inputs = BusInputs::new(&air, &trace, &air_inputs, pi_0, pi_1);
    let output = prove(&config, &inputs, test_challenger()).expect("proving should succeed");

    let verifier_digest = verify(&config, &inputs, &output.proof, test_challenger())
        .expect("verification should succeed");
    assert_eq!(output.digest, verifier_digest);
}

#[test]
fn bus_wrong_external_pi_fails() {
    let config = test_config();

    let pi_0 = Felt::from_u64(42);
    let pi_1 = Felt::from_u64(67);
    let start = Felt::from_u64(2);
    let height = 8;

    let air = BusTestAir;
    let trace = generate_pow4_trace(start, height);
    let air_inputs = vec![start, pi_0, pi_1];

    let inputs = BusInputs::new(&air, &trace, &air_inputs, pi_0, pi_1);
    let output = prove(&config, &inputs, test_challenger()).expect("proving should succeed");

    // Wrong aux_inputs on the verifier side — Fiat-Shamir diverges.
    let wrong_pi_0 = Felt::from_u64(99);
    let wrong_inputs = BusInputs::new(&air, &trace, &air_inputs, wrong_pi_0, pi_1);

    let err = verify(&config, &wrong_inputs, &output.proof, test_challenger())
        .expect_err("wrong external_pi should fail verification");

    let _ = err;
}

#[test]
fn bus_short_external_inputs_fails() {
    let config = test_config();

    let pi_0 = Felt::from_u64(42);
    let pi_1 = Felt::from_u64(67);
    let start = Felt::from_u64(2);
    let height = 8;

    let air = BusTestAir;
    let trace = generate_pow4_trace(start, height);
    let air_inputs = vec![start, pi_0, pi_1];

    // A short aux_inputs slice — `eval_external` will run out of inputs and
    // surface a ReductionError. Using the same inputs on both sides keeps
    // Fiat-Shamir consistent so the failure surfaces at the assertion path.
    let broken = BusInputs::with_aux_inputs(&air, &trace, &air_inputs, pi_0, pi_1, vec![pi_0]);

    let output = prove(&config, &broken, test_challenger()).expect("proving should succeed");

    let err = verify(&config, &broken, &output.proof, test_challenger())
        .expect_err("short external inputs should fail verification");

    assert!(
        matches!(err, crate::VerifierError::Reduction(_)),
        "expected Reduction, got {err:?}"
    );
}
