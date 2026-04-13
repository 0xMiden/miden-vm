//! Tests reduced auxiliary values (multiset and logup bus identities).

use alloc::{vec, vec::Vec};

use miden_lifted_air::ReductionError;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    AirInstance, AirWitness,
    air::{
        AirBuilder, AuxBuilder, BaseAir, ExtensionBuilder, LiftedAir, LiftedAirBuilder,
        ReducedAuxValues, VarLenPublicInputs, WindowAccess,
    },
    prove_multi,
    testing::configs::goldilocks_poseidon2::{
        Felt, QuadFelt, generate_pow4_trace, test_challenger, test_config,
    },
    verify_multi,
};

// ---------------------------------------------------------------------------
// BusTestAir: exercises reduced_aux_values with multiset + logup buses.
//
// Main trace: 1 column, power-of-4 chain (same as TinyAir).
// Aux trace: 2 constant columns (all rows identical):
//   col 0: 1/(pi_0 + challenge[0])  — inverse for multiset bus
//   col 1: pi_1 + challenge[1]      — accumulator for logup bus
//
// Aux values (committed to transcript, constrained to match aux trace last row):
//   aux_values[0] = col 0 value = 1/(pi_0 + c0)
//   aux_values[1] = col 1 value = pi_1 + c1
//
// reduced_aux_values (verifier-side bus identity check):
//   Bus 0 (multiset): prod = aux_values[0] * (c0 + pi_0) == 1
//   Bus 1 (logup):    sum  = (aux_values[1] - c1) - pi_1 == 0
//
// pi_0, pi_1 appear in two places:
//   - public_values[1..]: used by eval() for aux trace constraints
//   - var_len_public_inputs: used by reduced_aux_values() for bus check
// Both must agree for the proof to verify.
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

    fn num_var_len_public_inputs(&self) -> usize {
        2
    }

    fn reduced_aux_values(
        &self,
        aux_values: &[QuadFelt],
        challenges: &[QuadFelt],
        _public_values: &[Felt],
        var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    ) -> Result<ReducedAuxValues<QuadFelt>, ReductionError> {
        // Bus 0 (multiset): prod = aux_values[0] * (challenges[0] + pi_0)
        // aux_values[0] = 1/(pi_0 + c0), so prod == 1 when pi_0 matches.
        let pi_0 = QuadFelt::from(var_len_public_inputs[0][0]);
        let prod = aux_values[0] * (challenges[0] + pi_0);

        // Bus 1 (logup): sum = (aux_values[1] - challenges[1]) - pi_1
        // aux_values[1] = pi_1 + c1, so sum == 0 when pi_1 matches.
        let pi_1 = QuadFelt::from(var_len_public_inputs[1][0]);
        let sum = (aux_values[1] - challenges[1]) - pi_1;

        Ok(ReducedAuxValues { prod, sum })
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        // Copy public values upfront (PublicVar: Copy) to release borrow.
        let pv0 = builder.public_values()[0];
        let pv1 = builder.public_values()[1];
        let pv2 = builder.public_values()[2];

        let main = builder.main();
        let (local, next) = (main.current_slice(), main.next_slice());

        // Main trace: power-of-4 chain
        builder.when_first_row().assert_eq(local[0], pv0);
        let main_pow4: AB::Expr = local[0].into().exp_power_of_2(2);
        builder.when_transition().assert_eq(next[0], main_pow4);

        // Copy challenges and aux values (RandomVar/VarEF: Copy) to release borrow.
        let c0: AB::RandomVar = builder.permutation_randomness()[0];
        let c1: AB::RandomVar = builder.permutation_randomness()[1];
        let av0: AB::PermutationVar = builder.permutation_values()[0].clone();
        let av1: AB::PermutationVar = builder.permutation_values()[1].clone();

        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();

        // pi_0 = public_values[1], pi_1 = public_values[2]
        let pi_0: AB::ExprEF = Into::<AB::Expr>::into(pv1).into();
        let pi_1: AB::ExprEF = Into::<AB::Expr>::into(pv2).into();
        let c0: AB::ExprEF = c0.into();
        let c1: AB::ExprEF = c1.into();

        // First row: aux[0] * (pi_0 + c0) == 1
        let a0: AB::ExprEF = aux_local[0].into();
        builder.when_first_row().assert_eq_ext(a0 * (pi_0 + c0), AB::ExprEF::ONE);

        // First row: aux[1] == pi_1 + c1
        let a1: AB::ExprEF = aux_local[1].into();
        builder.when_first_row().assert_eq_ext(a1, pi_1 + c1);

        // Transition: constant columns
        builder
            .when_transition()
            .assert_eq_ext::<AB::ExprEF, AB::ExprEF>(aux_next[0].into(), aux_local[0].into());
        builder
            .when_transition()
            .assert_eq_ext::<AB::ExprEF, AB::ExprEF>(aux_next[1].into(), aux_local[1].into());

        // Last row: aux columns match aux_values
        builder
            .when_last_row()
            .assert_eq_ext::<AB::ExprEF, AB::ExprEF>(aux_local[0].into(), av0.into());
        builder
            .when_last_row()
            .assert_eq_ext::<AB::ExprEF, AB::ExprEF>(aux_local[1].into(), av1.into());
    }
}

// ---------------------------------------------------------------------------
// AuxBuilder: constant aux columns.
// ---------------------------------------------------------------------------

struct BusTestAuxBuilder {
    pi_0: Felt,
    pi_1: Felt,
}

impl AuxBuilder<Felt, QuadFelt> for BusTestAuxBuilder {
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let height = main.height();
        let c0 = challenges[0];
        let c1 = challenges[1];

        // col 0: 1/(pi_0 + c0), col 1: pi_1 + c1
        let col0_val = (QuadFelt::from(self.pi_0) + c0).inverse();
        let col1_val = QuadFelt::from(self.pi_1) + c1;

        let mut values = Vec::with_capacity(height * 2);
        for _ in 0..height {
            values.push(col0_val);
            values.push(col1_val);
        }

        let aux_trace = RowMajorMatrix::new(values, 2);
        let aux_values = vec![col0_val, col1_val];
        (aux_trace, aux_values)
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
    let aux_builder = BusTestAuxBuilder { pi_0, pi_1 };
    let trace = generate_pow4_trace(start, height);
    let public_values = vec![start, pi_0, pi_1];

    // Build var_len_public_inputs (one reducible input per bus)
    let input_0 = [pi_0];
    let input_1 = [pi_1];
    let var_len_pi: [&[Felt]; 2] = [&input_0, &input_1];

    // Prove
    let prover_instances =
        [(&air, AirWitness::new(&trace, &public_values, &var_len_pi), &aux_builder)];
    let output =
        prove_multi(&config, &prover_instances, test_challenger()).expect("proving should succeed");

    let instance = AirInstance {
        public_values: &public_values,
        var_len_public_inputs: &var_len_pi,
    };

    // Verify
    let verifier_digest =
        verify_multi(&config, &[(&air, instance)], &output.proof, test_challenger())
            .expect("verification should succeed");
    assert_eq!(output.digest, verifier_digest);
}

#[test]
fn bus_wrong_var_len_pi_fails() {
    let config = test_config();

    let pi_0 = Felt::from_u64(42);
    let pi_1 = Felt::from_u64(67);
    let start = Felt::from_u64(2);
    let height = 8;

    let air = BusTestAir;
    let aux_builder = BusTestAuxBuilder { pi_0, pi_1 };
    let trace = generate_pow4_trace(start, height);
    let public_values = vec![start, pi_0, pi_1];

    // Prove with correct values
    let input_0 = [pi_0];
    let input_1 = [pi_1];
    let var_len_pi: [&[Felt]; 2] = [&input_0, &input_1];

    let prover_instances =
        [(&air, AirWitness::new(&trace, &public_values, &var_len_pi), &aux_builder)];
    let output =
        prove_multi(&config, &prover_instances, test_challenger()).expect("proving should succeed");

    // Verify with WRONG var_len_public_inputs (99 instead of 42)
    let wrong_pi_0 = Felt::from_u64(99);
    let wrong_input_0 = [wrong_pi_0];
    let wrong_var_len_pi: [&[Felt]; 2] = [&wrong_input_0, &input_1];

    let instance = AirInstance {
        public_values: &public_values,
        var_len_public_inputs: &wrong_var_len_pi,
    };

    let err = verify_multi(&config, &[(&air, instance)], &output.proof, test_challenger())
        .expect_err("wrong var_len_pi should fail verification");

    assert!(
        matches!(err, crate::VerifierError::InvalidReducedAux),
        "expected InvalidReducedAux, got {err:?}"
    );
}

#[test]
fn bus_wrong_input_count_fails() {
    let config = test_config();

    let pi_0 = Felt::from_u64(42);
    let pi_1 = Felt::from_u64(67);
    let start = Felt::from_u64(2);
    let height = 8;

    let air = BusTestAir;
    let aux_builder = BusTestAuxBuilder { pi_0, pi_1 };
    let trace = generate_pow4_trace(start, height);
    let public_values = vec![start, pi_0, pi_1];

    // Prove with correct values
    let input_0 = [pi_0];
    let input_1 = [pi_1];
    let var_len_pi: [&[Felt]; 2] = [&input_0, &input_1];

    let prover_instances =
        [(&air, AirWitness::new(&trace, &public_values, &var_len_pi), &aux_builder)];
    let output =
        prove_multi(&config, &prover_instances, test_challenger()).expect("proving should succeed");

    // Verify with WRONG input count (1 instead of 2)
    let only_one: [&[Felt]; 1] = [&input_0];
    let instance = AirInstance {
        public_values: &public_values,
        var_len_public_inputs: &only_one,
    };

    let err = verify_multi(&config, &[(&air, instance)], &output.proof, test_challenger())
        .expect_err("wrong input count should fail verification");

    assert!(
        matches!(
            err,
            crate::VerifierError::Instance(
                crate::InstanceValidationError::VarLenPublicInputsMismatch { .. }
            )
        ),
        "expected VarLenPublicInputsMismatch, got {err:?}"
    );
}
