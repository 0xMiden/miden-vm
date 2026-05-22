//! Tests external assertions (multiset and logup bus identities encoded as polynomial
//! assertions over public inputs).

use alloc::{vec, vec::Vec};

use miden_lifted_air::ReductionError;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    MultiAir, ProverStatement, Statement,
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
// `BusMultiAir::eval_external` (must all equal zero):
//   assert_0 (multiset): aux_values[0] * (c0 + pi_0) - 1 == 0
//   assert_1 (logup):    (aux_values[1] - c1) - pi_1     == 0
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct BusTestAir {
    pi_0: Felt,
    pi_1: Felt,
}

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

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        // Two constant columns: col0 = 1/(pi_0 + c0) (multiset), col1 = pi_1 + c1 (logup).
        let c0 = challenges[0];
        let c1 = challenges[1];
        let col0 = (QuadFelt::from(self.pi_0) + c0).inverse();
        let col1 = QuadFelt::from(self.pi_1) + c1;

        let mut values = Vec::with_capacity(main.height() * 2);
        for _ in 0..main.height() {
            values.push(col0);
            values.push(col1);
        }
        (RowMajorMatrix::new(values, 2), vec![col0, col1])
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
// MultiAir: the cross-AIR `eval_external` reduction over `aux_inputs`.
// ---------------------------------------------------------------------------

struct BusMultiAir {
    airs: Vec<BusTestAir>,
}

impl MultiAir<Felt, QuadFelt> for BusMultiAir {
    type Air = BusTestAir;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }

    fn max_aux_inputs(&self) -> usize {
        // `pi_0` and `pi_1`.
        2
    }

    fn eval_external(
        &self,
        challenges: &[QuadFelt],
        _air_inputs: &[Felt],
        aux_inputs: &[Felt],
        aux_values: &[&[QuadFelt]],
        _log_trace_heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        let aux = aux_values.first().ok_or("expected aux values for the instance")?;

        let pi_0 = *aux_inputs.first().ok_or("missing pi_0")?;
        let pi_1 = *aux_inputs.get(1).ok_or("missing pi_1")?;
        let pi_0 = QuadFelt::from(pi_0);
        let pi_1 = QuadFelt::from(pi_1);

        let multiset = aux[0] * (challenges[0] + pi_0) - QuadFelt::ONE;
        let logup = (aux[1] - challenges[1]) - pi_1;

        Ok(vec![multiset, logup])
    }
}

fn bus_prover_statement(
    pi_0: Felt,
    pi_1: Felt,
    trace: RowMajorMatrix<Felt>,
    air_inputs: Vec<Felt>,
    aux_inputs: Vec<Felt>,
) -> ProverStatement<Felt, QuadFelt, BusMultiAir> {
    let statement = Statement::new(
        BusMultiAir { airs: vec![BusTestAir { pi_0, pi_1 }] },
        air_inputs,
        aux_inputs,
    )
    .expect("statement inputs valid");
    ProverStatement::new(statement, vec![trace]).expect("trace shape valid")
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

    let trace = generate_pow4_trace(start, height);
    let air_inputs = vec![start, pi_0, pi_1];
    let aux_inputs = vec![pi_0, pi_1];

    let prover_statement = bus_prover_statement(pi_0, pi_1, trace, air_inputs, aux_inputs);

    let output =
        prove(&config, &prover_statement, test_challenger()).expect("proving should succeed");

    let verifier_digest =
        verify(&config, prover_statement.statement(), &output.proof, test_challenger())
            .expect("verification should succeed");
    assert_eq!(output.digest, verifier_digest);
}

#[test]
fn bus_short_external_inputs_fails() {
    let config = test_config();

    let pi_0 = Felt::from_u64(42);
    let pi_1 = Felt::from_u64(67);
    let start = Felt::from_u64(2);
    let height = 8;

    let trace = generate_pow4_trace(start, height);
    let air_inputs = vec![start, pi_0, pi_1];

    // A short aux_inputs slice — `eval_external` will run out of inputs and
    // surface a ReductionError. Using the same inputs on both sides keeps
    // Fiat-Shamir consistent so the failure surfaces at the assertion path.
    let broken = bus_prover_statement(pi_0, pi_1, trace, air_inputs, vec![pi_0]);

    let output = prove(&config, &broken, test_challenger()).expect("proving should succeed");

    let err = verify(&config, broken.statement(), &output.proof, test_challenger())
        .expect_err("short external inputs should fail verification");

    assert!(
        matches!(err, crate::VerifierError::Reduction(_)),
        "expected Reduction, got {err:?}"
    );
}
