//! Tests the cross-AIR `eval_external` reduction: aux values committed to the
//! transcript are tied to public `aux_inputs` by extension-field assertions the
//! verifier checks outside the per-row AIR constraints.

use alloc::{vec, vec::Vec};

use miden_lifted_air::ReductionError;
use p3_field::PrimeCharacteristicRing;
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
// ExternalAir: a power-of-4 main trace plus a single constant aux column equal
// to `challenge + input`. The committed aux value is that constant, bound to
// the aux column's last row in-circuit; `eval_external` then ties it to
// `aux_inputs[0]` shifted by the challenge.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct ExternalAir {
    input: Felt,
}

impl BaseAir<Felt> for ExternalAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        1 // [start]
    }
}

impl LiftedAir<Felt, QuadFelt> for ExternalAir {
    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        1
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        // One constant column: challenge + input.
        let value = QuadFelt::from(self.input) + challenges[0];
        let values = vec![value; main.height()];
        (RowMajorMatrix::new(values, 1), vec![value])
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let start = builder.public_values()[0];

        let main = builder.main();
        let (local, next) = (main.current_slice(), main.next_slice());

        // Main trace: power-of-4 chain anchored at the public start value.
        builder.when_first_row().assert_eq(local[0], start);
        let main_pow4: AB::Expr = local[0].into().exp_power_of_2(2);
        builder.when_transition().assert_eq(next[0], main_pow4);

        // Aux column is constant and exposes its value as the committed aux value
        // on the last row — the value `eval_external` reasons about.
        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();
        let aux_value: AB::PermutationVar = builder.permutation_values()[0].clone();

        builder
            .when_transition()
            .assert_eq_ext::<AB::ExprEF, AB::ExprEF>(aux_next[0].into(), aux_local[0].into());
        builder
            .when_last_row()
            .assert_eq_ext::<AB::ExprEF, AB::ExprEF>(aux_local[0].into(), aux_value.into());
    }
}

// ---------------------------------------------------------------------------
// ExternalMultiAir: the cross-AIR `eval_external` reduction over `aux_inputs`.
// ---------------------------------------------------------------------------

struct ExternalMultiAir {
    airs: Vec<ExternalAir>,
}

impl MultiAir<Felt, QuadFelt> for ExternalMultiAir {
    type Air = ExternalAir;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }

    fn max_aux_inputs(&self) -> usize {
        1
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
        let input = *aux_inputs.first().ok_or("missing external input")?;

        // The committed aux value must equal `challenge + input`.
        Ok(vec![aux[0] - challenges[0] - QuadFelt::from(input)])
    }
}

fn external_prover_statement(
    input: Felt,
    trace: RowMajorMatrix<Felt>,
    air_inputs: Vec<Felt>,
    aux_inputs: Vec<Felt>,
) -> ProverStatement<Felt, QuadFelt, ExternalMultiAir> {
    let statement = Statement::new(
        ExternalMultiAir { airs: vec![ExternalAir { input }] },
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
fn external_assertion_holds() {
    let config = test_config();

    let input = Felt::from_u64(42);
    let start = Felt::from_u64(2);

    let trace = generate_pow4_trace(start, 8);
    let prover_statement = external_prover_statement(input, trace, vec![start], vec![input]);

    let output =
        prove(&config, &prover_statement, test_challenger()).expect("proving should succeed");

    let verifier_digest =
        verify(&config, prover_statement.statement(), &output.proof, test_challenger())
            .expect("verification should succeed");
    assert_eq!(output.digest, verifier_digest);
}

#[test]
fn missing_external_input_fails_proving() {
    let config = test_config();

    let input = Felt::from_u64(42);
    let start = Felt::from_u64(2);

    let trace = generate_pow4_trace(start, 8);

    // Empty `aux_inputs`: `eval_external` runs out of inputs and surfaces a
    // ReductionError. The prover mirrors the verifier's external assertion
    // evaluation after aux values are available, so malformed statements fail
    // early; this could become a debug assertion if proving needs to skip this
    // verifier-side sanity check.
    let broken = external_prover_statement(input, trace, vec![start], vec![]);

    let err = prove(&config, &broken, test_challenger())
        .expect_err("missing external input should fail proving");
    assert!(
        matches!(err, crate::ProverError::Reduction(_)),
        "expected Reduction, got {err:?}"
    );
}
