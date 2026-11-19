//! Tests cross-AIR assertions from `eval_external`: aux values committed to the
//! transcript are tied to public `aux_inputs` by extension-field assertion
//! expressions checked outside the per-row AIR constraints.

use alloc::{borrow::Cow, vec, vec::Vec};
use core::convert::Infallible;

use p3_field::{Dup, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    ProverInstance, VerifierInstance, air,
    air::{LiftedAirBuilder as _, MultiAir, ProverStatement, ReductionError, Statement},
    testing::configs::goldilocks_poseidon2::{
        Felt, QuadFelt, generate_pow4_trace, test_challenger, test_config,
    },
};

// ---------------------------------------------------------------------------
// ExternalAir: a power-of-4 main trace plus a single constant aux column equal
// to `challenge + input`. The committed aux value is that constant, bound to
// the aux column's last row by AIR constraints; `eval_external` then ties it to
// `aux_inputs[0]` shifted by the challenge.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct ExternalAir {
    input: Felt,
}

impl air::LiftedAir for ExternalAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 1,
            num_challenges: 1,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let local = frame.main.current;
        let next = frame.main.next;

        // Main trace: power-of-4 chain anchored at the public start value.
        builder.when(frame.first_row()).assert_eq(local[0].dup(), inputs.public(0));
        let main_pow4 = local[0].dup().exp_power_of_2(2);
        builder.when(frame.transition()).assert_eq(next[0].dup(), main_pow4);

        // The last-row export is the value used by the unchanged external reduction.
        builder
            .when(frame.transition())
            .assert_eq_ext(frame.aux.next[0].dup(), frame.aux.current[0].dup());
        builder
            .when(frame.last_row())
            .assert_eq_ext(frame.aux.current[0].dup(), inputs.export(0));
    }
}

impl air::ProverAir<QuadFelt> for ExternalAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        // One constant column: challenge + input.
        let value = QuadFelt::from(self.input) + inputs.challenges[0];
        let values = vec![value; inputs.main.height()];
        Ok(air::AuxTrace {
            columns: RowMajorMatrix::new(values, 1),
            exports: vec![value],
        })
    }
}

// ---------------------------------------------------------------------------
// ExternalMultiAir: the cross-AIR `eval_external` reduction over `aux_inputs`.
// ---------------------------------------------------------------------------

struct ExternalMultiAir {
    airs: Vec<air::DirectKernel<ExternalAir>>,
}

impl MultiAir<Felt, QuadFelt> for ExternalMultiAir {
    type Air = air::DirectKernel<ExternalAir>;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }

    fn max_aux_inputs(&self) -> usize {
        1
    }

    fn eval_external(
        &self,
        challenges: &[QuadFelt],
        _air_inputs: &[Vec<Felt>],
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
        ExternalMultiAir {
            airs: vec![air::DirectKernel::new(ExternalAir { input }).unwrap()],
        },
        vec![(0, air_inputs)],
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

    let prover_instance =
        ProverInstance::new(&config, prover_statement, None).expect("no preprocessed columns");
    let (output, statement) =
        prover_instance.prove(test_challenger()).expect("proving should succeed");

    let verifier_digest = VerifierInstance::new(&config, &statement, None)
        .expect("no preprocessed columns")
        .verify(&output.proof, test_challenger())
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

    let err = ProverInstance::new(&config, broken, None)
        .expect("no preprocessed columns")
        .prove(test_challenger())
        .err()
        .expect("missing external input should fail proving");
    assert!(
        matches!(err, crate::ProverError::Reduction(_)),
        "expected Reduction, got {err:?}"
    );
}
