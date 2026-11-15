//! Tests cross-AIR assertions from `eval_external`: aux values committed to the
//! transcript are tied to public `aux_inputs` by extension-field assertion
//! expressions checked outside the per-row AIR constraints.

use alloc::{borrow::Cow, vec, vec::Vec};

use core::convert::Infallible;

use p3_field::{Algebra, Dup, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::air::native::LiftedAirBuilder as _;
use crate::{
    ProverInstance, VerifierInstance,
    air::{
        BaseAir, LiftedAir, LiftedAirBuilder, MultiAir, ProverStatement, ReductionError, Statement,
        native,
    },
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

impl BaseAir<Felt> for ExternalAir {
    fn width(&self) -> usize {
        1
    }

    fn num_public_values(&self) -> usize {
        1 // [start]
    }
}

impl LiftedAir<Felt, QuadFelt> for ExternalAir {
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

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
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let aux = <Self as native::ProverAir<QuadFelt>>::build_aux_trace(
            self,
            native::AuxTraceInputs {
                main,
                preprocessed: None,
                public_values: air_inputs,
                statement: aux_inputs,
                challenges,
            },
        )
        .unwrap_or_else(|never| match never {});
        (aux.columns, aux.exports)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB, _data: &()) {
        native::migration::eval_source(self, builder);
    }
}

impl native::LiftedAir for ExternalAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 1,
            num_challenges: 1,
            num_exports: 1,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
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

impl native::ProverAir<QuadFelt> for ExternalAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        // One constant column: challenge + input.
        let value = QuadFelt::from(self.input) + inputs.challenges[0];
        let values = vec![value; inputs.main.height()];
        Ok(native::AuxTrace {
            columns: RowMajorMatrix::new(values, 1),
            exports: vec![value],
        })
    }
}

// ---------------------------------------------------------------------------
// ExternalMultiAir: the cross-AIR `eval_external` reduction over `aux_inputs`.
// ---------------------------------------------------------------------------

struct ExternalMultiAir {
    airs: Vec<native::DirectKernel<ExternalAir>>,
}

impl MultiAir<Felt, QuadFelt> for ExternalMultiAir {
    type Air = native::DirectKernel<ExternalAir>;

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
            airs: vec![native::DirectKernel::new(ExternalAir { input }).unwrap()],
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

#[test]
fn native_external_source_preserves_export_and_direct_symbolic_order() {
    use native::AirKernel;

    let source = ExternalAir { input: Felt::from_u64(42) };
    let expected = native::capture_with::<_, QuadFelt>(&source).unwrap();
    assert_eq!(expected.descriptor.analysis().layout().base_indices(), &[0, 1]);
    assert_eq!(expected.descriptor.analysis().layout().ext_indices(), &[2, 3]);

    let kernel = native::DirectKernel::new(source).unwrap();
    let main = generate_pow4_trace(Felt::from_u64(2), 4);
    let public = [Felt::from_u64(2)];
    let challenges = [QuadFelt::from_u64(7)];
    let aux = native::ProverAir::build_aux_trace(
        &kernel,
        native::AuxTraceInputs {
            main: &main,
            preprocessed: None,
            public_values: &public,
            statement: &[],
            challenges: &challenges,
        },
    )
    .unwrap();
    // This export is the constant itself, without trace-height normalization.
    assert_eq!(aux.columns.values, vec![QuadFelt::from_u64(49); 4]);
    assert_eq!(aux.exports, vec![QuadFelt::from_u64(49)]);

    let observed = native::capture_from_spec::<Felt, QuadFelt>(
        kernel.descriptor().spec().as_borrowed(),
        |frame, inputs, sink| kernel.bind(inputs).unwrap().eval(frame, sink),
    )
    .unwrap();
    assert_eq!(observed.descriptor.fingerprint(), expected.descriptor.fingerprint());
    assert_eq!(observed.descriptor.analysis(), expected.descriptor.analysis());
}
