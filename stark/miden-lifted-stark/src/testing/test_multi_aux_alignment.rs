//! Tests LMCS alignment with padding for multi-trace proving/verification.

use alloc::{vec, vec::Vec};

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    Instance, Lmcs, ProverInstance, VerifierError,
    air::{AirBuilder, BaseAir, ExtensionBuilder, LiftedAir, LiftedAirBuilder, WindowAccess},
    prove,
    testing::configs::goldilocks_poseidon2::{
        Felt, QuadFelt, prove_and_verify_instance, test_challenger, test_config,
    },
    transcript::TranscriptData,
    verify,
};

const START: u64 = 2;

#[derive(Clone, Debug)]
struct PaddingAir {
    width: usize,
    aux_width: usize,
}

impl PaddingAir {
    fn new(width: usize, aux_width: usize) -> Self {
        Self { width, aux_width }
    }
}

impl BaseAir<Felt> for PaddingAir {
    fn width(&self) -> usize {
        self.width
    }

    fn num_public_values(&self) -> usize {
        1
    }
}

impl LiftedAir<Felt, QuadFelt> for PaddingAir {
    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        self.aux_width
    }

    fn num_aux_values(&self) -> usize {
        0
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main();
        let start = builder.public_values()[0];
        let (local, next) = (main.current_slice(), main.next_slice());

        builder.when_first_row().assert_eq(local[0], start);
        builder.when_transition().assert_eq(next[0], local[0]);

        let aux = builder.permutation();
        let aux_local = aux.current_slice();
        let aux_next = aux.next_slice();
        let challenge: AB::ExprEF = builder.permutation_randomness()[0].into();
        builder.when_first_row().assert_eq_ext(aux_local[0].into(), challenge);
        builder.when_transition().assert_eq_ext(aux_next[0].into(), aux_local[0].into());
    }
}

struct PaddingInputs<'a> {
    aux_width: usize,
    airs: Vec<&'a PaddingAir>,
    traces: Vec<&'a RowMajorMatrix<Felt>>,
    air_inputs: &'a [Felt],
}

impl Instance<Felt, QuadFelt> for PaddingInputs<'_> {
    type Air = PaddingAir;

    fn airs(&self) -> &[&Self::Air] {
        &self.airs
    }

    fn air_inputs(&self) -> &[Felt] {
        self.air_inputs
    }
}

impl<'a> ProverInstance<Felt, QuadFelt> for PaddingInputs<'a> {
    type Instance = Self;

    fn instance(&self) -> &Self {
        self
    }

    fn traces(&self) -> &[&RowMajorMatrix<Felt>] {
        &self.traces
    }

    fn build_aux_traces(
        &self,
        challenges: &[QuadFelt],
    ) -> (Vec<RowMajorMatrix<QuadFelt>>, Vec<Vec<QuadFelt>>) {
        let challenge = challenges[0];
        let mut traces_out = Vec::with_capacity(self.traces.len());
        let mut values_out = Vec::with_capacity(self.traces.len());
        for &t in &self.traces {
            let height = t.height();
            let mut values = Vec::with_capacity(height * self.aux_width);
            for _ in 0..height {
                values.push(challenge);
                values.extend(core::iter::repeat_n(QuadFelt::ZERO, self.aux_width - 1));
            }
            traces_out.push(RowMajorMatrix::new(values, self.aux_width));
            values_out.push(vec![]);
        }
        (traces_out, values_out)
    }
}

fn generate_trace(start: Felt, height: usize, width: usize) -> RowMajorMatrix<Felt> {
    let mut values = Vec::with_capacity(height * width);
    for _ in 0..height {
        values.push(start);
        values.extend(core::iter::repeat_n(Felt::ZERO, width - 1));
    }
    RowMajorMatrix::new(values, width)
}

#[test]
fn multi_trace_with_aux_padding() {
    let config = test_config();
    let alignment = config.lmcs.alignment();
    let width = alignment + 1;
    let aux_width = alignment + 1;
    let start = Felt::from_u64(START);

    let air = PaddingAir::new(width, aux_width);
    let t0 = generate_trace(start, 8, width);
    let t1 = generate_trace(start, 16, width);
    let air_inputs = vec![start];

    let inputs = PaddingInputs {
        aux_width,
        airs: vec![&air, &air],
        traces: vec![&t0, &t1],
        air_inputs: &air_inputs,
    };

    prove_and_verify_instance(&inputs);
}

#[test]
fn multi_trace_rejects_trailing_transcript_data() {
    let config = test_config();
    let alignment = config.lmcs.alignment();
    let width = alignment + 1;
    let aux_width = alignment + 1;
    let start = Felt::from_u64(START);

    let air = PaddingAir::new(width, aux_width);
    let t0 = generate_trace(start, 8, width);
    let t1 = generate_trace(start, 16, width);
    let air_inputs = vec![start];

    let inputs = PaddingInputs {
        aux_width,
        airs: vec![&air, &air],
        traces: vec![&t0, &t1],
        air_inputs: &air_inputs,
    };

    let output = prove(&config, &inputs, test_challenger()).expect("proving should succeed");

    let mut bad_proof = output.proof;
    let (mut fields, commitments) = bad_proof.transcript.into_parts();
    fields.push(Felt::ONE);
    bad_proof.transcript = TranscriptData::new(fields, commitments);

    let err = verify(&config, &inputs, &bad_proof, test_challenger())
        .expect_err("extra transcript data should fail verification");
    assert!(matches!(
        err,
        VerifierError::Transcript(crate::transcript::TranscriptError::TrailingData)
    ));
}
