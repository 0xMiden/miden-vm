//! Current source and compiled execution retain every input namespace and emission.

use miden_constraint_compiler::testing::{EvaluationBuilder, assert_concrete_evaluations_equal};
use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_stark::air::{
    AirDescriptor, AirFrame, AirKernel, AuxTrace, AuxTraceInputs, DirectKernel, Frame, Inputs,
    LiftedAirBuilder, ProverAir, Rows, Selectors, UniformInputs,
};
use p3_field::{Algebra, PrimeCharacteristicRing};

#[path = "../build/current_inputs_fixture.rs"]
mod fixture;
mod generated {
    include!(concat!(env!("OUT_DIR"), "/current_inputs_fixture.rs"));
}

struct Kernel(AirDescriptor<Felt>);
impl AirKernel for Kernel {
    type F = Felt;
    type Prepared<B: Algebra<Felt>, E: Algebra<B>> = [E; generated::ALL_INPUTS_PREPARED_TERMS];

    fn descriptor(&self) -> &AirDescriptor<Felt> {
        &self.0
    }
    fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
        &self,
        inputs: UniformInputs<'_, B, E>,
    ) -> Self::Prepared<B, E> {
        generated::precompute_all_inputs(inputs)
    }
    fn eval_row<B: LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &Frame<'_, B>,
        inputs: Inputs<'_, B>,
        terms: &Self::Prepared<B::Expr, B::ExtExpr>,
        sink: &mut B,
    ) {
        generated::eval_all_inputs(frame, inputs, sink, terms);
    }
}

fn quad(real: u64, imaginary: u64) -> QuadFelt {
    QuadFelt::new([Felt::from_u64(real), Felt::from_u64(imaginary)])
}

fn assert_expected_emissions<K: AirKernel<F = Felt>>(
    kernel: &K,
    frame: &AirFrame<'_, Felt, QuadFelt>,
    inputs: UniformInputs<'_, Felt, QuadFelt>,
) {
    let mut actual = EvaluationBuilder::<Felt, QuadFelt>::default();
    kernel
        .bind(inputs)
        .expect("current-input dimensions match the descriptor")
        .eval(frame, &mut actual);
    // Global sequence: B, E, B(0), B(0), B, E, B. Large selectors detect wrong routing.
    assert_eq!(actual.base_indices, [0, 2, 3, 4, 6]);
    assert_eq!(actual.ext_indices, [1, 5]);
    assert_eq!(
        actual.base_constraints,
        [
            -Felt::from_u64(1003), // 59 * (2 - 19)
            Felt::ZERO,
            Felt::ZERO,
            Felt::from_u64(201),  // 67 * (5 - 2)
            -Felt::from_u64(854), // 61 * (3 - 17)
        ],
    );
    assert_eq!(
        actual.ext_constraints,
        [
            quad(28, 19),   // (23, 29) + (41, 43) - (47, 53) + 11
            quad(61, 2257), // 61 * ((31, 37) - (13 + 17))
        ],
    );
}

#[test]
fn all_inputs_and_ordered_emissions_match_source_and_hand_values() {
    let source = DirectKernel::new(fixture::AllInputs).unwrap();
    let kernel = Kernel(source.descriptor().clone());
    let main = [[2, 3], [5, 7]].map(|row| row.map(Felt::from_u64));
    let preprocessed = [[11], [13]].map(|row| row.map(Felt::from_u64));
    let aux = [[quad(23, 29)], [quad(31, 37)]];
    let periodic = [Felt::from_u64(17)];
    let frame = AirFrame {
        main: Rows { current: &main[0], next: &main[1] },
        preprocessed: Rows {
            current: &preprocessed[0],
            next: &preprocessed[1],
        },
        aux: Rows { current: &aux[0], next: &aux[1] },
        periodic: &periodic,
        selectors: Selectors {
            first: Felt::from_u64(59),
            last: Felt::from_u64(61),
            transition: Felt::from_u64(67),
        },
    };
    let inputs = UniformInputs {
        public_values: &[Felt::from_u64(19)],
        challenges: &[quad(41, 43)],
        exports: &[quad(47, 53)],
    };
    assert_expected_emissions(&source, &frame, inputs);
    assert_expected_emissions(&kernel, &frame, inputs);
    for seed in [0, 0x243f6a8885a308d3, 0x13198a2e03707344, u64::MAX] {
        assert_concrete_evaluations_equal(&source, &kernel, seed);
    }
    assert_eq!(fixture::generate(), fixture::generate(), "generation is deterministic");
}

impl ProverAir<QuadFelt> for fixture::AllInputs {
    type Error = core::convert::Infallible;

    fn build_aux_trace(
        &self,
        inputs: AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<AuxTrace<QuadFelt>, Self::Error> {
        let mut accumulator = inputs.challenges[0] + inputs.public_values[0];
        let mut values = Vec::with_capacity(inputs.main.values.len() / 2);
        for row in inputs.main.values.chunks_exact(2) {
            values.push(accumulator);
            accumulator += row[0];
        }
        Ok(AuxTrace {
            columns: RowMajorMatrix::new(values, 1),
            exports: vec![accumulator],
        })
    }
}

#[test]
fn auxiliary_running_sum_and_export_match_hand_values() {
    let main = RowMajorMatrix::new([2, 3, 5, 7, 11, 13, 17, 19].map(Felt::from_u64).to_vec(), 2);
    let built = fixture::AllInputs
        .build_aux_trace(AuxTraceInputs {
            main: &main,
            preprocessed: None,
            public_values: &[Felt::from_u64(23)],
            statement: &[],
            challenges: &[quad(29, 31)],
        })
        .unwrap();
    // Start at challenge + public = (52, 31), then add each row's first main cell.
    assert_eq!(built.columns.width, 1);
    assert_eq!(built.columns.values, [quad(52, 31), quad(54, 31), quad(59, 31), quad(70, 31)]);
    assert_eq!(built.exports, [quad(87, 31)]);
}
