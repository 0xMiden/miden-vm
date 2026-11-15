//! Tests LMCS alignment with padding for multi-trace proving/verification.

use alloc::{borrow::Cow, vec, vec::Vec};

use core::convert::Infallible;

use p3_field::{Algebra, Dup, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::air::native::LiftedAirBuilder as _;
use crate::{
    air::{BaseAir, LiftedAir, LiftedAirBuilder, MultiAir, ProverStatement, Statement, native},
    lmcs::Lmcs,
    testing::configs::goldilocks_poseidon2::{
        Felt, QuadFelt, prove_and_verify_statement, test_config,
    },
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
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        self.aux_width
    }

    fn num_aux_values(&self) -> usize {
        0
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

impl native::LiftedAir for PaddingAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: self.width,
            aux_width: self.aux_width,
            num_public_values: 1,
            num_challenges: 1,
            num_exports: 0,
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

        builder.when(frame.first_row()).assert_eq(local[0].dup(), inputs.public(0));
        builder.when(frame.transition()).assert_eq(next[0].dup(), local[0].dup());
        builder
            .when(frame.first_row())
            .assert_eq_ext(frame.aux.current[0].dup(), inputs.challenge(0));
        builder
            .when(frame.transition())
            .assert_eq_ext(frame.aux.next[0].dup(), frame.aux.current[0].dup());
    }
}

impl native::ProverAir<QuadFelt> for PaddingAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        // Column 0 holds the challenge; all remaining auxiliary columns are padding.
        let challenge = inputs.challenges[0];
        let mut values = Vec::with_capacity(inputs.main.height() * self.aux_width);
        for _ in 0..inputs.main.height() {
            values.push(challenge);
            values.extend(core::iter::repeat_n(QuadFelt::ZERO, self.aux_width - 1));
        }
        Ok(native::AuxTrace {
            columns: RowMajorMatrix::new(values, self.aux_width),
            exports: vec![],
        })
    }
}

struct PaddingMultiAir {
    airs: Vec<native::DirectKernel<PaddingAir>>,
}

impl MultiAir<Felt, QuadFelt> for PaddingMultiAir {
    type Air = native::DirectKernel<PaddingAir>;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
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

fn padding_prover_statement(
    width: usize,
    aux_width: usize,
    start: Felt,
) -> ProverStatement<Felt, QuadFelt, PaddingMultiAir> {
    let air = PaddingAir::new(width, aux_width);
    let t0 = generate_trace(start, 8, width);
    let t1 = generate_trace(start, 16, width);
    let statement = Statement::new(
        PaddingMultiAir {
            airs: vec![
                native::DirectKernel::new(air.clone()).unwrap(),
                native::DirectKernel::new(air).unwrap(),
            ],
        },
        vec![(0, vec![start]), (1, vec![start])],
        Vec::new(),
    )
    .unwrap();
    ProverStatement::new(statement, vec![t0, t1]).unwrap()
}

#[test]
fn multi_trace_with_aux_padding() {
    let config = test_config();
    let alignment = config.lmcs.alignment();
    let width = alignment + 1;
    let aux_width = alignment + 1;
    let start = Felt::from_u64(START);

    let prover_statement = padding_prover_statement(width, aux_width, start);

    prove_and_verify_statement(prover_statement);
}

#[test]
fn native_padding_source_preserves_declared_aux_width_and_direct_symbolic_order() {
    use native::AirKernel;

    let source = PaddingAir::new(3, 2);
    let expected = native::capture_with::<_, QuadFelt>(&source).unwrap();
    assert_eq!(expected.descriptor.analysis().layout().base_indices(), &[0, 1]);
    assert_eq!(expected.descriptor.analysis().layout().ext_indices(), &[2, 3]);

    let kernel = native::DirectKernel::new(source).unwrap();
    let main = generate_trace(Felt::from_u64(2), 4, 3);
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
    assert_eq!(aux.columns.width(), 2);
    assert_eq!(aux.columns.values, [QuadFelt::from_u64(7), QuadFelt::ZERO].repeat(4),);
    assert!(aux.exports.is_empty());

    let observed = native::capture_from_spec::<Felt, QuadFelt>(
        kernel.descriptor().spec().as_borrowed(),
        |frame, inputs, sink| kernel.bind(inputs).unwrap().eval(frame, sink),
    )
    .unwrap();
    assert_eq!(observed.descriptor.fingerprint(), expected.descriptor.fingerprint());
    assert_eq!(observed.descriptor.analysis(), expected.descriptor.analysis());
}
