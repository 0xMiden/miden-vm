//! One authored relation shared by the test-only native preparation build pilot and its tests.

use std::borrow::Cow;

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_crypto::field::{Algebra, PrimeCharacteristicRing};
use miden_stark::air::{BaseAir, LiftedAir, LiftedAirBuilder, native};
use p3_field::Dup;

#[derive(Debug)]
pub struct PreparationFixture(pub bool);

impl BaseAir<Felt> for PreparationFixture {
    fn width(&self) -> usize {
        1
    }
}

impl LiftedAir<Felt, QuadFelt> for PreparationFixture {
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

    fn aux_width(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        2
    }
    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        _main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        _challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        unreachable!("this fixture only evaluates constraints")
    }

    fn eval<B: LiftedAirBuilder<F = Felt>>(&self, builder: &mut B, _data: &()) {
        native::migration::eval_source(self, builder);
    }
}

impl native::LiftedAir for PreparationFixture {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 2,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<B: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, B>,
        inputs: native::Inputs<'_, B>,
        sink: &mut B,
    ) {
        let main = frame.main.current[0].dup();
        if self.0 {
            let beta = inputs.challenge(1);
            let square = beta.dup() * beta.dup();
            let cube = square.dup() * beta;
            sink.assert_zero_ext(square * main.dup());
            sink.assert_zero_ext(cube + B::ExtExpr::from(main));
        } else {
            sink.assert_zero(main);
        }
    }
}

/// A native-only renderer fixture covering row/uniform namespaces and typed rewrites.
/// It is not registered as a production AIR and has no concrete witness algorithm.
pub struct NativeRendererFixture;

impl native::LiftedAir for NativeRendererFixture {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: 2,
            aux_width: 2,
            num_public_values: 1,
            num_challenges: 2,
            num_exports: 1,
            preprocessed: Some(native::PreprocessedSpec { width: 1, log_height: 2 }),
            periodic_columns: Cow::Owned(vec![vec![Felt::ONE, Felt::TWO, Felt::ZERO, Felt::ONE]]),
        }
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        panic!("renderer code generation must not materialize fixed tables")
    }

    fn eval<B: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, B>,
        inputs: native::Inputs<'_, B>,
        sink: &mut B,
    ) {
        use native::LiftedAirBuilder as _;

        let current = frame.main.current[0].dup();
        let next = frame.main.next[1].dup();
        let fixed = frame.preprocessed.current[0].dup();
        let next_fixed = frame.preprocessed.next[0].dup();
        let periodic = frame.periodic[0].dup();
        sink.named("renderer/base-dot").when(frame.first_row()).assert_zero(
            current.dup() * fixed.dup()
                + next.dup() * next_fixed.dup()
                + inputs.public(0) * periodic.dup()
                + frame.main.current[1].dup() * frame.main.next[0].dup(),
        );
        let shared = current.dup() + next.dup();
        sink.when(frame.transition())
            .assert_zero(shared.dup() * fixed + shared * next_fixed);
        sink.when(frame.last_row()).assert_zero_ext(
            frame.aux.current[0].dup() * current.dup()
                + frame.aux.next[1].dup() * next.dup()
                + inputs.export(0) * inputs.public(0)
                + frame.aux.current[1].dup() * frame.main.current[1].dup(),
        );
        sink.assert_zero(current.square() + next + periodic + inputs.public(0));
        let beta = inputs.challenge(1);
        let beta_square = beta.dup() * beta;
        sink.assert_zero_ext(beta_square * frame.aux.current[1].dup() - inputs.challenge(0));
    }
}
