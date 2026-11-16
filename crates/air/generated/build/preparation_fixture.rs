//! One authored relation shared by the test-only native preparation build pilot and its tests.

use std::borrow::Cow;

use miden_core::{Felt, utils::RowMajorMatrix};
use miden_crypto::field::PrimeCharacteristicRing;
use miden_stark::air;
use p3_field::Dup;

#[derive(Debug)]
pub struct PreparationFixture(pub bool);

impl air::LiftedAir for PreparationFixture {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: 1,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 2,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<B: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, B>,
        inputs: air::Inputs<'_, B>,
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

impl air::LiftedAir for NativeRendererFixture {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: 2,
            aux_width: 2,
            num_public_values: 1,
            num_challenges: 2,
            num_exports: 1,
            preprocessed: Some(air::PreprocessedSpec { width: 1, log_height: 2 }),
            periodic_columns: Cow::Owned(vec![vec![Felt::ONE, Felt::TWO, Felt::ZERO, Felt::ONE]]),
        }
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        panic!("renderer code generation must not materialize fixed tables")
    }

    fn eval<B: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, B>,
        inputs: air::Inputs<'_, B>,
        sink: &mut B,
    ) {
        use air::LiftedAirBuilder as _;

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
