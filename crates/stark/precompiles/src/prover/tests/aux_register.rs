//! Tests for an extension-field register that shares the auxiliary trace with LogUp columns.
//!
//! A beta-dependent accumulator must be committed after the Fiat-Shamir challenge is sampled, so
//! it belongs in the auxiliary trace. [`native_lookup::ConstraintLookupBuilder`] uses the declared
//! lookup-column prefix to keep such registers out of the LogUp sum while preserving their AIR
//! constraints.

use std::{borrow::Cow, vec, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_stark::{air::native, lookup::native as native_lookup};
use native::LiftedAirBuilder as _;
use p3_field::Dup;
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::prover::{
    logup::{Deg, NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
};

const COL_X: usize = 0;
const NUM_MAIN_COLS: usize = 1;

// Aux layout: col 0 = centered running sum (the one LogUp column, emitting nothing); col 1 = the
// extension-field Horner register.
const NUM_LOGUP_COLS: usize = 1;
const REGISTER_COL: usize = 1;
const AUX_WIDTH: usize = 2;

/// The single LogUp column emits no bus tuples.
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [0];

#[derive(Debug, Default, Clone, Copy)]
struct AuxRegisterAir;

impl native::LiftedAir for AuxRegisterAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: AUX_WIDTH,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
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
        // The committed Horner suffix precedes the LogUp assertion stream.
        let x_local = frame.main.current[COL_X].dup();
        let beta = inputs.challenge(1);
        let acc = frame.aux.current[REGISTER_COL].dup();
        let acc_next = frame.aux.next[REGISTER_COL].dup();
        builder.when(frame.first_row()).assert_zero_ext(acc.dup());
        builder
            .when(frame.transition())
            .assert_zero_ext(acc_next - acc * beta - x_local);
        native_lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl native::ProverAir<QuadFelt> for AuxRegisterAir {
    type Error = native_lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        // The collector allocates both columns but normalizes only the declared empty prefix.
        let mut auxiliary = native_lookup::build_logup_aux_trace(self, inputs)?;
        let beta = inputs.challenges[1];
        let mut reg = QuadFelt::ZERO;
        for row in 0..inputs.main.height() {
            auxiliary.columns.values[row * AUX_WIDTH + REGISTER_COL] = reg;
            reg = reg * beta + QuadFelt::from(inputs.main.values[row * NUM_MAIN_COLS + COL_X]);
        }
        Ok(auxiliary)
    }
}

impl<LB: native_lookup::LookupBuilder<F = Felt>> native_lookup::LookupAir<LB> for AuxRegisterAir {
    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, _frame: &native_lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        // Auxiliary column 1 follows the declared LogUp prefix and is excluded from its sum.
        builder.next_column(|_col| {}, Deg { v: 1, u: 1 });
    }
}

fn rand_qf(rng: &mut impl Rng) -> QuadFelt {
    QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())])
}

#[test]
fn ext_register_verifies_and_stays_out_of_the_logup_sum() {
    let mut rng = StdRng::seed_from_u64(0x5217e);
    let n = 16usize;
    let x: Vec<Felt> = (0..n).map(|_| Felt::from(rng.random::<u32>())).collect();
    let main = RowMajorMatrix::new(x, NUM_MAIN_COLS);

    let challenges: [QuadFelt; NUM_RANDOMNESS] = [rand_qf(&mut rng), rand_qf(&mut rng)];

    // The register remains committed and constrained without contributing to the LogUp sum.
    let native::AuxTrace {
        columns: auxiliary,
        exports: normalized_sum,
    } = native::ProverAir::build_aux_trace(
        &AuxRegisterAir,
        native::AuxTraceInputs {
            main: &main,
            preprocessed: None,
            public_values: &[],
            statement: &[],
            challenges: &challenges,
        },
    )
    .expect("register witness inputs are valid");
    assert_eq!(normalized_sum, vec![QuadFelt::ZERO], "register must not pollute the LogUp sum");
    assert_eq!(auxiliary.width(), AUX_WIDTH);
    assert!(auxiliary.values.chunks(AUX_WIDTH).all(|row| row[0] == QuadFelt::ZERO));
    assert_eq!(auxiliary.values[REGISTER_COL], QuadFelt::ZERO);
    assert_eq!(auxiliary.values[AUX_WIDTH + REGISTER_COL], QuadFelt::from(main.values[COL_X]));

    // Inspect the same native body with non-Copy expressions and a real direct binding.
    use native::AirKernel;
    let expected = native::capture_with::<_, QuadFelt>(&AuxRegisterAir).unwrap();
    assert!(expected.descriptor.analysis().layout().base_indices().is_empty());
    assert_eq!(expected.descriptor.analysis().layout().ext_indices(), &[0, 1, 2, 3]);
    let kernel = native::DirectKernel::new(AuxRegisterAir).unwrap();
    let observed = native::capture_from_spec::<Felt, QuadFelt>(
        kernel.descriptor().spec().as_borrowed(),
        |frame, inputs, sink| kernel.bind(inputs).unwrap().eval(frame, sink),
    )
    .unwrap();
    assert_eq!(observed.descriptor.fingerprint(), expected.descriptor.fingerprint());
    assert_eq!(observed.descriptor.analysis(), expected.descriptor.analysis());

    // The Horner and centered LogUp recurrences both hold on the trace.
    crate::prover::tests::check_local(AuxRegisterAir, &main);
}
