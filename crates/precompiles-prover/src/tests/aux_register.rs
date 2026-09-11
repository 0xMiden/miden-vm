//! Tests for an extension-field register that shares the auxiliary trace with LogUp columns.
//!
//! A beta-dependent accumulator must be committed after the Fiat-Shamir challenge is sampled, so
//! it belongs in the auxiliary trace. [`ConstraintLookupBuilder`] uses the declared lookup-column
//! prefix to keep such registers out of the LogUp sum while preserving their AIR constraints.

use std::{vec, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::air::ExtensionBuilder;
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::{
    logup::{
        ConstraintLookupBuilder, Deg, LookupAir, LookupBuilder, NUM_LOGUP_VALUES,
        NUM_PUBLIC_VALUES, NUM_RANDOMNESS, build_logup_aux_trace,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main},
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

impl BaseAir<Felt> for AuxRegisterAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl LiftedAir<Felt, QuadFelt> for AuxRegisterAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        AUX_WIDTH
    }

    fn num_aux_values(&self) -> usize {
        NUM_LOGUP_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        // Col 0: the centered running sum from the empty LogUp column.
        let (logup, normalized_sum) = build_logup_aux_trace(&AuxRegisterAir, main, challenges);
        let n = main.height();
        let beta = challenges[1];

        // Col 1: the Horner register, interleaved with col 0 into a
        // 2-wide row-major aux trace. reg[0] = 0; reg[r+1] = reg[r]·β + x[r].
        let mut data = Vec::with_capacity(AUX_WIDTH * n);
        let mut reg = QuadFelt::ZERO;
        for r in 0..n {
            data.push(logup.values[r]);
            data.push(reg);
            reg = reg * beta + QuadFelt::from(main.values[r]);
        }
        (RowMajorMatrix::new(data, AUX_WIDTH), normalized_sum)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        // Phase 1: the extension-field Horner register on aux col 1.
        //   reg[0] = 0,  reg[r+1] = reg[r]·β + x[r].
        let x_local: AB::Var = current_main::<_, AB::Var, NUM_MAIN_COLS>(builder.main(), 0)[COL_X];
        let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
        let acc: AB::ExprEF =
            current_main::<_, AB::VarEF, 1>(builder.permutation(), REGISTER_COL)[0].into();
        let acc_next: AB::ExprEF =
            next_main::<_, AB::VarEF, 1>(builder.permutation(), REGISTER_COL)[0].into();

        // Boundary: the register seeds at 0.
        builder.when_first_row().assert_zero_ext(acc.clone());
        // Transition: acc_next − acc·β − x = 0 (the wrap row is excluded).
        let x_expr: AB::Expr = x_local.into();
        builder.when_transition().assert_zero_ext(acc_next - acc * beta - x_expr);

        // Phase 2: LogUp over one empty column, so the normalized sum is zero.
        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

impl<LB> LookupAir<LB> for AuxRegisterAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
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
    let (_, normalized_sum) = AuxRegisterAir.build_aux_trace(&main, &[], &[], &challenges);
    assert_eq!(normalized_sum, vec![QuadFelt::ZERO], "register must not pollute the LogUp sum");

    // The Horner and centered LogUp recurrences both hold on the trace.
    crate::tests::check_local(AuxRegisterAir, &main);
}
