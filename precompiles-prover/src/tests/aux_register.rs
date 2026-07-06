//! Spike: an extension-field "register" column in the aux trace, kept
//! out of σ.
//!
//! De-risks the vertical Schwartz–Zippel layout the field chiplet needs
//! (`docs/chiplets/field.md`). A β-dependent accumulator cannot live in
//! the main trace — that's committed before β is Fiat-Shamir-sampled — so
//! it must be an aux column. But the σ/n running-sum constraint folds in
//! every aux column past col 0, which would pull the register into σ and
//! break the cross-AIR balance. This validates the `num_logup_cols` bound
//! added to [`CyclicConstraintLookupBuilder`]: aux col 1 carries a Horner
//! accumulator `acc' = acc·β + x`, committed and AIR-constrained via
//! `assert_zero_ext`, yet excluded from σ — which must come out **0**
//! here, since the single LogUp column emits nothing.

use std::{vec, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::stark::air::ExtensionBuilder;
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::{
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBuilder, NUM_PUBLIC_VALUES,
        NUM_RANDOMNESS, NUM_SIGMA_VALUES, build_logup_aux_trace,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main},
};

const COL_X: usize = 0;
const NUM_MAIN_COLS: usize = 1;

// Aux layout: col 0 = σ/n running sum (the one LogUp column, emitting
// nothing); col 1 = the extension-field Horner register.
const NUM_LOGUP_COLS: usize = 1;
const REGISTER_COL: usize = 1;
const AUX_WIDTH: usize = 2;

/// The single LogUp column emits no bus tuples.
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [0];

#[derive(Debug, Default, Clone, Copy)]
struct SpikeAir;

impl BaseAir<Felt> for SpikeAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl LiftedAir<Felt, QuadFelt> for SpikeAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        AUX_WIDTH
    }

    fn num_aux_values(&self) -> usize {
        NUM_SIGMA_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        // Col 0: the σ/n running sum from the (empty) LogUp column.
        let (logup, sigma) = build_logup_aux_trace(&SpikeAir, main, challenges);
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
        (RowMajorMatrix::new(data, AUX_WIDTH), sigma)
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

        // Phase 2: LogUp over one empty column ⇒ σ = 0.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

impl<LB> LookupAir<LB> for SpikeAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_LOGUP_COLS
    }

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
        // One LogUp column that emits no bus tuples: its running sum stays
        // 0, so σ = 0. The register at aux col 1 is excluded from this
        // sum by the `num_logup_cols` bound.
        builder.next_column(|_col| {}, Deg { v: 1, u: 1 });
    }
}

fn rand_qf(rng: &mut impl Rng) -> QuadFelt {
    QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())])
}

#[test]
fn ext_register_verifies_and_stays_out_of_sigma() {
    let mut rng = StdRng::seed_from_u64(0x5217e);
    let n = 16usize;
    let x: Vec<Felt> = (0..n).map(|_| Felt::from(rng.random::<u32>())).collect();
    let main = RowMajorMatrix::new(x, NUM_MAIN_COLS);

    let challenges: [QuadFelt; NUM_RANDOMNESS] = [rand_qf(&mut rng), rand_qf(&mut rng)];

    // σ comes out 0: the register is committed + AIR-constrained but
    // excluded from the running sum by the `num_logup_cols` bound. Without
    // that bound the σ recurrence would fold the register in and this would
    // be non-zero (and `check_local` below would fail).
    let (_, sigma) = SpikeAir.build_aux_trace(&main, &[], &[], &challenges);
    assert_eq!(sigma, vec![QuadFelt::ZERO], "register must not pollute σ");

    // The Horner recurrence and the σ recurrence both hold on the trace.
    crate::tests::check_local(SpikeAir, &main);
}
