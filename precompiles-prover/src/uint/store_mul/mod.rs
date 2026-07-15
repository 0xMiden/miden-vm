//! UintStoreMul chiplet — the uint store and the scaled-MAC relation
//! sharing one row range.
//!
//! Store's period (4) divides mul's period (8), so both progress
//! **simultaneously** on the same rows in disjoint column ranges: main
//! columns 0..18 are exactly [`UintStoreAir`](crate::uint)'s own layout
//! (unchanged), columns 18..44 are exactly
//! [`UintMulAir`](crate::uint::mul)'s own layout (unchanged, shifted by
//! [`MUL_COL_OFFSET`]). Every 8-row cycle, store completes 2 of its own
//! 4-row blocks while mul completes 1 of its own 8-row block — both for
//! real, no mode selector, no cross-gating. Each side keeps its own
//! constraint degree (`lqd = 1`); nothing here raises it.
//!
//! Exactly one running-sum column is committed per AIR, so column 0 is
//! store's own anchor fraction, unchanged; mul's own anchor fraction
//! becomes an ordinary (non-anchor) column instead of folding into
//! store's — both still close into the one shared σ via the standard
//! `acc_next[0] = Σ acc[i]` recurrence, and neither pays the degree cost
//! of physically sharing column 0. Every other LogUp column and both
//! sides' `id` / `S` registers stay independent (separate columns), since
//! store and mul are simultaneously live, not mutually exclusive.
//!
//! The shared height is `max` of what each side natively needs
//! (independently `next_power_of_two`-padded, own padding mechanism —
//! store's self-referential zero blocks, mul's `act = 0` blocks) — not
//! their sum, since they occupy the same rows.

pub mod trace;

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::stark::air::ExtensionBuilder;
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES,
    },
    primitives::byte_pair_lut::Range16Msg,
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::{
        COLUMN_SHAPE as STORE_COLUMN_SHAPE, NUM_LOGUP_COLS as STORE_NUM_LOGUP_COLS, UintLimbsMsg,
        UintValMsg,
        mul::{
            COL_A_PTR as M_COL_A_PTR, COL_ACT as M_COL_ACT, COL_B_PTR as M_COL_B_PTR,
            COL_BORROW as M_COL_BORROW, COL_BOUND_PTR as M_COL_BOUND_PTR,
            COL_KAPPA_A as M_COL_KAPPA_A, COL_R_PTR as M_COL_R_PTR,
            COLUMN_SHAPE as MUL_COLUMN_SHAPE, GAMMA_OFFSET, GAMMA_SLOTS,
            NUM_CELLS as MUL_NUM_CELLS, NUM_GAMMA, NUM_LOGUP_COLS as MUL_NUM_LOGUP_COLS,
            NUM_MAIN_COLS as MUL_NUM_MAIN_COLS, NUM_Q_LIMBS, PERIOD as MUL_PERIOD, ROW_A, ROW_B,
            ROW_C, ROW_P, ROW_Q, ROW_R, S_KEEP, TERM_CELL_C_PTR, TERM_CELL_IS_SUB,
            TERM_CELL_KAPPA_C, TERM_CELL_KAPPA_C_SIGNED, TERM_CELL_MULT, UintMulMsg,
        },
    },
    utils::{current_main, next_main},
};

// COLUMN LAYOUT
// ================================================================================================

// STORE — main cols 0..18, its own original numbering, unshifted.
pub const NUM_CELLS: usize = 16;
pub const COL_PTR: usize = 16;
pub const COL_BOUND_PTR: usize = 17;
pub const STORE_NUM_MAIN_COLS: usize = 18;
pub const HUB_CELL_UINTVAL_MULT: usize = 8;
pub const HUB_CELL_UINTLIMBS_MULT: usize = 9;
pub const TERM_CELL_GAP: usize = 15;
pub const CARRY_LO_BEGIN: usize = 4;
pub const CARRY_HI_BEGIN: usize = 12;
/// Store's own block period: one uint = 4 rows.
pub const STORE_PERIOD: usize = 4;

const PCOL_V_LO: usize = 0;
const PCOL_V_HI: usize = 1;
const PCOL_COMP: usize = 2;
const PCOL_BOUND: usize = 3;

// MUL — main cols 18..44, its own original numbering shifted by
// `MUL_COL_OFFSET`.
pub const MUL_COL_OFFSET: usize = STORE_NUM_MAIN_COLS;

pub const NUM_MAIN_COLS: usize = STORE_NUM_MAIN_COLS + MUL_NUM_MAIN_COLS;
/// The shared block period: `lcm(4, 8) = 8` — store's period divides it,
/// so both progress every cycle.
pub const PERIOD: usize = MUL_PERIOD;
const _: () = assert!(
    MUL_PERIOD.is_multiple_of(STORE_PERIOD),
    "the tiled periodic columns below assume store's period divides mul's"
);
/// How many times store's own period tiles within the shared period.
const STORE_TILE_COUNT: usize = MUL_PERIOD / STORE_PERIOD;

// Periodic columns: mul's 8 one-hots + its `S_KEEP` gate first (indices
// 0..9, unchanged from mul's own reading convention), then store's 4
// one-hots (period 4, tiled twice over the shared period-8 domain).
const PCOL_MUL_S_KEEP: usize = MUL_PERIOD;
const PCOL_STORE_ROLE_BASE: usize = MUL_PERIOD + 1;
const NUM_PERIODIC: usize = MUL_PERIOD + 1 + STORE_PERIOD;

// Aux layout: col 0 = the shared running sum (store's own anchor
// fraction + mul's own anchor fraction, both unconditionally live —
// exactly one running-sum column is committed per AIR); the rest is a
// straight concatenation of store's own column shape (cols 1..8) and
// mul's own column shape (cols 8..; mul's own col 0, its anchor,
// becomes an ordinary column here rather than folding into store's).
// Registers stay independent (store and mul are simultaneously live,
// not mutually exclusive, so their `id` accumulators cannot share a
// column).
pub const NUM_LOGUP_COLS: usize = STORE_NUM_LOGUP_COLS + MUL_NUM_LOGUP_COLS;
pub const STORE_REG_ID: usize = NUM_LOGUP_COLS;
pub const MUL_REG_ID: usize = NUM_LOGUP_COLS + 1;
pub const MUL_REG_S: usize = NUM_LOGUP_COLS + 2;
pub const AUX_WIDTH: usize = NUM_LOGUP_COLS + 3;

const fn column_shape() -> [usize; NUM_LOGUP_COLS] {
    let mut shape = [0usize; NUM_LOGUP_COLS];
    let mut i = 0;
    while i < STORE_NUM_LOGUP_COLS {
        shape[i] = STORE_COLUMN_SHAPE[i];
        i += 1;
    }
    let mut j = 0;
    while j < MUL_NUM_LOGUP_COLS {
        shape[STORE_NUM_LOGUP_COLS + j] = MUL_COLUMN_SHAPE[j];
        j += 1;
    }
    shape
}
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = column_shape();

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct UintStoreMulAir;

impl BaseAir<Felt> for UintStoreMulAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        let mut cols = Vec::with_capacity(NUM_PERIODIC);
        for row in 0..MUL_PERIOD {
            let mut c = vec![Felt::ZERO; MUL_PERIOD];
            c[row] = Felt::ONE;
            cols.push(c);
        }
        cols.push(S_KEEP.iter().map(|&g| Felt::from(g as u32)).collect());
        for role in 0..STORE_PERIOD {
            let mut c = vec![Felt::ZERO; MUL_PERIOD];
            for tile in 0..STORE_TILE_COUNT {
                c[role + tile * STORE_PERIOD] = Felt::ONE;
            }
            cols.push(c);
        }
        cols
    }
}

impl LiftedAir<Felt, QuadFelt> for UintStoreMulAir {
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
        trace::build_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        // ---- STORE (verbatim from `UintStoreAir::eval`, cols 0..10) ----
        {
            let local: [AB::Var; STORE_NUM_MAIN_COLS] = current_main(builder.main(), 0);
            let next: [AB::Var; STORE_NUM_MAIN_COLS] = next_main(builder.main(), 0);

            let (v_lo_sel, v_hi_sel, comp_sel, bound_sel): (
                AB::Expr,
                AB::Expr,
                AB::Expr,
                AB::Expr,
            ) = {
                let p = builder.periodic_values();
                let b = PCOL_STORE_ROLE_BASE;
                (
                    p[b + PCOL_V_LO].into(),
                    p[b + PCOL_V_HI].into(),
                    p[b + PCOL_COMP].into(),
                    p[b + PCOL_BOUND].into(),
                )
            };

            let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
            let mut bp: Vec<AB::ExprEF> = Vec::with_capacity(8);
            bp.push(AB::ExprEF::ONE);
            for i in 1..8 {
                bp.push(bp[i - 1].clone() * beta.clone());
            }

            let id: AB::ExprEF =
                current_main::<_, AB::VarEF, 1>(builder.permutation(), STORE_REG_ID)[0].into();
            let id_next: AB::ExprEF =
                next_main::<_, AB::VarEF, 1>(builder.permutation(), STORE_REG_ID)[0].into();

            let two16: AB::Expr = AB::Expr::from(Felt::from(1u32 << 16));
            let mut recomb_lo07 = AB::ExprEF::ZERO;
            let mut recomb_hi07 = AB::ExprEF::ZERO;
            let mut recomb_hi815 = AB::ExprEF::ZERO;
            let mut direct_lo = AB::ExprEF::ZERO;
            let mut direct_hi = AB::ExprEF::ZERO;
            for k in 0..4 {
                let r07: AB::Expr =
                    AB::Expr::from(local[2 * k]) + two16.clone() * AB::Expr::from(local[2 * k + 1]);
                let r815: AB::Expr = AB::Expr::from(local[8 + 2 * k])
                    + two16.clone() * AB::Expr::from(local[8 + 2 * k + 1]);
                recomb_lo07 += bp[k].clone() * r07.clone();
                recomb_hi07 += bp[4 + k].clone() * r07;
                recomb_hi815 += bp[4 + k].clone() * r815;
                direct_lo += bp[k].clone() * AB::Expr::from(local[k]);
                direct_hi += bp[4 + k].clone() * AB::Expr::from(local[8 + k]);
            }

            let t32: AB::Expr = AB::Expr::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));
            let mut carry_lo_term = AB::ExprEF::ZERO;
            for j in 0..4 {
                let weight: AB::ExprEF = bp[j + 1].clone() - bp[j].clone() * t32.clone();
                carry_lo_term += weight * AB::Expr::from(local[CARRY_LO_BEGIN + j]);
            }
            let mut carry_hi_term = AB::ExprEF::ZERO;
            for j in 4..7 {
                let weight: AB::ExprEF = bp[j + 1].clone() - bp[j].clone() * t32.clone();
                carry_hi_term += weight * AB::Expr::from(local[CARRY_HI_BEGIN + (j - 4)]);
            }

            let contrib: AB::ExprEF = recomb_lo07.clone() * (v_lo_sel.clone() + comp_sel.clone())
                + recomb_hi07 * v_hi_sel.clone()
                + recomb_hi815 * comp_sel.clone()
                + (carry_lo_term.clone() - direct_lo.clone() + carry_hi_term.clone()
                    - direct_hi.clone())
                    * bound_sel.clone();

            builder.when_first_row().assert_zero_ext(id.clone());
            builder.when_transition().assert_zero_ext(id_next - id.clone() - contrib);

            let bound_own: AB::ExprEF = carry_lo_term - direct_lo + carry_hi_term - direct_hi;
            builder.assert_zero_ext((id + bound_own) * bound_sel.clone());

            for &cell in
                [CARRY_LO_BEGIN, CARRY_LO_BEGIN + 1, CARRY_LO_BEGIN + 2, CARRY_LO_BEGIN + 3].iter()
            {
                let lj: AB::Expr = local[cell].into();
                builder.assert_zero(bound_sel.clone() * lj.clone() * (AB::Expr::ONE - lj));
            }
            for &cell in [CARRY_HI_BEGIN, CARRY_HI_BEGIN + 1, CARRY_HI_BEGIN + 2].iter() {
                let lj: AB::Expr = local[cell].into();
                builder.assert_zero(bound_sel.clone() * lj.clone() * (AB::Expr::ONE - lj));
            }

            let not_term: AB::Expr = AB::Expr::ONE - bound_sel.clone();
            for col in [COL_PTR, COL_BOUND_PTR] {
                let here: AB::Expr = local[col].into();
                let there: AB::Expr = next[col].into();
                builder.assert_zero(not_term.clone() * (there - here));
            }

            let gap: AB::Expr = local[TERM_CELL_GAP].into();
            let ptr_here: AB::Expr = local[COL_PTR].into();
            let ptr_next: AB::Expr = next[COL_PTR].into();
            builder
                .when_transition()
                .assert_zero(bound_sel * (gap + ptr_here + AB::Expr::ONE - ptr_next));
        }

        // ---- MUL (verbatim from `UintMulAir::eval`, cols `MUL_COL_OFFSET`..`NUM_MAIN_COLS`) ----
        {
            let local: [AB::Var; MUL_NUM_MAIN_COLS] = current_main(builder.main(), MUL_COL_OFFSET);
            let next: [AB::Var; MUL_NUM_MAIN_COLS] = next_main(builder.main(), MUL_COL_OFFSET);

            // Mul's own periodic reading convention: indices 0..8 = role
            // one-hots, 8 = `S_KEEP` — unchanged, since mul's periodic
            // columns sit first in `periodic_columns()`.
            let sel: [AB::Expr; MUL_PERIOD + 1] = {
                let p = builder.periodic_values();
                array::from_fn(|i| p[i].into())
            };

            let beta: AB::ExprEF = builder.permutation_randomness()[1].into();
            let mut bp: Vec<AB::ExprEF> = Vec::with_capacity(NUM_GAMMA + 1);
            bp.push(AB::ExprEF::ONE);
            for i in 1..NUM_GAMMA + 1 {
                bp.push(bp[i - 1].clone() * beta.clone());
            }
            let t16: AB::Expr = AB::Expr::from(Felt::from(1u32 << 16));
            let x_minus_t: AB::ExprEF = beta - t16.clone();
            let offset: AB::Expr = AB::Expr::from(Felt::from(GAMMA_OFFSET));

            let kappa_a: AB::Expr = local[M_COL_KAPPA_A].into();
            let act: AB::Expr = local[M_COL_ACT].into();
            let kappa_c_signed_local: AB::Expr = local[TERM_CELL_KAPPA_C_SIGNED].into();

            let id: AB::ExprEF =
                current_main::<_, AB::VarEF, 1>(builder.permutation(), MUL_REG_ID)[0].into();
            let id_next: AB::ExprEF =
                next_main::<_, AB::VarEF, 1>(builder.permutation(), MUL_REG_ID)[0].into();
            let s: AB::ExprEF =
                current_main::<_, AB::VarEF, 1>(builder.permutation(), MUL_REG_S)[0].into();
            let s_next: AB::ExprEF =
                next_main::<_, AB::VarEF, 1>(builder.permutation(), MUL_REG_S)[0].into();

            let full16_sum: AB::ExprEF = (0..16)
                .fold(AB::ExprEF::ZERO, |acc, i| acc + bp[i].clone() * AB::Expr::from(local[i]));
            let full_q_sum: AB::ExprEF = (0..NUM_Q_LIMBS)
                .fold(AB::ExprEF::ZERO, |acc, i| acc + bp[i].clone() * AB::Expr::from(local[i]));
            let val_sum: AB::ExprEF = (0..8).fold(AB::ExprEF::ZERO, |acc, m| {
                acc + bp[2 * m].clone() * AB::Expr::from(local[m])
            });

            let build: AB::ExprEF = full16_sum.clone() * (sel[ROW_A].clone() * kappa_a)
                + full16_sum.clone() * sel[ROW_P].clone();
            let keep: AB::Expr = sel[PCOL_MUL_S_KEEP].clone();
            builder.when_first_row().assert_zero_ext(s.clone());
            builder.when_transition().assert_zero_ext(s_next - s.clone() * keep - build);

            let product = s.clone() * full16_sum.clone() * sel[ROW_B].clone();
            let quotient = (s + AB::ExprEF::ONE) * full_q_sum * sel[ROW_Q].clone();
            let linear = val_sum.clone() * (sel[ROW_C].clone() * kappa_c_signed_local.clone())
                - val_sum.clone() * sel[ROW_R].clone();

            let mut carries = AB::ExprEF::ZERO;
            for (slot, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
                let k = slot / 2;
                let mut w = x_minus_t.clone() * bp[k].clone();
                if slot % 2 == 1 {
                    w *= t16.clone();
                }
                let mut gated: AB::Expr = sel[row].clone() * AB::Expr::from(local[cell]);
                if slot % 2 == 0 {
                    gated -= sel[row].clone() * act.clone() * offset.clone();
                }
                carries += w * gated;
            }

            let borrow: AB::Expr = local[M_COL_BORROW].into();
            let borrow_contrib: AB::ExprEF =
                (full16_sum + AB::ExprEF::ONE) * (sel[ROW_P].clone() * borrow.clone());

            let contrib: AB::ExprEF = product - quotient + linear + carries + borrow_contrib;
            builder.when_first_row().assert_zero_ext(id.clone());
            builder.when_transition().assert_zero_ext(id_next - id.clone() - contrib);

            // The `c` row folds the closing check onto its own last-operand
            // row, exactly like `UintMulAir::eval` — see that function's
            // comment for the full rationale.
            let mut c_own: AB::ExprEF = val_sum * kappa_c_signed_local.clone();
            for (slot, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
                if row == ROW_C {
                    let k = slot / 2;
                    let mut w = x_minus_t.clone() * bp[k].clone();
                    if slot % 2 == 1 {
                        w *= t16.clone();
                    }
                    let mut gated: AB::Expr = AB::Expr::from(local[cell]);
                    if slot % 2 == 0 {
                        gated -= act.clone() * offset.clone();
                    }
                    c_own += w * gated;
                }
            }
            builder.assert_zero_ext((id + c_own) * sel[ROW_C].clone());

            builder.assert_zero(act.clone() * (AB::Expr::ONE - act.clone()));

            let is_sub: AB::Expr = local[TERM_CELL_IS_SUB].into();
            builder.assert_zero(
                sel[ROW_C].clone() * is_sub.clone() * (AB::Expr::ONE - is_sub.clone()),
            );

            let kappa_c_local: AB::Expr = local[TERM_CELL_KAPPA_C].into();
            let c_sign_local: AB::Expr =
                AB::Expr::ONE - AB::Expr::from(Felt::from(2u32)) * is_sub.clone();
            builder.assert_zero(
                sel[ROW_C].clone() * (kappa_c_signed_local - kappa_c_local * c_sign_local),
            );

            let two = AB::Expr::from(Felt::from(2u32));
            builder.assert_zero(
                borrow.clone() * (borrow.clone() - AB::Expr::ONE) * (borrow.clone() - two),
            );
            builder.assert_zero(sel[ROW_C].clone() * borrow * (AB::Expr::ONE - is_sub));

            builder.assert_zero(
                sel[ROW_C].clone() * (AB::Expr::ONE - act) * local[TERM_CELL_MULT].into(),
            );

            let not_term: AB::Expr = AB::Expr::ONE - sel[ROW_C].clone();
            for col in [
                M_COL_A_PTR,
                M_COL_B_PTR,
                M_COL_R_PTR,
                M_COL_BOUND_PTR,
                M_COL_KAPPA_A,
                M_COL_ACT,
                M_COL_BORROW,
            ] {
                let here: AB::Expr = local[col].into();
                let there: AB::Expr = next[col].into();
                builder.assert_zero(not_term.clone() * (there - here));
            }
        }

        // Phase 2: LogUp.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for UintStoreMulAir
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
        // STORE's own window.
        let local_s: [LB::Var; STORE_NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next_s: [LB::Var; STORE_NUM_MAIN_COLS] = next_main(builder.main(), 0);
        let (v_lo_sel, v_hi_sel, comp_sel, bound_sel): (LB::Expr, LB::Expr, LB::Expr, LB::Expr) = {
            let p = builder.periodic_values();
            let b = PCOL_STORE_ROLE_BASE;
            (
                p[b + PCOL_V_LO].into(),
                p[b + PCOL_V_HI].into(),
                p[b + PCOL_COMP].into(),
                p[b + PCOL_BOUND].into(),
            )
        };
        let store_ptr: LB::Expr = local_s[COL_PTR].into();
        let store_bound_ptr: LB::Expr = local_s[COL_BOUND_PTR].into();
        let neg_mult_next: LB::Expr = LB::Expr::ZERO - next_s[HUB_CELL_UINTVAL_MULT].into();
        let neg_mult_here: LB::Expr = LB::Expr::ZERO - local_s[HUB_CELL_UINTVAL_MULT].into();
        let two16: LB::Expr = LB::Expr::from(Felt::from(1u32 << 16));
        let recomb: [LB::Expr; 4] =
            array::from_fn(|k| local_s[2 * k].into() + two16.clone() * local_s[2 * k + 1].into());
        let direct_lo: [LB::Expr; 4] = array::from_fn(|k| local_s[k].into());
        let direct_hi: [LB::Expr; 4] = array::from_fn(|k| local_s[8 + k].into());

        let provide_deg = Deg { v: 2, u: 1 };
        let consume_deg = Deg { v: 1, u: 1 };
        let pair_deg = Deg { v: 3, u: 2 };
        let raw: [LB::Expr; 8] = array::from_fn(|j| local_s[j].into());
        let neg_limbs_mult_next: LB::Expr = LB::Expr::ZERO - next_s[HUB_CELL_UINTLIMBS_MULT].into();
        let neg_limbs_mult_here: LB::Expr =
            LB::Expr::ZERO - local_s[HUB_CELL_UINTLIMBS_MULT].into();
        let rc_deg = Deg { v: 1, u: 1 };

        // MUL's own window.
        let local_m: [LB::Var; MUL_NUM_MAIN_COLS] = current_main(builder.main(), MUL_COL_OFFSET);
        let sel: [LB::Expr; MUL_PERIOD] = {
            let p = builder.periodic_values();
            array::from_fn(|i| p[i].into())
        };
        let a_ptr: LB::Expr = local_m[M_COL_A_PTR].into();
        let b_ptr: LB::Expr = local_m[M_COL_B_PTR].into();
        let r_ptr: LB::Expr = local_m[M_COL_R_PTR].into();
        let mul_bound_ptr: LB::Expr = local_m[M_COL_BOUND_PTR].into();
        let mul_kappa_a: LB::Expr = local_m[M_COL_KAPPA_A].into();
        let mul_act: LB::Expr = local_m[M_COL_ACT].into();
        let c_ptr_local: LB::Expr = local_m[TERM_CELL_C_PTR].into();
        let kappa_c_local: LB::Expr = local_m[TERM_CELL_KAPPA_C].into();
        let neg_mult: LB::Expr = LB::Expr::ZERO - local_m[TERM_CELL_MULT].into();
        let mul_provide_deg = Deg { v: 2, u: 1 };
        let mul_consume_deg = Deg { v: 2, u: 1 };
        let mul_rc_deg = Deg { v: 2, u: 1 };
        let raw_m_lo: [LB::Expr; 8] = array::from_fn(|i| local_m[i].into());
        let raw_m_hi: [LB::Expr; 8] = array::from_fn(|i| local_m[8 + i].into());
        let val_lo: [LB::Expr; 4] = array::from_fn(|k| local_m[k].into());
        let val_hi: [LB::Expr; 4] = array::from_fn(|k| local_m[4 + k].into());

        // col 0: the running sum — store's own anchor fraction, unpaired
        // and unchanged (not folded with mul's, which would multiply the
        // two groups' (u, v) together and push the closing constraint
        // past the lqd = 1 budget for no width gain).
        builder.next_column(
            |col| {
                col.group(
                    "uintval",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "provide-lo",
                                    neg_mult_next * v_lo_sel.clone(),
                                    UintValMsg {
                                        ptr: store_ptr.clone(),
                                        bound_ptr: store_bound_ptr.clone(),
                                        offset: LB::Expr::ZERO,
                                        limbs: recomb.clone(),
                                    },
                                    provide_deg,
                                );
                            },
                            provide_deg,
                        );
                    },
                    provide_deg,
                );
            },
            provide_deg,
        );

        // cols 1..: store's own remaining columns, unchanged in shape.
        builder.next_column(
            |col| {
                col.group(
                    "uintval",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "provide-hi",
                                    neg_mult_here * v_hi_sel.clone(),
                                    UintValMsg {
                                        ptr: store_ptr.clone(),
                                        bound_ptr: store_bound_ptr.clone(),
                                        offset: LB::Expr::ONE,
                                        limbs: recomb.clone(),
                                    },
                                    provide_deg,
                                );
                                b.insert(
                                    "consume-lo",
                                    bound_sel.clone(),
                                    UintValMsg {
                                        ptr: store_bound_ptr.clone(),
                                        bound_ptr: store_bound_ptr.clone(),
                                        offset: LB::Expr::ZERO,
                                        limbs: direct_lo.clone(),
                                    },
                                    consume_deg,
                                );
                            },
                            pair_deg,
                        );
                    },
                    pair_deg,
                );
            },
            pair_deg,
        );
        builder.next_column(
            |col| {
                col.group(
                    "uintval",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-hi",
                                    bound_sel.clone(),
                                    UintValMsg {
                                        ptr: store_bound_ptr.clone(),
                                        bound_ptr: store_bound_ptr.clone(),
                                        offset: LB::Expr::ONE,
                                        limbs: direct_hi.clone(),
                                    },
                                    consume_deg,
                                );
                                b.insert(
                                    "range16-gap",
                                    bound_sel.clone(),
                                    Range16Msg { w: local_s[TERM_CELL_GAP].into() },
                                    consume_deg,
                                );
                            },
                            pair_deg,
                        );
                    },
                    pair_deg,
                );
            },
            pair_deg,
        );
        let store_cell_gate = |cell: usize| -> LB::Expr {
            if cell < 8 {
                v_lo_sel.clone() + v_hi_sel.clone() + comp_sel.clone()
            } else {
                comp_sel.clone()
            }
        };
        let store_cell_specs: Vec<(LB::Expr, usize)> =
            (0..NUM_CELLS).map(|cell| (store_cell_gate(cell), cell)).collect();
        for group in store_cell_specs
            .chunks(2)
            .map(<[(<LB as LookupBuilder>::Expr, usize)]>::to_vec)
            .collect::<Vec<_>>()
        {
            builder.next_column(
                |col| {
                    col.group(
                        "range16",
                        |g| {
                            g.batch(
                                "f",
                                LB::Expr::ONE,
                                |b| {
                                    for (mult, cell) in group {
                                        b.insert(
                                            "range16-limb",
                                            mult,
                                            Range16Msg { w: local_s[cell].into() },
                                            rc_deg,
                                        );
                                    }
                                },
                                pair_deg,
                            );
                        },
                        pair_deg,
                    );
                },
                pair_deg,
            );
        }
        builder.next_column(
            |col| {
                col.group(
                    "uintlimbs",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "provide-raw-lo",
                                    neg_limbs_mult_next * v_lo_sel,
                                    UintLimbsMsg {
                                        ptr: store_ptr.clone(),
                                        bound_ptr: store_bound_ptr.clone(),
                                        offset: LB::Expr::ZERO,
                                        limbs: raw.clone(),
                                    },
                                    provide_deg,
                                );
                                b.insert(
                                    "provide-raw-hi",
                                    neg_limbs_mult_here * v_hi_sel,
                                    UintLimbsMsg {
                                        ptr: store_ptr,
                                        bound_ptr: store_bound_ptr,
                                        offset: LB::Expr::ONE,
                                        limbs: raw,
                                    },
                                    provide_deg,
                                );
                            },
                            pair_deg,
                        );
                    },
                    pair_deg,
                );
            },
            pair_deg,
        );

        // col 8: mul's original col 0 (the `UintMul` provide) — placed
        // here as an ordinary (non-anchor) column, since it still folds
        // into the shared σ via the standard `acc_next[0] = Σ acc[i]`
        // recurrence without needing to physically sit at column 0.
        builder.next_column(
            |col| {
                col.group(
                    "uintmul",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "provide-uintmul",
                                    neg_mult.clone() * sel[ROW_C].clone(),
                                    UintMulMsg {
                                        kappa_a: mul_kappa_a.clone(),
                                        kappa_c: kappa_c_local.clone(),
                                        a_ptr: a_ptr.clone(),
                                        b_ptr: b_ptr.clone(),
                                        c_ptr: c_ptr_local.clone(),
                                        r_ptr: r_ptr.clone(),
                                        bound_ptr: mul_bound_ptr.clone(),
                                        is_sub: local_m[TERM_CELL_IS_SUB].into(),
                                    },
                                    mul_provide_deg,
                                );
                            },
                            mul_provide_deg,
                        );
                    },
                    mul_provide_deg,
                );
            },
            mul_provide_deg,
        );

        // cols 9..: mul's own remaining columns, unchanged in shape.
        let raw_consumes: Vec<(LB::Expr, LB::Expr, LB::Expr, [LB::Expr; 8])> =
            [(ROW_A, a_ptr.clone()), (ROW_B, b_ptr.clone()), (ROW_P, mul_bound_ptr.clone())]
                .into_iter()
                .flat_map(|(row, ptr)| {
                    let mult = sel[row].clone() * mul_act.clone();
                    [
                        (mult.clone(), ptr.clone(), LB::Expr::ZERO, raw_m_lo.clone()),
                        (mult, ptr, LB::Expr::ONE, raw_m_hi.clone()),
                    ]
                })
                .collect();
        for group in raw_consumes
            .chunks(2)
            .map(
                <[(
                    <LB as LookupBuilder>::Expr,
                    <LB as LookupBuilder>::Expr,
                    <LB as LookupBuilder>::Expr,
                    [<LB as LookupBuilder>::Expr; 8],
                )]>::to_vec,
            )
            .collect::<Vec<_>>()
        {
            builder.next_column(
                |col| {
                    col.group(
                        "uintlimbs",
                        |g| {
                            g.batch(
                                "f",
                                LB::Expr::ONE,
                                |b| {
                                    for (mult, ptr, off, limbs) in group {
                                        b.insert(
                                            "consume-uintlimbs",
                                            mult,
                                            UintLimbsMsg {
                                                ptr,
                                                bound_ptr: mul_bound_ptr.clone(),
                                                offset: off,
                                                limbs,
                                            },
                                            mul_consume_deg,
                                        );
                                    }
                                },
                                pair_deg,
                            );
                        },
                        pair_deg,
                    );
                },
                pair_deg,
            );
        }

        let mul_raw16_gate = |cell: usize| -> LB::Expr {
            if cell < NUM_Q_LIMBS {
                sel[ROW_Q].clone()
            } else {
                LB::Expr::ZERO
            }
        };
        let mul_gamma_gate = |cell: usize| -> LB::Expr {
            GAMMA_SLOTS
                .iter()
                .filter(|&&(_, c)| c == cell)
                .fold(LB::Expr::ZERO, |acc, &(row, _)| acc + sel[row].clone())
        };
        let cell_gate = |cell: usize| -> LB::Expr { mul_raw16_gate(cell) + mul_gamma_gate(cell) };
        let cell_specs: Vec<(LB::Expr, usize)> = (0..MUL_NUM_CELLS)
            .map(|cell| (cell_gate(cell) * mul_act.clone(), cell))
            .collect();
        for group in cell_specs
            .chunks(2)
            .map(<[(<LB as LookupBuilder>::Expr, usize)]>::to_vec)
            .collect::<Vec<_>>()
        {
            builder.next_column(
                |col| {
                    col.group(
                        "range16-cells",
                        |g| {
                            g.batch(
                                "f",
                                LB::Expr::ONE,
                                |b| {
                                    for (mult, cell) in group {
                                        b.insert(
                                            "range16-cell",
                                            mult,
                                            Range16Msg { w: local_m[cell].into() },
                                            mul_rc_deg,
                                        );
                                    }
                                },
                                pair_deg,
                            );
                        },
                        pair_deg,
                    );
                },
                pair_deg,
            );
        }

        builder.next_column(
            |col| {
                col.group(
                    "range16-kappa",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "range16-kappa-a",
                                    sel[ROW_C].clone() * mul_act.clone(),
                                    Range16Msg { w: mul_kappa_a.clone() },
                                    mul_rc_deg,
                                );
                                b.insert(
                                    "range16-kappa-c",
                                    sel[ROW_C].clone() * mul_act.clone(),
                                    Range16Msg { w: kappa_c_local.clone() },
                                    mul_rc_deg,
                                );
                            },
                            pair_deg,
                        );
                    },
                    pair_deg,
                );
            },
            pair_deg,
        );
        let val_consumes: [(usize, LB::Expr); 2] = [(ROW_R, r_ptr.clone()), (ROW_C, c_ptr_local)];
        for (row, ptr) in val_consumes {
            builder.next_column(
                |col| {
                    col.group(
                        "uintval",
                        |g| {
                            g.batch(
                                "f",
                                LB::Expr::ONE,
                                |b| {
                                    for (off, half) in [
                                        (LB::Expr::ZERO, val_lo.clone()),
                                        (LB::Expr::ONE, val_hi.clone()),
                                    ] {
                                        b.insert(
                                            "consume-uintval",
                                            sel[row].clone() * mul_act.clone(),
                                            UintValMsg {
                                                ptr: ptr.clone(),
                                                bound_ptr: mul_bound_ptr.clone(),
                                                offset: off,
                                                limbs: half,
                                            },
                                            mul_consume_deg,
                                        );
                                    }
                                },
                                pair_deg,
                            );
                        },
                        pair_deg,
                    );
                },
                pair_deg,
            );
        }
    }
}
