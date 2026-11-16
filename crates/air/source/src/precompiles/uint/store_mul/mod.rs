//! UintStoreMul chiplet — the uint store and the scaled-MAC relation
//! sharing one row range.
//!
//! Store's period (4) divides mul's period (8), so both progress simultaneously on the same rows
//! in disjoint column ranges. Main columns 0..18 use [`UintStoreAir`](crate::precompiles::uint)'s
//! layout, and columns 18..44 use [`UintMulAir`](crate::precompiles::uint::mul)'s layout translated
//! by [`MUL_COL_OFFSET`]. Every 8-row cycle, store completes two 4-row blocks while mul completes
//! one 8-row block. Both constraint systems are active on every shared row and retain
//! `log_quotient_degree = 1`.
//!
//! Two lookup columns select mutually exclusive interactions using the fixed eight-row schedule.
//! The remaining interactions share nineteen two-fraction columns. All close at degree three;
//! column 0 also carries the centered running sum. Both sides' `id` / `S` registers remain
//! independent because store and mul are simultaneously live.
//!
//! The shared height is the larger of the two independently power-of-two-padded component heights.
//! Store pads with self-referential zero blocks; mul pads with inactive (`act = 0`) blocks.

mod aux;

use alloc::{borrow::Cow, vec, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
};
use miden_stark::{
    air,
    air::LiftedAirBuilder as _,
    lookup::{self, Deg, LookupBatch, LookupColumn, LookupGroup},
};
use miden_utils_sync::LazyLock;
use p3_field::Dup;

use crate::precompiles::{
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS, frac_col},
    primitives::byte_pair_lut::Range16Msg,
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::{
        UintLimbsMsg, UintValMsg,
        mul::{
            COL_A_PTR as M_COL_A_PTR, COL_ACT as M_COL_ACT, COL_B_PTR as M_COL_B_PTR,
            COL_BORROW as M_COL_BORROW, COL_BOUND_PTR as M_COL_BOUND_PTR,
            COL_KAPPA_A as M_COL_KAPPA_A, COL_R_PTR as M_COL_R_PTR, GAMMA_OFFSET, GAMMA_SLOTS,
            NUM_CELLS as MUL_NUM_CELLS, NUM_GAMMA, NUM_MAIN_COLS as MUL_NUM_MAIN_COLS, NUM_Q_LIMBS,
            PERIOD as MUL_PERIOD, ROW_A, ROW_B, ROW_C, ROW_P, ROW_Q, ROW_R, S_KEEP,
            TERM_CELL_C_PTR, TERM_CELL_IS_SUB, TERM_CELL_KAPPA_C, TERM_CELL_KAPPA_C_SIGNED,
            TERM_CELL_MULT, UintMulMsg,
        },
    },
};

// COLUMN LAYOUT
// ================================================================================================

// STORE — main columns 0..18 using UintStoreAir's numbering.
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

// MUL — main columns 18..44 using UintMulAir's numbering plus `MUL_COL_OFFSET`.
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
// 0..9, following UintMulAir's indexing), then store's 4
// one-hots (period 4, tiled twice over the shared period-8 domain).
const PCOL_MUL_S_KEEP: usize = MUL_PERIOD;
const PCOL_STORE_ROLE_BASE: usize = MUL_PERIOD + 1;
const NUM_PERIODIC: usize = MUL_PERIOD + 1 + STORE_PERIOD;

// Two selected singleton groups and nineteen ordinary pairs. Column 0 also carries the centered
// running sum. Store and mul keep separate registers because their computations overlap in time.
pub const NUM_LOGUP_COLS: usize = 21;
pub const STORE_REG_ID: usize = NUM_LOGUP_COLS;
pub const MUL_REG_ID: usize = NUM_LOGUP_COLS + 1;
pub const MUL_REG_S: usize = NUM_LOGUP_COLS + 2;
pub const AUX_WIDTH: usize = NUM_LOGUP_COLS + 3;

const fn column_shape() -> [usize; NUM_LOGUP_COLS] {
    let mut shape = [2usize; NUM_LOGUP_COLS];
    shape[0] = 1;
    shape[1] = 1;
    shape
}
pub(crate) const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = column_shape();

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct UintStoreMulAir;

static PERIODIC_COLUMNS: LazyLock<Vec<Vec<Felt>>> = LazyLock::new(|| {
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
});

// LOOKUP AIR
// ================================================================================================

impl<LB> lookup::LookupAir<LB> for UintStoreMulAir
where
    LB: lookup::LookupBuilder<F = Felt>,
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

    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        // STORE's own window.
        let local_s: &[LB::Expr; STORE_NUM_MAIN_COLS] = frame.main.current[..STORE_NUM_MAIN_COLS]
            .try_into()
            .expect("uint lookup row band");
        let next_s: &[LB::Expr; STORE_NUM_MAIN_COLS] =
            frame.main.next[..STORE_NUM_MAIN_COLS].try_into().expect("uint lookup row band");
        let (v_lo_sel, v_hi_sel, comp_sel, bound_sel): (LB::Expr, LB::Expr, LB::Expr, LB::Expr) = {
            let p = frame.periodic;
            let b = PCOL_STORE_ROLE_BASE;
            (
                p[b + PCOL_V_LO].dup(),
                p[b + PCOL_V_HI].dup(),
                p[b + PCOL_COMP].dup(),
                p[b + PCOL_BOUND].dup(),
            )
        };
        let store_ptr = local_s[COL_PTR].dup();
        let store_bound_ptr = local_s[COL_BOUND_PTR].dup();
        let neg_val_mult = -next_s[HUB_CELL_UINTVAL_MULT].dup();
        let neg_limbs_val_mult = -next_s[HUB_CELL_UINTLIMBS_MULT].dup();
        let recomb: [LB::Expr; 8] = array::from_fn(|k| {
            if k < 4 {
                local_s[2 * k].dup() + local_s[2 * k + 1].mul_2exp_u64(16)
            } else {
                let k = k - 4;
                next_s[2 * k].dup() + next_s[2 * k + 1].mul_2exp_u64(16)
            }
        });
        let direct: [LB::Expr; 8] =
            array::from_fn(|k| if k < 4 { local_s[k].dup() } else { local_s[4 + k].dup() });

        let provide_deg = Deg { v: 2, u: 1 };
        let consume_deg = Deg { v: 1, u: 1 };
        let store_pair_deg = Deg { v: 2, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };
        let raw: [LB::Expr; 16] =
            array::from_fn(|j| if j < 8 { local_s[j].dup() } else { next_s[j - 8].dup() });
        let rc_deg = Deg { v: 1, u: 1 };

        // MUL's own window.
        let local_m: &[LB::Expr; MUL_NUM_MAIN_COLS] = frame.main.current
            [MUL_COL_OFFSET..MUL_COL_OFFSET + MUL_NUM_MAIN_COLS]
            .try_into()
            .expect("declared AIR row band");
        let sel: &[LB::Expr; MUL_PERIOD] =
            frame.periodic[..MUL_PERIOD].try_into().expect("declared AIR row band");
        let a_ptr = local_m[M_COL_A_PTR].dup();
        let b_ptr = local_m[M_COL_B_PTR].dup();
        let r_ptr = local_m[M_COL_R_PTR].dup();
        let mul_bound_ptr = local_m[M_COL_BOUND_PTR].dup();
        let mul_kappa_a = local_m[M_COL_KAPPA_A].dup();
        let mul_act = local_m[M_COL_ACT].dup();
        let c_ptr_local = local_m[TERM_CELL_C_PTR].dup();
        let kappa_c_local = local_m[TERM_CELL_KAPPA_C].dup();
        let neg_mult = -local_m[TERM_CELL_MULT].dup();
        let mul_consume_deg = Deg { v: 2, u: 1 };
        let mul_rc_deg = Deg { v: 2, u: 1 };
        let raw_m_lo: [LB::Expr; 8] = array::from_fn(|i| local_m[i].dup());
        let raw_m_hi: [LB::Expr; 8] = array::from_fn(|i| local_m[8 + i].dup());
        let val_lo: [LB::Expr; 4] = array::from_fn(|k| local_m[k].dup());
        let val_hi: [LB::Expr; 4] = array::from_fn(|k| local_m[4 + k].dup());

        let mul_raw_limbs: [LB::Expr; 16] = array::from_fn(|i| {
            if i < 8 {
                raw_m_lo[i].clone()
            } else {
                raw_m_hi[i - 8].clone()
            }
        });
        let val_full: [LB::Expr; 8] = array::from_fn(|i| {
            if i < 4 {
                val_lo[i].clone()
            } else {
                val_hi[i - 4].clone()
            }
        });
        let cell_gate = |cell: usize| -> LB::Expr {
            let raw16 = if cell < NUM_Q_LIMBS {
                sel[ROW_Q].clone()
            } else {
                LB::Expr::ZERO
            };
            GAMMA_SLOTS
                .iter()
                .filter(|&&(_, c)| c == cell)
                .map(|&(row, _)| sel[row].dup())
                .sum::<LB::Expr>()
                + raw16
        };
        let selected_deg = Deg { v: 2, u: 2 };

        // Supports are {0,4}, {2,6}, and {7}. A selected group adds its gated denominator
        // without multiplying the alternatives; its closing constraint has degree three.
        builder.next_column(
            |col| {
                col.group(
                    "store-and-kappa",
                    |g| {
                        g.insert(
                            "provide",
                            v_lo_sel.clone(),
                            neg_val_mult,
                            || UintValMsg {
                                ptr: store_ptr.clone(),
                                bound_ptr: store_bound_ptr.clone(),
                                limbs: recomb,
                            },
                            selected_deg,
                        );
                        g.add(
                            "range16-limb",
                            comp_sel.clone(),
                            || Range16Msg { w: local_s[8].dup() },
                            Deg { v: 1, u: 2 },
                        );
                        g.insert(
                            "range16-kappa-a",
                            sel[ROW_C].clone(),
                            mul_act.clone(),
                            || Range16Msg { w: mul_kappa_a.clone() },
                            selected_deg,
                        );
                    },
                    selected_deg,
                )
            },
            selected_deg,
        );

        // Every row selects exactly one alternative: A, B, bound, cell 0, result, or provide.
        // Cell 0 is checked on Q (row 3) and the gamma-only rows 5 and 6.
        builder.next_column(
            |col| {
                col.group(
                    "mul-row-relation",
                    |g| {
                        for (row, ptr) in [
                            (ROW_A, a_ptr.clone()),
                            (ROW_B, b_ptr.clone()),
                            (ROW_P, mul_bound_ptr.clone()),
                        ] {
                            g.insert(
                                "consume-uintlimbs",
                                sel[row].clone(),
                                mul_act.clone(),
                                || UintLimbsMsg {
                                    ptr,
                                    bound_ptr: mul_bound_ptr.clone(),
                                    limbs: mul_raw_limbs.clone(),
                                },
                                selected_deg,
                            );
                        }
                        g.insert(
                            "range16-cell",
                            cell_gate(0),
                            mul_act.clone(),
                            || Range16Msg { w: local_m[0].dup() },
                            selected_deg,
                        );
                        g.insert(
                            "consume-uintval",
                            sel[ROW_R].clone(),
                            mul_act.clone(),
                            || UintValMsg {
                                ptr: r_ptr.clone(),
                                bound_ptr: mul_bound_ptr.clone(),
                                limbs: val_full.clone(),
                            },
                            selected_deg,
                        );
                        g.insert(
                            "provide-uintmul",
                            sel[ROW_C].clone(),
                            neg_mult,
                            || UintMulMsg {
                                kappa_a: mul_kappa_a,
                                kappa_c: kappa_c_local.clone(),
                                a_ptr,
                                b_ptr,
                                c_ptr: c_ptr_local.clone(),
                                r_ptr,
                                bound_ptr: mul_bound_ptr.clone(),
                                is_sub: local_m[TERM_CELL_IS_SUB].dup(),
                            },
                            selected_deg,
                        );
                    },
                    selected_deg,
                )
            },
            selected_deg,
        );

        frac_col!(
            builder,
            "uintval",
            store_pair_deg,
            (
                "consume",
                bound_sel.clone(),
                UintValMsg {
                    ptr: store_bound_ptr.clone(),
                    bound_ptr: store_bound_ptr.clone(),
                    limbs: direct,
                },
                consume_deg
            ),
            (
                "range16-gap",
                bound_sel,
                Range16Msg { w: local_s[TERM_CELL_GAP].dup() },
                consume_deg
            ),
        );
        // Store cells 0..8 are live on three row kinds; cells 9..15 are live only on COMP.
        // Cell 8 belongs to the selected group and cell 15 pairs with the raw-limbs provide.
        for cells in (0..8)
            .step_by(2)
            .map(|i| [i, i + 1])
            .chain((9..15).step_by(2).map(|i| [i, i + 1]))
        {
            let gate = if cells[0] < 8 {
                v_lo_sel.clone() + v_hi_sel.clone() + comp_sel.clone()
            } else {
                comp_sel.clone()
            };
            frac_col!(
                builder,
                "store-range16",
                store_pair_deg,
                ("range16-limb", gate.clone(), Range16Msg { w: local_s[cells[0]].dup() }, rc_deg),
                ("range16-limb", gate, Range16Msg { w: local_s[cells[1]].dup() }, rc_deg),
            );
        }
        frac_col!(
            builder,
            "store-tail",
            pair_deg,
            ("range16-limb", comp_sel, Range16Msg { w: local_s[15].dup() }, rc_deg),
            (
                "provide-raw",
                neg_limbs_val_mult * v_lo_sel,
                UintLimbsMsg {
                    ptr: store_ptr,
                    bound_ptr: store_bound_ptr,
                    limbs: raw
                },
                provide_deg
            ),
        );
        // Mul cell 0 is selected above. The other eighteen cells form nine ordinary pairs.
        for first in (1..MUL_NUM_CELLS).step_by(2) {
            frac_col!(
                builder,
                "mul-range16",
                pair_deg,
                (
                    "range16-cell",
                    cell_gate(first) * mul_act.clone(),
                    Range16Msg { w: local_m[first].dup() },
                    mul_rc_deg
                ),
                (
                    "range16-cell",
                    cell_gate(first + 1) * mul_act.clone(),
                    Range16Msg { w: local_m[first + 1].dup() },
                    mul_rc_deg
                ),
            );
        }
        frac_col!(
            builder,
            "mul-term",
            pair_deg,
            (
                "range16-kappa-c",
                sel[ROW_C].clone() * mul_act.clone(),
                Range16Msg { w: kappa_c_local },
                mul_rc_deg
            ),
            (
                "consume-uintval",
                sel[ROW_C].clone() * mul_act,
                UintValMsg {
                    ptr: c_ptr_local,
                    bound_ptr: mul_bound_ptr,
                    limbs: val_full
                },
                mul_consume_deg
            ),
        );
    }
}

impl air::LiftedAir for UintStoreMulAir {
    type F = Felt;
    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: AUX_WIDTH,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(PERIODIC_COLUMNS.as_slice()),
        }
    }
    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        // The shared challenge powers feed both bands' fingerprints and carry weights.
        let beta: AB::ExtExpr = inputs.challenges[1].dup();
        let mut beta_powers: [AB::ExtExpr; NUM_GAMMA + 1] = array::from_fn(|_| AB::ExtExpr::ZERO);
        beta.powers().fill(&mut beta_powers);

        // ---- STORE (`UintStoreAir::eval` constraints, columns 0..18) ----
        {
            let local: &[AB::Expr; STORE_NUM_MAIN_COLS] = frame.main.current[..STORE_NUM_MAIN_COLS]
                .try_into()
                .expect("declared AIR row band");
            let next: &[AB::Expr; STORE_NUM_MAIN_COLS] = frame.main.next[..STORE_NUM_MAIN_COLS]
                .try_into()
                .expect("declared AIR row band");

            let (v_lo_sel, v_hi_sel, comp_sel, bound_sel): (
                AB::Expr,
                AB::Expr,
                AB::Expr,
                AB::Expr,
            ) = {
                let p = frame.periodic;
                let b = PCOL_STORE_ROLE_BASE;
                (
                    p[b + PCOL_V_LO].dup(),
                    p[b + PCOL_V_HI].dup(),
                    p[b + PCOL_COMP].dup(),
                    p[b + PCOL_BOUND].dup(),
                )
            };

            let bp: &[AB::ExtExpr; 8] =
                beta_powers[..8].try_into().expect("store fingerprint weights");

            let id: AB::ExtExpr = frame.aux.current[STORE_REG_ID].dup();
            let id_next: AB::ExtExpr = frame.aux.next[STORE_REG_ID].dup();

            let recombined_lo: [AB::Expr; 4] =
                array::from_fn(|k| local[2 * k].dup() + local[2 * k + 1].mul_2exp_u64(16));
            let recombined_hi: [AB::Expr; 4] =
                array::from_fn(|k| local[8 + 2 * k].dup() + local[8 + 2 * k + 1].mul_2exp_u64(16));
            let low_weights: &[AB::ExtExpr; 4] = bp[..4].try_into().expect("low limb weights");
            let high_weights: &[AB::ExtExpr; 4] = bp[4..].try_into().expect("high limb weights");
            let recomb_lo07 =
                <AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product(low_weights, &recombined_lo);
            let recomb_hi07 =
                <AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product(high_weights, &recombined_lo);
            let recomb_hi815 =
                <AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product(high_weights, &recombined_hi);
            let direct_lo = <AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product(
                low_weights,
                local[..4].try_into().expect("low bound limbs"),
            );
            let direct_hi = <AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product(
                high_weights,
                local[8..12].try_into().expect("high bound limbs"),
            );

            // Carry coefficients depend only on the challenge and limb radix.
            let carry_weights: [AB::ExtExpr; 7] =
                array::from_fn(|j| bp[j + 1].dup() - bp[j].mul_2exp_u64(32));
            let carry_lo_term = <AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<4>(
                carry_weights[..4].try_into().expect("low carry weights"),
                local[CARRY_LO_BEGIN..CARRY_LO_BEGIN + 4].try_into().expect("low carries"),
            );
            let carry_hi_term: AB::ExtExpr = (4..7)
                .map(|j| carry_weights[j].dup() * local[CARRY_HI_BEGIN + j - 4].dup())
                .sum();

            let contrib: AB::ExtExpr = recomb_lo07.dup() * (v_lo_sel + comp_sel.dup())
                + recomb_hi07 * v_hi_sel
                + recomb_hi815 * comp_sel
                + (carry_lo_term.dup() + carry_hi_term.dup() - (direct_lo.dup() + direct_hi.dup()))
                    * bound_sel.dup();

            builder.when(frame.first_row()).assert_zero_ext(id.dup());
            builder.when(frame.transition()).assert_eq_ext(id_next, id.dup() + contrib);

            let bound_own: AB::ExtExpr = carry_lo_term + carry_hi_term - (direct_lo + direct_hi);
            builder.when(bound_sel.dup()).assert_zero_ext(id + bound_own);

            // Root the bounded positive pointer-gap chain at 1. Even a maximum
            // 2³²-row trace grows by < 2⁴⁶, so it cannot wrap through 0.
            let ptr = local[COL_PTR].dup();
            builder.when(frame.first_row()).assert_one(ptr.dup());

            builder.when(bound_sel.dup()).assert_bools([
                local[CARRY_LO_BEGIN].dup(),
                local[CARRY_LO_BEGIN + 1].dup(),
                local[CARRY_LO_BEGIN + 2].dup(),
                local[CARRY_LO_BEGIN + 3].dup(),
                local[CARRY_HI_BEGIN].dup(),
                local[CARRY_HI_BEGIN + 1].dup(),
                local[CARRY_HI_BEGIN + 2].dup(),
            ]);

            let not_term = AB::Expr::ONE - bound_sel.dup();
            for col in [COL_PTR, COL_BOUND_PTR] {
                let here = local[col].dup();
                let there = next[col].dup();
                builder.when(not_term.dup()).assert_eq(there, here);
            }

            let gap = local[TERM_CELL_GAP].dup();
            let ptr_here = local[COL_PTR].dup();
            let ptr_next = next[COL_PTR].dup();
            builder
                .when(frame.transition())
                .when(bound_sel)
                .assert_eq(gap + ptr_here + AB::Expr::ONE, ptr_next);
        }

        // ---- MUL (`UintMulAir::eval` constraints, columns `MUL_COL_OFFSET`..`NUM_MAIN_COLS`) ----
        {
            let local: &[AB::Expr; MUL_NUM_MAIN_COLS] = frame.main.current
                [(MUL_COL_OFFSET)..(MUL_COL_OFFSET) + MUL_NUM_MAIN_COLS]
                .try_into()
                .expect("declared AIR row band");
            let next: &[AB::Expr; MUL_NUM_MAIN_COLS] = frame.main.next
                [(MUL_COL_OFFSET)..(MUL_COL_OFFSET) + MUL_NUM_MAIN_COLS]
                .try_into()
                .expect("declared AIR row band");

            // UintMulAir periodic indexing: indices 0..8 are role one-hots and index 8 is
            // `S_KEEP`; these columns lead `periodic_columns()`.
            let sel: &[AB::Expr; MUL_PERIOD + 1] =
                frame.periodic[..MUL_PERIOD + 1].try_into().expect("declared AIR row band");

            let bp = &beta_powers;
            let t16 = AB::Expr::from(Felt::from(1u32 << 16));
            let x_minus_t: AB::ExtExpr = beta - t16.dup();
            let offset = AB::Expr::from(Felt::from(GAMMA_OFFSET));

            let kappa_a = local[M_COL_KAPPA_A].dup();
            let act = local[M_COL_ACT].dup();
            let kappa_c_signed_local = local[TERM_CELL_KAPPA_C_SIGNED].dup();

            let id: AB::ExtExpr = frame.aux.current[MUL_REG_ID].dup();
            let id_next: AB::ExtExpr = frame.aux.next[MUL_REG_ID].dup();
            let s: AB::ExtExpr = frame.aux.current[MUL_REG_S].dup();
            let s_next: AB::ExtExpr = frame.aux.next[MUL_REG_S].dup();

            // Keep the 16-limb prefix shared with the 17-limb quotient.
            let full16_sum = <AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<8>(
                bp[..8].try_into().expect("low operand weights"),
                local[..8].try_into().expect("low operand limbs"),
            ) + <AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product::<8>(
                bp[8..16].try_into().expect("high operand weights"),
                local[8..16].try_into().expect("high operand limbs"),
            );
            let full_q_sum =
                full16_sum.dup() + bp[NUM_Q_LIMBS - 1].dup() * local[NUM_Q_LIMBS - 1].dup();
            let even_weights: [AB::ExtExpr; 8] = array::from_fn(|m| bp[2 * m].dup());
            let val_sum = <AB::ExtExpr as Algebra<AB::Expr>>::mixed_dot_product(
                &even_weights,
                local[..8].try_into().expect("linear operand limbs"),
            );

            let build: AB::ExtExpr =
                full16_sum.dup() * (sel[ROW_A].dup() * kappa_a.dup() + sel[ROW_P].dup());
            let keep = sel[PCOL_MUL_S_KEEP].dup();
            builder.when(frame.first_row()).assert_zero_ext(s.dup());
            builder.when(frame.transition()).assert_eq_ext(s_next, s.dup() * keep + build);

            let product = s.dup() * full16_sum.dup() * sel[ROW_B].dup();
            let quotient = (s + AB::ExtExpr::ONE) * full_q_sum * sel[ROW_Q].dup();
            let linear =
                val_sum.dup() * (sel[ROW_C].dup() * kappa_c_signed_local.dup() - sel[ROW_R].dup());

            let carries: AB::ExtExpr = GAMMA_SLOTS
                .iter()
                .enumerate()
                .map(|(slot, &(row, cell))| {
                    let k = slot / 2;
                    let mut w = x_minus_t.dup() * bp[k].dup();
                    if slot % 2 == 1 {
                        w = w.mul_2exp_u64(16);
                    }
                    let mut gated = sel[row].dup() * local[cell].dup();
                    if slot % 2 == 0 {
                        gated -= sel[row].dup() * act.dup() * offset.dup();
                    }
                    w * gated
                })
                .sum();

            let borrow = local[M_COL_BORROW].dup();
            let borrow_contrib: AB::ExtExpr =
                (full16_sum + AB::ExtExpr::ONE) * (sel[ROW_P].dup() * borrow.dup());

            let contrib: AB::ExtExpr = product - quotient + linear + carries + borrow_contrib;
            builder.when(frame.first_row()).assert_zero_ext(id.dup());
            builder.when(frame.transition()).assert_eq_ext(id_next, id.dup() + contrib);

            // The `c` row folds the closing check onto its own last-operand
            // row, exactly like `UintMulAir::eval` — see that function's
            // comment for the full rationale.
            let c_carries: AB::ExtExpr = GAMMA_SLOTS
                .iter()
                .enumerate()
                .filter(|&(_, &(row, _))| row == ROW_C)
                .map(|(slot, &(_, cell))| {
                    let mut weight = x_minus_t.dup() * bp[slot / 2].dup();
                    if slot % 2 == 1 {
                        weight = weight.mul_2exp_u64(16);
                    }
                    let carry = if slot % 2 == 0 {
                        local[cell].dup() - act.dup() * offset.dup()
                    } else {
                        local[cell].dup()
                    };
                    weight * carry
                })
                .sum();
            let c_own = val_sum * kappa_c_signed_local.dup() + c_carries;
            builder.when(sel[ROW_C].dup()).assert_zero_ext(id + c_own);

            builder.assert_bool(act.dup());

            let is_sub = local[TERM_CELL_IS_SUB].dup();
            builder.when(sel[ROW_C].dup()).assert_bool(is_sub.dup());

            let kappa_c_local = local[TERM_CELL_KAPPA_C].dup();
            let c_sign_local = AB::Expr::ONE - is_sub.double();
            builder
                .when(sel[ROW_C].dup())
                .assert_eq(kappa_c_signed_local.dup(), kappa_c_local.dup() * c_sign_local);

            builder.assert_zero(borrow.bool_check() * (borrow.dup() - AB::Expr::TWO));
            builder
                .when(sel[ROW_C].dup() * borrow.dup())
                .assert_eq(AB::Expr::ONE, is_sub.dup());

            builder
                .when(sel[ROW_C].dup() * (AB::Expr::ONE - act.dup()))
                .assert_zero(local[TERM_CELL_MULT].dup());

            let not_term = AB::Expr::ONE - sel[ROW_C].dup();
            for col in [
                M_COL_A_PTR,
                M_COL_B_PTR,
                M_COL_R_PTR,
                M_COL_BOUND_PTR,
                M_COL_KAPPA_A,
                M_COL_ACT,
                M_COL_BORROW,
            ] {
                let here = local[col].dup();
                let there = next[col].dup();
                builder.when(not_term.dup()).assert_eq(there, here);
            }
        }

        // Phase 2: LogUp.
        lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl air::ProverAir<QuadFelt> for UintStoreMulAir {
    type Error = lookup::LookupError;
    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        aux::build_aux(inputs)
    }
}
