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
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_stark::air::native::LiftedAirBuilder as _;
use miden_stark::{
    air::native,
    lookup::{Deg, LookupBatch, LookupColumn, LookupGroup, native as native_lookup},
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

impl<LB> native_lookup::LookupAir<LB> for UintStoreMulAir
where
    LB: native_lookup::LookupBuilder<F = Felt>,
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

    fn eval(&self, frame: &native_lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
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
        let store_ptr: LB::Expr = local_s[COL_PTR].dup();
        let store_bound_ptr: LB::Expr = local_s[COL_BOUND_PTR].dup();
        let neg_val_mult: LB::Expr = LB::Expr::ZERO - next_s[HUB_CELL_UINTVAL_MULT].dup();
        let neg_limbs_val_mult: LB::Expr = LB::Expr::ZERO - next_s[HUB_CELL_UINTLIMBS_MULT].dup();
        let two16: LB::Expr = LB::Expr::from(Felt::from(1u32 << 16));
        let recomb: [LB::Expr; 8] = array::from_fn(|k| {
            if k < 4 {
                local_s[2 * k].dup() + two16.clone() * local_s[2 * k + 1].dup()
            } else {
                let k = k - 4;
                next_s[2 * k].dup() + two16.clone() * next_s[2 * k + 1].dup()
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
            .expect("uint lookup row band");
        let sel: [LB::Expr; MUL_PERIOD] = {
            let p = frame.periodic;
            array::from_fn(|i| p[i].dup())
        };
        let a_ptr: LB::Expr = local_m[M_COL_A_PTR].dup();
        let b_ptr: LB::Expr = local_m[M_COL_B_PTR].dup();
        let r_ptr: LB::Expr = local_m[M_COL_R_PTR].dup();
        let mul_bound_ptr: LB::Expr = local_m[M_COL_BOUND_PTR].dup();
        let mul_kappa_a: LB::Expr = local_m[M_COL_KAPPA_A].dup();
        let mul_act: LB::Expr = local_m[M_COL_ACT].dup();
        let c_ptr_local: LB::Expr = local_m[TERM_CELL_C_PTR].dup();
        let kappa_c_local: LB::Expr = local_m[TERM_CELL_KAPPA_C].dup();
        let neg_mult: LB::Expr = LB::Expr::ZERO - local_m[TERM_CELL_MULT].dup();
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
                .fold(raw16, |acc, &(row, _)| acc + sel[row].clone())
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

impl native::LiftedAir for UintStoreMulAir {
    type F = Felt;
    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: AUX_WIDTH,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(PERIODIC_COLUMNS.as_slice()),
        }
    }
    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        // ---- STORE (`UintStoreAir::eval` constraints, columns 0..18) ----
        {
            let local: &[AB::Expr; STORE_NUM_MAIN_COLS] = frame.main.current[..STORE_NUM_MAIN_COLS]
                .try_into()
                .expect("uint main row band");
            let next: &[AB::Expr; STORE_NUM_MAIN_COLS] =
                frame.main.next[..STORE_NUM_MAIN_COLS].try_into().expect("uint main row band");

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

            let beta: AB::ExtExpr = inputs.challenge(1);
            let mut bp: Vec<AB::ExtExpr> = Vec::with_capacity(8);
            bp.push(AB::ExtExpr::ONE);
            for i in 1..8 {
                bp.push(bp[i - 1].clone() * beta.clone());
            }

            let id: AB::ExtExpr = frame.aux.current[STORE_REG_ID].dup();
            let id_next: AB::ExtExpr = frame.aux.next[STORE_REG_ID].dup();

            let two16: AB::Expr = AB::Expr::from(Felt::from(1u32 << 16));
            let mut recomb_lo07 = AB::ExtExpr::ZERO;
            let mut recomb_hi07 = AB::ExtExpr::ZERO;
            let mut recomb_hi815 = AB::ExtExpr::ZERO;
            let mut direct_lo = AB::ExtExpr::ZERO;
            let mut direct_hi = AB::ExtExpr::ZERO;
            for k in 0..4 {
                let r07: AB::Expr = local[2 * k].dup() + two16.clone() * local[2 * k + 1].dup();
                let r815: AB::Expr =
                    local[8 + 2 * k].dup() + two16.clone() * local[8 + 2 * k + 1].dup();
                recomb_lo07 += bp[k].clone() * r07.clone();
                recomb_hi07 += bp[4 + k].clone() * r07;
                recomb_hi815 += bp[4 + k].clone() * r815;
                direct_lo += bp[k].clone() * local[k].dup();
                direct_hi += bp[4 + k].clone() * local[8 + k].dup();
            }

            let t32: AB::Expr = AB::Expr::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));
            let mut carry_lo_term = AB::ExtExpr::ZERO;
            for j in 0..4 {
                let weight: AB::ExtExpr = bp[j + 1].clone() - bp[j].clone() * t32.clone();
                carry_lo_term += weight * local[CARRY_LO_BEGIN + j].dup();
            }
            let mut carry_hi_term = AB::ExtExpr::ZERO;
            for j in 4..7 {
                let weight: AB::ExtExpr = bp[j + 1].clone() - bp[j].clone() * t32.clone();
                carry_hi_term += weight * local[CARRY_HI_BEGIN + (j - 4)].dup();
            }

            let contrib: AB::ExtExpr = recomb_lo07.clone() * (v_lo_sel + comp_sel.clone())
                + recomb_hi07 * v_hi_sel
                + recomb_hi815 * comp_sel
                + (carry_lo_term.clone() - direct_lo.clone() + carry_hi_term.clone()
                    - direct_hi.clone())
                    * bound_sel.clone();

            builder.when(frame.first_row()).assert_zero_ext(id.clone());
            builder.when(frame.transition()).assert_zero_ext(id_next - id.clone() - contrib);

            let bound_own: AB::ExtExpr = carry_lo_term - direct_lo + carry_hi_term - direct_hi;
            builder.assert_zero_ext((id + bound_own) * bound_sel.clone());

            // Root the bounded positive pointer-gap chain at 1. Even a maximum
            // 2³²-row trace grows by < 2⁴⁶, so it cannot wrap through 0.
            let ptr: AB::Expr = local[COL_PTR].dup();
            builder.when(frame.first_row()).assert_zero(ptr - AB::Expr::ONE);

            for &cell in
                [CARRY_LO_BEGIN, CARRY_LO_BEGIN + 1, CARRY_LO_BEGIN + 2, CARRY_LO_BEGIN + 3].iter()
            {
                let lj: AB::Expr = local[cell].dup();
                builder.assert_zero(bound_sel.clone() * lj.clone() * (AB::Expr::ONE - lj));
            }
            for &cell in [CARRY_HI_BEGIN, CARRY_HI_BEGIN + 1, CARRY_HI_BEGIN + 2].iter() {
                let lj: AB::Expr = local[cell].dup();
                builder.assert_zero(bound_sel.clone() * lj.clone() * (AB::Expr::ONE - lj));
            }

            let not_term: AB::Expr = AB::Expr::ONE - bound_sel.clone();
            for col in [COL_PTR, COL_BOUND_PTR] {
                let here: AB::Expr = local[col].dup();
                let there: AB::Expr = next[col].dup();
                builder.assert_zero(not_term.clone() * (there - here));
            }

            let gap: AB::Expr = local[TERM_CELL_GAP].dup();
            let ptr_here: AB::Expr = local[COL_PTR].dup();
            let ptr_next: AB::Expr = next[COL_PTR].dup();
            builder
                .when(frame.transition())
                .assert_zero(bound_sel * (gap + ptr_here + AB::Expr::ONE - ptr_next));
        }

        // ---- MUL (`UintMulAir::eval` constraints, columns `MUL_COL_OFFSET`..`NUM_MAIN_COLS`) ----
        {
            let local: &[AB::Expr; MUL_NUM_MAIN_COLS] = frame.main.current
                [MUL_COL_OFFSET..MUL_COL_OFFSET + MUL_NUM_MAIN_COLS]
                .try_into()
                .expect("uint main row band");
            let next: &[AB::Expr; MUL_NUM_MAIN_COLS] = frame.main.next
                [MUL_COL_OFFSET..MUL_COL_OFFSET + MUL_NUM_MAIN_COLS]
                .try_into()
                .expect("uint main row band");

            // UintMulAir periodic indexing: indices 0..8 are role one-hots and index 8 is
            // `S_KEEP`; these columns lead `periodic_columns()`.
            let sel: [AB::Expr; MUL_PERIOD + 1] = {
                let p = frame.periodic;
                array::from_fn(|i| p[i].dup())
            };

            let beta: AB::ExtExpr = inputs.challenge(1);
            let mut bp: Vec<AB::ExtExpr> = Vec::with_capacity(NUM_GAMMA + 1);
            bp.push(AB::ExtExpr::ONE);
            for i in 1..NUM_GAMMA + 1 {
                bp.push(bp[i - 1].clone() * beta.clone());
            }
            let t16: AB::Expr = AB::Expr::from(Felt::from(1u32 << 16));
            let x_minus_t: AB::ExtExpr = beta - t16.clone();
            let offset: AB::Expr = AB::Expr::from(Felt::from(GAMMA_OFFSET));

            let kappa_a: AB::Expr = local[M_COL_KAPPA_A].dup();
            let act: AB::Expr = local[M_COL_ACT].dup();
            let kappa_c_signed_local: AB::Expr = local[TERM_CELL_KAPPA_C_SIGNED].dup();

            let id: AB::ExtExpr = frame.aux.current[MUL_REG_ID].dup();
            let id_next: AB::ExtExpr = frame.aux.next[MUL_REG_ID].dup();
            let s: AB::ExtExpr = frame.aux.current[MUL_REG_S].dup();
            let s_next: AB::ExtExpr = frame.aux.next[MUL_REG_S].dup();

            let full16_sum: AB::ExtExpr =
                (0..16).fold(AB::ExtExpr::ZERO, |acc, i| acc + bp[i].clone() * local[i].dup());
            let full_q_sum: AB::ExtExpr = (0..NUM_Q_LIMBS)
                .fold(AB::ExtExpr::ZERO, |acc, i| acc + bp[i].clone() * local[i].dup());
            let val_sum: AB::ExtExpr =
                (0..8).fold(AB::ExtExpr::ZERO, |acc, m| acc + bp[2 * m].clone() * local[m].dup());

            let build: AB::ExtExpr = full16_sum.clone() * (sel[ROW_A].clone() * kappa_a)
                + full16_sum.clone() * sel[ROW_P].clone();
            let keep: AB::Expr = sel[PCOL_MUL_S_KEEP].clone();
            builder.when(frame.first_row()).assert_zero_ext(s.clone());
            builder
                .when(frame.transition())
                .assert_zero_ext(s_next - s.clone() * keep - build);

            let product = s.clone() * full16_sum.clone() * sel[ROW_B].clone();
            let quotient = (s + AB::ExtExpr::ONE) * full_q_sum * sel[ROW_Q].clone();
            let linear = val_sum.clone() * (sel[ROW_C].clone() * kappa_c_signed_local.clone())
                - val_sum.clone() * sel[ROW_R].clone();

            let mut carries = AB::ExtExpr::ZERO;
            for (slot, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
                let k = slot / 2;
                let mut w = x_minus_t.clone() * bp[k].clone();
                if slot % 2 == 1 {
                    w *= t16.clone();
                }
                let mut gated: AB::Expr = sel[row].clone() * local[cell].dup();
                if slot % 2 == 0 {
                    gated -= sel[row].clone() * act.clone() * offset.clone();
                }
                carries += w * gated;
            }

            let borrow: AB::Expr = local[M_COL_BORROW].dup();
            let borrow_contrib: AB::ExtExpr =
                (full16_sum + AB::ExtExpr::ONE) * (sel[ROW_P].clone() * borrow.clone());

            let contrib: AB::ExtExpr = product - quotient + linear + carries + borrow_contrib;
            builder.when(frame.first_row()).assert_zero_ext(id.clone());
            builder.when(frame.transition()).assert_zero_ext(id_next - id.clone() - contrib);

            // The `c` row folds the closing check onto its own last-operand
            // row, exactly like `UintMulAir::eval` — see that function's
            // comment for the full rationale.
            let mut c_own: AB::ExtExpr = val_sum * kappa_c_signed_local.clone();
            for (slot, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
                if row == ROW_C {
                    let k = slot / 2;
                    let mut w = x_minus_t.clone() * bp[k].clone();
                    if slot % 2 == 1 {
                        w *= t16.clone();
                    }
                    let mut gated: AB::Expr = local[cell].dup();
                    if slot % 2 == 0 {
                        gated -= act.clone() * offset.clone();
                    }
                    c_own += w * gated;
                }
            }
            builder.assert_zero_ext((id + c_own) * sel[ROW_C].clone());

            builder.assert_zero(act.clone() * (AB::Expr::ONE - act.clone()));

            let is_sub: AB::Expr = local[TERM_CELL_IS_SUB].dup();
            builder.assert_zero(
                sel[ROW_C].clone() * is_sub.clone() * (AB::Expr::ONE - is_sub.clone()),
            );

            let kappa_c_local: AB::Expr = local[TERM_CELL_KAPPA_C].dup();
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
                sel[ROW_C].clone() * (AB::Expr::ONE - act) * local[TERM_CELL_MULT].dup(),
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
                let here: AB::Expr = local[col].dup();
                let there: AB::Expr = next[col].dup();
                builder.assert_zero(not_term.clone() * (there - here));
            }
        }

        // Phase 2: LogUp.
        native_lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl native::ProverAir<QuadFelt> for UintStoreMulAir {
    type Error = native_lookup::LookupError;
    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        aux::build_aux(inputs)
    }
}
