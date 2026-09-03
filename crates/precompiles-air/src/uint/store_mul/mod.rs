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
//! Exactly one centered running-sum column is committed per AIR. Column 0 remains store's anchor;
//! mul's anchor is repacked into an ordinary two-fraction column. The four singleton fractions
//! other than the retained store anchor are paired across two columns, and every fraction closes
//! into the same centered residue without raising the constraint degree. Both sides' `id` / `S`
//! registers remain independent because store and mul are simultaneously live.
//!
//! The shared height is `max` of what each side natively needs
//! (independently `next_power_of_two`-padded, own padding mechanism —
//! store's self-referential zero blocks, mul's `act = 0` blocks) — not
//! their sum, since they occupy the same rows.

mod aux;

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    logup::{
        ConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
    },
    primitives::byte_pair_lut::Range16Msg,
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::{
        self, NUM_LOGUP_COLS as STORE_NUM_LOGUP_COLS, StoreBand, UintLimbsMsg, UintValMsg,
        mul::{
            COL_A_PTR as M_COL_A_PTR, COL_ACT as M_COL_ACT, COL_B_PTR as M_COL_B_PTR,
            COL_BOUND_PTR as M_COL_BOUND_PTR, COL_KAPPA_A as M_COL_KAPPA_A,
            COL_R_PTR as M_COL_R_PTR, GAMMA_SLOTS, MulBand, NUM_CELLS as MUL_NUM_CELLS,
            NUM_LOGUP_COLS as MUL_NUM_LOGUP_COLS, NUM_MAIN_COLS as MUL_NUM_MAIN_COLS, NUM_Q_LIMBS,
            PERIOD as MUL_PERIOD, ROW_A, ROW_B, ROW_C, ROW_P, ROW_Q, ROW_R, S_KEEP,
            TERM_CELL_C_PTR, TERM_CELL_IS_SUB, TERM_CELL_KAPPA_C, TERM_CELL_MULT, UintMulMsg,
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
const PCOL_STORE_ROLE_BASE: usize = MUL_PERIOD + 1;
const NUM_PERIODIC: usize = MUL_PERIOD + 1 + STORE_PERIOD;

// Aux layout: col 0 is store's anchor fraction and the centered running sum. The remaining 46
// fractions are paired into 23 ordinary columns, including the two repacked columns that absorb
// the four singleton fractions other than the retained store anchor. Registers stay independent
// because store and mul are simultaneously live, so their `id` accumulators cannot share a column.
const REPACKED_COLUMN_SAVINGS: usize = 2;
pub const NUM_LOGUP_COLS: usize =
    STORE_NUM_LOGUP_COLS + MUL_NUM_LOGUP_COLS - REPACKED_COLUMN_SAVINGS;
pub const STORE_REG_ID: usize = NUM_LOGUP_COLS;
pub const MUL_REG_ID: usize = NUM_LOGUP_COLS + 1;
pub const MUL_REG_S: usize = NUM_LOGUP_COLS + 2;
pub const AUX_WIDTH: usize = NUM_LOGUP_COLS + 3;

/// The bands the two components occupy inside this composite.
const STORE_BAND: StoreBand = StoreBand {
    main: 0,
    periodic: PCOL_STORE_ROLE_BASE,
    reg_id: STORE_REG_ID,
};
const MUL_BAND: MulBand = MulBand {
    main: MUL_COL_OFFSET,
    periodic: 0,
    reg_id: MUL_REG_ID,
    reg_s: MUL_REG_S,
};

const _: () = assert!(
    MUL_NUM_CELLS % 2 == 1,
    "the final mul Range16 interaction must be a singleton tail"
);

const fn column_shape() -> [usize; NUM_LOGUP_COLS] {
    let mut shape = [2usize; NUM_LOGUP_COLS];
    shape[0] = 1;
    shape
}
pub(crate) const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = column_shape();

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
        NUM_LOGUP_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        aux::build_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        uint::eval_main(builder, STORE_BAND);
        uint::mul::eval_main(builder, MUL_BAND);

        // Phase 2: LogUp.
        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for UintStoreMulAir
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
        let neg_val_mult: LB::Expr = LB::Expr::ZERO - next_s[HUB_CELL_UINTVAL_MULT].into();
        let neg_limbs_val_mult: LB::Expr = LB::Expr::ZERO - next_s[HUB_CELL_UINTLIMBS_MULT].into();
        let two16: LB::Expr = LB::Expr::from(Felt::from(1u32 << 16));
        let recomb: [LB::Expr; 8] = array::from_fn(|k| {
            if k < 4 {
                local_s[2 * k].into() + two16.clone() * local_s[2 * k + 1].into()
            } else {
                let k = k - 4;
                next_s[2 * k].into() + two16.clone() * next_s[2 * k + 1].into()
            }
        });
        let direct: [LB::Expr; 8] = array::from_fn(|k| {
            if k < 4 {
                local_s[k].into()
            } else {
                local_s[4 + k].into()
            }
        });

        let provide_deg = Deg { v: 2, u: 1 };
        let consume_deg = Deg { v: 1, u: 1 };
        let store_pair_deg = Deg { v: 2, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };
        let raw: [LB::Expr; 16] =
            array::from_fn(|j| if j < 8 { local_s[j].into() } else { next_s[j - 8].into() });
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

        // col 0: store's original first fraction column, which drives the composite's centered
        // accumulator.
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
                                    "provide",
                                    neg_val_mult * v_lo_sel.clone(),
                                    UintValMsg {
                                        ptr: store_ptr.clone(),
                                        bound_ptr: store_bound_ptr.clone(),
                                        limbs: recomb,
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

        // col 1: store's merged consume + the ptr-gap Range16.
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
                                    "consume",
                                    bound_sel.clone(),
                                    UintValMsg {
                                        ptr: store_bound_ptr.clone(),
                                        bound_ptr: store_bound_ptr.clone(),
                                        limbs: direct,
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
                            store_pair_deg,
                        );
                    },
                    store_pair_deg,
                );
            },
            store_pair_deg,
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
                                store_pair_deg,
                            );
                        },
                        store_pair_deg,
                    );
                },
                store_pair_deg,
            );
        }
        // Pair store's non-anchor raw provide with mul's relocated anchor provide. They retain
        // their distinct typed buses; only their rational fractions share an auxiliary column.
        builder.next_column(
            |col| {
                col.group(
                    "store+mul-provides",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "provide-raw",
                                    neg_limbs_val_mult * v_lo_sel,
                                    UintLimbsMsg {
                                        ptr: store_ptr,
                                        bound_ptr: store_bound_ptr,
                                        limbs: raw,
                                    },
                                    provide_deg,
                                );
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
                            pair_deg,
                        );
                    },
                    pair_deg,
                );
            },
            pair_deg,
        );

        let mul_raw_limbs: [LB::Expr; 16] = array::from_fn(|i| {
            if i < 8 {
                raw_m_lo[i].clone()
            } else {
                raw_m_hi[i - 8].clone()
            }
        });
        builder.next_column(
            |col| {
                col.group(
                    "uintlimbs",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                for (row, ptr) in [(ROW_A, a_ptr.clone()), (ROW_B, b_ptr.clone())] {
                                    b.insert(
                                        "consume-uintlimbs",
                                        sel[row].clone() * mul_act.clone(),
                                        UintLimbsMsg {
                                            ptr,
                                            bound_ptr: mul_bound_ptr.clone(),
                                            limbs: mul_raw_limbs.clone(),
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
        for pair in 0..MUL_NUM_CELLS / 2 {
            let cells = [2 * pair, 2 * pair + 1];
            builder.next_column(
                |col| {
                    col.group(
                        "range16-cells",
                        |g| {
                            g.batch(
                                "f",
                                LB::Expr::ONE,
                                |b| {
                                    for cell in cells {
                                        b.insert(
                                            "range16-cell",
                                            cell_gate(cell) * mul_act.clone(),
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

        // Pair mul's two remaining singleton tails: the bound's raw UintLimbs consume and the
        // final cell-position Range16 check. Their bus domains remain independent.
        let tail_cell = MUL_NUM_CELLS - 1;
        builder.next_column(
            |col| {
                col.group(
                    "bound+range16",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "consume-bound-limbs",
                                    sel[ROW_P].clone() * mul_act.clone(),
                                    UintLimbsMsg {
                                        ptr: mul_bound_ptr.clone(),
                                        bound_ptr: mul_bound_ptr.clone(),
                                        limbs: mul_raw_limbs,
                                    },
                                    mul_consume_deg,
                                );
                                b.insert(
                                    "range16-cell",
                                    cell_gate(tail_cell) * mul_act.clone(),
                                    Range16Msg { w: local_m[tail_cell].into() },
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
        let val_full: [LB::Expr; 8] = array::from_fn(|i| {
            if i < 4 {
                val_lo[i].clone()
            } else {
                val_hi[i - 4].clone()
            }
        });
        let val_consumes: [(usize, LB::Expr); 2] = [(ROW_R, r_ptr.clone()), (ROW_C, c_ptr_local)];
        builder.next_column(
            |col| {
                col.group(
                    "uintval",
                    |g| {
                        g.batch(
                            "f",
                            LB::Expr::ONE,
                            |b| {
                                for (row, ptr) in val_consumes {
                                    b.insert(
                                        "consume-uintval",
                                        sel[row].clone() * mul_act.clone(),
                                        UintValMsg {
                                            ptr,
                                            bound_ptr: mul_bound_ptr.clone(),
                                            limbs: val_full.clone(),
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
