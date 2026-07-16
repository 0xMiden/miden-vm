//! EcGroupAdd chiplet — adversarially complete point addition over the
//! [EC stores](crate::ec).
//!
//! One op proves `R = P + Q` for **any** stored operands via a
//! prover-witnessed near-one-hot over five cases. Every predicate and
//! every piece of field math rides **ptr-level certificate tuples**
//! consumed from the uint relation chiplets — no coordinate limb ever
//! enters this trace. This AIR's own job is *proving which case
//! applies* and tying the right certificate set to the result.
//!
//! See the design notes for the design.
//!
//! ## The case lattice
//!
//! | case | condition | result |
//! |---|---|---|
//! | `pai_p` | `P = ∞` | `r_ptr = q_ptr` (tie) |
//! | `pai_q` | `Q = ∞` | `r_ptr = p_ptr` (tie) |
//! | `cancel` | finite, `x₁ = x₂`, `y₁ + y₂ ≡ 0` | `R` = the group's PAI row |
//! | `double` | finite, `x₁ = x₂`, `y₁ = y₂`, `y₁ ≠ 0` | tangent |
//! | `generic` | finite, `x₁ ≠ x₂` | chord |
//!
//! Exhaustive *because the store's eager on-curve invariant pins
//! `y₂ = ±y₁` whenever `x₁ = x₂`*, and `double`/`cancel` are
//! structurally disjoint (`2y ≡ 0 ∧ y ≠ 0` is impossible for odd `p`).
//! The operand `is_pai` flags are not witnessed twice: **the case flags
//! themselves ride the consumed `EcPoint` tuples** as the `is_pai`
//! field, so a forged claim matches no store row. That wiring is also
//! why `∞ + ∞` sets *both* pass flags (the one-hot relaxes to
//! `Σ = act + pai_p·pai_q`): each infinite operand needs `is_pai = 1`
//! on its own tuple, and the two ties then force `p = q = r` — the
//! group's canonical PAI row.
//!
//! ## Predicates as certificates
//!
//! Equality (`double`/`cancel`'s `x₁ = x₂`, `double`'s `y₁ = y₂`) is
//! the [`is_b_zero`](crate::uint::add) `UintAdd` form `x₁ + 0 ≡ x₂` —
//! value-level (distinct ptrs binding equal coordinates still close),
//! deterministic, no limbs. Disequality (`generic`'s `x₁ ≠ x₂`) and
//! nonzero (`double`'s `y₁ ≠ 0`) are **inverse MACs against the
//! group's `b`**: a stored witness `inv` with
//!
//! ```text
//! inv·d + 0 ≡ b      (generic: d = x₂ − x₁, the slope transient)
//! inv·y₁ + 0 ≡ b     (double)
//! ```
//!
//! `b ≠ 0` (the EcCreate guard, doing double duty) makes either MAC
//! unsatisfiable when the factor is zero — the λ-float attack dies in
//! the mul chiplet, deterministically, with no β-dependent fingerprint,
//! no aux witness registers, and no completeness gap.
//!
//! ## Certificates (consumed tuples)
//!
//! The slope and tail arrangements are recorded as ordinary uint ops
//! and consumed here with exact κ's — `double`'s constants vanish into
//! the MAC scales (`s ≡ 3·x² + a`; `2·λ·y ≡ s` with the shared
//! `r_ptr = s`), `cancel`'s `y₁ + y₂ ≡ 0` is the `is_c_zero` `UintAdd`
//! tuple, and the shared tail (`w = λ²`, `t`, `x₃`, `e`, `u`, `y₃`) is
//! identical for both live cases. The result `R` is bound by consuming
//! its `EcPoint` tuple against the computed `(x₃, y₃)` (or the group's
//! PAI row for `cancel`); `R` itself is an ordinary eager-membership
//! store point.
//!
//! ## Layout
//!
//! Period **4**, 4 ptr cells/row; one add op per block, all-zero
//! `act = 0` blocks as padding. The per-block scalars that the old
//! 16-row layout held as cycle-constant columns are **hosted in dead
//! cells** and read through the two-row windows:
//!
//! | row | cells 0–3 | emits |
//! |---|---|---|
//! | 0 `slope` | `(slope_aux, λ, inv, t)` | slope + predicate certs (local), tail certs (cells @ next) |
//! | 1 `tail`  | `(w, e, u, x₃)` | `y₃`-sub + the live result consume (`r`/`y₃`/`group` @ next) |
//! | 2 `res`   | `(y₃, r, sbound, group)` | the provide + operand/PAI/group consumes (`p`/`q`/mult @ next) |
//! | 3 `term`  | `(mult, p, q, —)` | — (hosts only; the constancy gate drops here) |
//!
//! Columns carry only what gates or names certificates on rows 0–2:
//! the four operand coordinate ptrs, `a`/`b`/`bound`, the five case
//! flags, `act` — 17 main columns, 3 LogUp aux columns, 4 periodic
//! one-hots.

pub mod trace;

use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    ec::{EcGroupMsg, EcPointMsg},
    logup::{
        Challenges, CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder,
        LookupColumn, LookupGroup, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
        NUM_SIGMA_VALUES,
    },
    primitives::byte_pair_lut::Range16Msg,
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::{add::UintAddMsg, mul::UintMulMsg},
    utils::{current_main, next_main},
};

// MESSAGES
// ================================================================================================

/// LogUp message for the [`EcGroupAdd`](BusId::EcGroupAdd) relation: the
/// 4-tuple `(group_ptr, p_ptr, q_ptr, r_ptr)` asserting `R = P + Q` in
/// the group. *Provided* here (dormant until ladder / DAG consumers).
#[derive(Debug, Clone)]
pub struct EcGroupAddMsg<E> {
    pub group_ptr: E,
    pub p_ptr: E,
    pub q_ptr: E,
    pub r_ptr: E,
}

impl<E, EF> LookupMessage<E, EF> for EcGroupAddMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::EcGroupAdd as usize,
            [
                self.group_ptr.clone(),
                self.p_ptr.clone(),
                self.q_ptr.clone(),
                self.r_ptr.clone(),
            ],
        )
    }
}

/// LogUp message for the [`EcOnCurveCert`](BusId::EcOnCurveCert)
/// relation: the 2-tuple `(group_ptr, r_ptr)` vouching that point `r` is
/// on `group`'s curve *because the group law is closed*. **Provided** by
/// a mint op (a fresh `generic` / `double` result, gated `mints`), whose
/// own block certifies `r = p + q` for on-curve operands `p`, `q`;
/// **consumed** by `r`'s point-store row in place of the on-curve MAC
/// trio. The strict ptr ordering `r > p ∧ r > q` (witnessed on the same
/// block) grounds the induction over ptr, so a cert-certified point only
/// ever cites strictly-smaller already-on-curve operands.
#[derive(Debug, Clone)]
pub struct EcOnCurveCertMsg<E> {
    pub group_ptr: E,
    pub r_ptr: E,
}

impl<E, EF> LookupMessage<E, EF> for EcOnCurveCertMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges
            .encode(BusId::EcOnCurveCert as usize, [self.group_ptr.clone(), self.r_ptr.clone()])
    }
}

// COLUMN LAYOUT
// ================================================================================================

/// Ptr cells per row (transients / hosted scalars by row role).
pub const NUM_CELLS: usize = 4;
/// Operand coordinate ptrs (0 for a PAI operand, matching its store row).
pub const COL_PX: usize = 4;
pub const COL_PY: usize = 5;
pub const COL_QX: usize = 6;
pub const COL_QY: usize = 7;
/// Curve params + base-field modulus (read by certificates on rows 0–2).
pub const COL_A_PTR: usize = 8;
pub const COL_B_PTR: usize = 9;
pub const COL_BOUND_PTR: usize = 10;
/// The case near-one-hot (cycle-constant; Σ = act + pai_p·pai_q).
pub const COL_PAI_P: usize = 11;
pub const COL_PAI_Q: usize = 12;
pub const COL_CANCEL: usize = 13;
pub const COL_DBL: usize = 14;
pub const COL_GEN: usize = 15;
pub const COL_ACT: usize = 16;
/// Fresh-mint flag (closure certificate, Phase 1): set iff this op is the
/// *first* to mint its result point (`add_point_at` miss) on a generic /
/// double case — the op that owns `r`'s membership certificate. Witnessed,
/// pinned by the case guard `mints ⟹ generic ∨ double` and the strict
/// ordering `mints ⟹ r_ptr > p_ptr ∧ r_ptr > q_ptr` below. Cycle-constant.
pub const COL_MINTS: usize = 17;
/// Limbs of `r_ptr − p_ptr − 1` (16-bit lo / hi) — the witnessed,
/// Range16-checked difference proving `r_ptr > p_ptr` on `mints` ops. 0 off
/// mint ops. Cycle-constant.
pub const COL_RP_LO: usize = 18;
pub const COL_RP_HI: usize = 19;
/// Limbs of `r_ptr − q_ptr − 1` — proving `r_ptr > q_ptr`.
pub const COL_RQ_LO: usize = 20;
pub const COL_RQ_HI: usize = 21;
pub const NUM_MAIN_COLS: usize = 22;

/// Block period: one add op = 4 rows.
pub const PERIOD: usize = 4;

// Row roles.
pub const ROW_SLOPE: usize = 0;
pub const ROW_TAIL: usize = 1;
pub const ROW_RES: usize = 2;
pub const ROW_TERM: usize = 3;

/// Row-0 cells: `slope_aux` is `d = x₂ − x₁` for `generic`, `s = 3x² + a`
/// for `double`; `inv` is the disequality / nonzero witness
/// (`b·d⁻¹` / `b·y₁⁻¹`).
pub const CELL_SLOPE_AUX: usize = 0;
pub const CELL_LAMBDA: usize = 1;
pub const CELL_INV: usize = 2;
pub const CELL_T: usize = 3;
/// Row-1 cells.
pub const CELL_W: usize = 0;
pub const CELL_E: usize = 1;
pub const CELL_U: usize = 2;
pub const CELL_X3: usize = 3;
/// Row-2 cells: the result's `y₃`, plus the hosted `r` / scalar-bound /
/// group ptrs.
pub const CELL_Y3: usize = 0;
pub const CELL_R: usize = 1;
pub const CELL_SBOUND: usize = 2;
pub const CELL_GROUP: usize = 3;
/// Row-3 (term) cells: the `EcGroupAdd` provide multiplicity and the
/// hosted operand ptrs.
pub const TERM_CELL_MULT: usize = 0;
pub const TERM_CELL_P: usize = 1;
pub const TERM_CELL_Q: usize = 2;

// Periodic: one one-hot per row role.
const PCOL_SLOPE: usize = 0;
const PCOL_TAIL: usize = 1;
const PCOL_RES: usize = 2;
const PCOL_TERM: usize = 3;
const NUM_PERIODIC: usize = 4;
const ROLE_ROWS: [usize; NUM_PERIODIC] = [0, 1, 2, 3];

// Aux: four LogUp columns — three for the bindings / certificates, plus a
// fourth (the "mint column") carrying the closure-cert ptr-ordering
// Range16 checks (4 limb consumes) and the result-membership cert provide,
// all gated on `mints`.
const NUM_LOGUP_COLS: usize = 4;
const AUX_WIDTH: usize = 4;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [7, 7, 7, 5];

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct EcGroupAddAir;

impl BaseAir<Felt> for EcGroupAddAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        ROLE_ROWS
            .iter()
            .map(|&row| {
                let mut col = vec![Felt::ZERO; PERIOD];
                col[row] = Felt::ONE;
                col
            })
            .collect()
    }
}

impl LiftedAir<Felt, QuadFelt> for EcGroupAddAir {
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
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let sel: [AB::Expr; NUM_PERIODIC] = {
            let p = builder.periodic_values();
            array::from_fn(|i| p[i].into())
        };

        let pai_p: AB::Expr = local[COL_PAI_P].into();
        let pai_q: AB::Expr = local[COL_PAI_Q].into();
        let cancel: AB::Expr = local[COL_CANCEL].into();
        let dbl: AB::Expr = local[COL_DBL].into();
        let generic: AB::Expr = local[COL_GEN].into();
        let act: AB::Expr = local[COL_ACT].into();
        let mints: AB::Expr = local[COL_MINTS].into();

        // Case flags + act + mints are boolean; exactly one case per active
        // block — except `∞ + ∞`, where *both* pass flags must be set (each
        // rides its operand's consumed tuple as the `is_pai` field, and an
        // infinite operand matches no `is_pai = 0` provide). The ties below
        // then force `p = q = r`: the group's canonical PAI row.
        for flag in [&pai_p, &pai_q, &cancel, &dbl, &generic, &act, &mints] {
            builder.assert_zero(flag.clone() * (AB::Expr::ONE - flag.clone()));
        }
        builder.assert_zero(
            pai_p.clone() + pai_q.clone() + cancel + dbl + generic
                - act
                - pai_p.clone() * pai_q.clone(),
        );

        // Pass-through result ties, at the res row where r is local and
        // p / q sit in the term row's cells (next).
        let r_cell: AB::Expr = local[CELL_R].into();
        let p_cell: AB::Expr = next[TERM_CELL_P].into();
        let q_cell: AB::Expr = next[TERM_CELL_Q].into();
        builder.assert_zero(sel[PCOL_RES].clone() * pai_p * (r_cell.clone() - q_cell));
        builder.assert_zero(sel[PCOL_RES].clone() * pai_q * (r_cell - p_cell));

        // Closure-cert scaffolding (Phase 1). A mint op (its result freshly
        // allocated → strictly-maximal ptr) is pinned two ways:
        //  - case guard: mint ⟹ generic ∨ double (the only fresh-result cases). Forbids `mints` on
        //    cancel (result is the ∞ row — a high-ptr ∞ could otherwise satisfy the ordering) and
        //    on pass-throughs (result is an operand).
        //  - strict ordering: r_ptr > p_ptr ∧ r_ptr > q_ptr, via the witnessed limb diffs `r − p −
        //    1 = lo + 2¹⁶·hi` (limbs Range16-checked in the LookupAir). Read on the res row, where
        //    r is local and p / q are the term cells (next).
        let dbl_g: AB::Expr = local[COL_DBL].into();
        let gen_g: AB::Expr = local[COL_GEN].into();
        builder.assert_zero(mints.clone() * (AB::Expr::ONE - dbl_g - gen_g));
        let r_res: AB::Expr = local[CELL_R].into();
        let p_res: AB::Expr = next[TERM_CELL_P].into();
        let q_res: AB::Expr = next[TERM_CELL_Q].into();
        let two_16 = AB::Expr::from(Felt::from(1u32 << 16));
        let rp_lo: AB::Expr = local[COL_RP_LO].into();
        let rp_hi: AB::Expr = local[COL_RP_HI].into();
        let rq_lo: AB::Expr = local[COL_RQ_LO].into();
        let rq_hi: AB::Expr = local[COL_RQ_HI].into();
        let at_res: AB::Expr = sel[PCOL_RES].clone();
        builder.assert_zero(
            at_res.clone()
                * mints.clone()
                * (r_res.clone() - p_res - AB::Expr::ONE - rp_lo - two_16.clone() * rp_hi),
        );
        builder
            .assert_zero(at_res * mints * (r_res - q_res - AB::Expr::ONE - rq_lo - two_16 * rq_hi));

        // Cycle-constancy for every metadata column (the term row is the
        // block's last, so the not_term gate drops exactly at the
        // boundary).
        let not_term: AB::Expr = AB::Expr::ONE - sel[PCOL_TERM].clone();
        for col in COL_PX..NUM_MAIN_COLS {
            let here: AB::Expr = local[col].into();
            let there: AB::Expr = next[col].into();
            builder.assert_zero(not_term.clone() * (there - here));
        }

        // Phase 2: LogUp.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for EcGroupAddAir
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
        let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [LB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let sel: [LB::Expr; NUM_PERIODIC] = {
            let p = builder.periodic_values();
            array::from_fn(|i| p[i].into())
        };

        let px: LB::Expr = local[COL_PX].into();
        let py: LB::Expr = local[COL_PY].into();
        let qx: LB::Expr = local[COL_QX].into();
        let qy: LB::Expr = local[COL_QY].into();
        let a_ptr: LB::Expr = local[COL_A_PTR].into();
        let b_ptr: LB::Expr = local[COL_B_PTR].into();
        let bound: LB::Expr = local[COL_BOUND_PTR].into();
        let pai_p: LB::Expr = local[COL_PAI_P].into();
        let pai_q: LB::Expr = local[COL_PAI_Q].into();
        let cancel: LB::Expr = local[COL_CANCEL].into();
        let dbl: LB::Expr = local[COL_DBL].into();
        let generic: LB::Expr = local[COL_GEN].into();
        let act: LB::Expr = local[COL_ACT].into();
        let mints: LB::Expr = local[COL_MINTS].into();
        let rp_lo: LB::Expr = local[COL_RP_LO].into();
        let rp_hi: LB::Expr = local[COL_RP_HI].into();
        let rq_lo: LB::Expr = local[COL_RQ_LO].into();
        let rq_hi: LB::Expr = local[COL_RQ_HI].into();
        let live: LB::Expr = cancel.clone() + dbl.clone() + generic.clone();
        let tail: LB::Expr = dbl.clone() + generic.clone();
        let x_eq: LB::Expr = dbl.clone() + cancel.clone();

        let at_slope: LB::Expr = sel[PCOL_SLOPE].clone();
        let at_tail: LB::Expr = sel[PCOL_TAIL].clone();
        let at_res: LB::Expr = sel[PCOL_RES].clone();

        // Row-0 window: the slope transients (local) + the tail
        // transients (next).
        let slope_aux: LB::Expr = local[CELL_SLOPE_AUX].into();
        let lambda: LB::Expr = local[CELL_LAMBDA].into();
        let inv: LB::Expr = local[CELL_INV].into();
        let t: LB::Expr = local[CELL_T].into();
        let w: LB::Expr = next[CELL_W].into();
        let e: LB::Expr = next[CELL_E].into();
        let u_next: LB::Expr = next[CELL_U].into();
        let x3_next: LB::Expr = next[CELL_X3].into();
        // Row-1 window: the tail transients (local) + the result cells
        // (next).
        let u_local: LB::Expr = local[CELL_U].into();
        let x3_local: LB::Expr = local[CELL_X3].into();
        let y3: LB::Expr = next[CELL_Y3].into();
        let r_next: LB::Expr = next[CELL_R].into();
        let group_next: LB::Expr = next[CELL_GROUP].into();
        // Row-2 window: the result cells (local) + the term cells (next).
        let r_local: LB::Expr = local[CELL_R].into();
        let sbound: LB::Expr = local[CELL_SBOUND].into();
        let group_local: LB::Expr = local[CELL_GROUP].into();
        let neg_mult: LB::Expr = LB::Expr::ZERO - next[TERM_CELL_MULT].into();
        let p_ptr: LB::Expr = next[TERM_CELL_P].into();
        let q_ptr: LB::Expr = next[TERM_CELL_Q].into();

        let one: LB::Expr = LB::Expr::ONE;
        let zero: LB::Expr = LB::Expr::ZERO;
        let two: LB::Expr = LB::Expr::from(Felt::from(2u32));
        let three: LB::Expr = LB::Expr::from(Felt::from(3u32));

        let f2 = Deg { v: 2, u: 1 };
        let col_deg = Deg { v: 8, u: 7 };
        // Mint column: 4 Range16 consumes + 1 cert provide, each a deg-2
        // gate (at_res · mints) over a deg-1 message ⇒ over 5 fractions the
        // numerator is 2 + 4·1 = 6, denominator 5.
        let mint_col_deg = Deg { v: 6, u: 5 };

        // Col 0 (running sum): the provide + the point / group bindings,
        // all emitted in the res-row window (term cells via next), except
        // the live result consume, which needs x₃ (row 1) and y₃/r/group
        // (row 2) together — the tail-row window.
        builder.next_column(
            |col| {
                col.group(
                    "ec-add-bindings",
                    |g| {
                        g.batch(
                            "bindings",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "provide-ecgroupadd",
                                    neg_mult * at_res.clone(),
                                    EcGroupAddMsg {
                                        group_ptr: group_local.clone(),
                                        p_ptr: p_ptr.clone(),
                                        q_ptr: q_ptr.clone(),
                                        r_ptr: r_local.clone(),
                                    },
                                    f2,
                                );
                                // Operands: the case flags ARE the is_pai
                                // fields — a forged claim matches no row.
                                b.insert(
                                    "consume-ecpoint-p",
                                    act.clone() * at_res.clone(),
                                    EcPointMsg {
                                        point_ptr: p_ptr,
                                        group_ptr: group_local.clone(),
                                        x_ptr: px.clone(),
                                        y_ptr: py.clone(),
                                        is_pai: pai_p,
                                    },
                                    f2,
                                );
                                b.insert(
                                    "consume-ecpoint-q",
                                    act.clone() * at_res.clone(),
                                    EcPointMsg {
                                        point_ptr: q_ptr,
                                        group_ptr: group_local.clone(),
                                        x_ptr: qx.clone(),
                                        y_ptr: qy.clone(),
                                        is_pai: pai_q,
                                    },
                                    f2,
                                );
                                // The live result binds the computed
                                // coordinates…
                                b.insert(
                                    "consume-ecpoint-r",
                                    tail.clone() * at_tail.clone(),
                                    EcPointMsg {
                                        point_ptr: r_next,
                                        group_ptr: group_next,
                                        x_ptr: x3_local,
                                        y_ptr: y3.clone(),
                                        is_pai: zero.clone(),
                                    },
                                    f2,
                                );
                                // …and cancel resolves to the group's PAI
                                // row.
                                b.insert(
                                    "consume-ecpoint-r-pai",
                                    cancel.clone() * at_res.clone(),
                                    EcPointMsg {
                                        point_ptr: r_local,
                                        group_ptr: group_local.clone(),
                                        x_ptr: zero.clone(),
                                        y_ptr: zero.clone(),
                                        is_pai: one.clone(),
                                    },
                                    f2,
                                );
                                b.insert(
                                    "consume-ecgroup",
                                    live * at_res.clone(),
                                    EcGroupMsg {
                                        group_ptr: group_local,
                                        a_ptr: a_ptr.clone(),
                                        b_ptr: b_ptr.clone(),
                                        bound_ptr: bound.clone(),
                                        scalar_bound_ptr: sbound,
                                    },
                                    f2,
                                );
                                // cancel: y₁ + y₂ ≡ 0 — the is_c_zero
                                // negation tuple as the certificate.
                                b.insert(
                                    "consume-cancel-zero",
                                    cancel.clone() * at_res,
                                    UintAddMsg {
                                        bound_ptr: bound.clone(),
                                        a_ptr: py.clone(),
                                        b_ptr: qy.clone(),
                                        c_ptr: zero.clone(),
                                    },
                                    f2,
                                );
                            },
                            col_deg,
                        );
                    },
                    col_deg,
                );
            },
            col_deg,
        );

        // Col 1 (fractions): the slope + predicate certificates, all in
        // the slope-row window.
        builder.next_column(
            |col| {
                col.group(
                    "ec-add-slope",
                    |g| {
                        g.batch(
                            "slope",
                            LB::Expr::ONE,
                            |b| {
                                // generic: d = x₂ − x₁ (the arrangement
                                // x₁ + d ≡ x₂) and the chord λ·d + y₁ ≡ y₂.
                                b.insert(
                                    "consume-d-sub",
                                    generic.clone() * at_slope.clone(),
                                    UintAddMsg {
                                        bound_ptr: bound.clone(),
                                        a_ptr: px.clone(),
                                        b_ptr: slope_aux.clone(),
                                        c_ptr: qx.clone(),
                                    },
                                    f2,
                                );
                                b.insert(
                                    "consume-chord",
                                    generic.clone() * at_slope.clone(),
                                    UintMulMsg {
                                        kappa_a: one.clone(),
                                        kappa_c: one.clone(),
                                        a_ptr: lambda.clone(),
                                        b_ptr: slope_aux.clone(),
                                        c_ptr: py.clone(),
                                        r_ptr: qy.clone(),
                                        bound_ptr: bound.clone(),
                                    },
                                    f2,
                                );
                                // generic's disequality witness:
                                // inv·d ≡ b ≠ 0 ⟹ d ≠ 0 — what pins λ to
                                // the unique chord slope.
                                b.insert(
                                    "consume-inv-d",
                                    generic.clone() * at_slope.clone(),
                                    UintMulMsg {
                                        kappa_a: one.clone(),
                                        kappa_c: zero.clone(),
                                        a_ptr: inv.clone(),
                                        b_ptr: slope_aux.clone(),
                                        c_ptr: bound.clone(),
                                        r_ptr: b_ptr.clone(),
                                        bound_ptr: bound.clone(),
                                    },
                                    f2,
                                );
                                // double: s ≡ 3·x² + a and 2·λ·y ≡ s (the
                                // κ's carrying the tangent constants;
                                // shared r_ptr = s).
                                b.insert(
                                    "consume-tangent-s",
                                    dbl.clone() * at_slope.clone(),
                                    UintMulMsg {
                                        kappa_a: three,
                                        kappa_c: one.clone(),
                                        a_ptr: px.clone(),
                                        b_ptr: px.clone(),
                                        c_ptr: a_ptr,
                                        r_ptr: slope_aux.clone(),
                                        bound_ptr: bound.clone(),
                                    },
                                    f2,
                                );
                                b.insert(
                                    "consume-tangent-2ly",
                                    dbl.clone() * at_slope.clone(),
                                    UintMulMsg {
                                        kappa_a: two,
                                        kappa_c: zero.clone(),
                                        a_ptr: lambda.clone(),
                                        b_ptr: py.clone(),
                                        c_ptr: bound.clone(),
                                        r_ptr: slope_aux,
                                        bound_ptr: bound.clone(),
                                    },
                                    f2,
                                );
                                // double's nonzero witness: inv·y₁ ≡ b —
                                // the 2y denominator's invertibility.
                                b.insert(
                                    "consume-inv-y",
                                    dbl.clone() * at_slope.clone(),
                                    UintMulMsg {
                                        kappa_a: one.clone(),
                                        kappa_c: zero.clone(),
                                        a_ptr: inv,
                                        b_ptr: py.clone(),
                                        c_ptr: bound.clone(),
                                        r_ptr: b_ptr,
                                        bound_ptr: bound.clone(),
                                    },
                                    f2,
                                );
                                // double/cancel: x₁ = x₂ — the is_b_zero
                                // equality certificate.
                                b.insert(
                                    "consume-x-eq",
                                    x_eq * at_slope.clone(),
                                    UintAddMsg {
                                        bound_ptr: bound.clone(),
                                        a_ptr: px.clone(),
                                        b_ptr: zero.clone(),
                                        c_ptr: qx.clone(),
                                    },
                                    f2,
                                );
                            },
                            col_deg,
                        );
                    },
                    col_deg,
                );
            },
            col_deg,
        );

        // Col 2 (fractions): the shared tail, emitted from the slope-row
        // window (tail cells via next) except y₃'s sub, which fires on
        // the tail row (y₃ via next) — plus double's y-equality.
        builder.next_column(
            |col| {
                col.group(
                    "ec-add-tail",
                    |g| {
                        g.batch(
                            "tail",
                            LB::Expr::ONE,
                            |b| {
                                // w = λ².
                                b.insert(
                                    "consume-w-mul",
                                    tail.clone() * at_slope.clone(),
                                    UintMulMsg {
                                        kappa_a: one.clone(),
                                        kappa_c: zero.clone(),
                                        a_ptr: lambda.clone(),
                                        b_ptr: lambda.clone(),
                                        c_ptr: bound.clone(),
                                        r_ptr: w.clone(),
                                        bound_ptr: bound.clone(),
                                    },
                                    f2,
                                );
                                // t = x₁ + x₂ (2x via the same block when
                                // doubling).
                                b.insert(
                                    "consume-t-add",
                                    tail.clone() * at_slope.clone(),
                                    UintAddMsg {
                                        bound_ptr: bound.clone(),
                                        a_ptr: px.clone(),
                                        b_ptr: qx.clone(),
                                        c_ptr: t.clone(),
                                    },
                                    f2,
                                );
                                // x₃ + t ≡ w  (x₃ = w − t).
                                b.insert(
                                    "consume-x3-sub",
                                    tail.clone() * at_slope.clone(),
                                    UintAddMsg {
                                        bound_ptr: bound.clone(),
                                        a_ptr: t,
                                        b_ptr: x3_next.clone(),
                                        c_ptr: w,
                                    },
                                    f2,
                                );
                                // e = x₁ − x₃  (x₃ + e ≡ x₁).
                                b.insert(
                                    "consume-e-sub",
                                    tail.clone() * at_slope.clone(),
                                    UintAddMsg {
                                        bound_ptr: bound.clone(),
                                        a_ptr: x3_next,
                                        b_ptr: e.clone(),
                                        c_ptr: px,
                                    },
                                    f2,
                                );
                                // u = λ·e.
                                b.insert(
                                    "consume-u-mul",
                                    tail.clone() * at_slope,
                                    UintMulMsg {
                                        kappa_a: one,
                                        kappa_c: zero.clone(),
                                        a_ptr: lambda,
                                        b_ptr: e,
                                        c_ptr: bound.clone(),
                                        r_ptr: u_next,
                                        bound_ptr: bound.clone(),
                                    },
                                    f2,
                                );
                                // y₃ + y₁ ≡ u  (y₃ = u − y₁), on the tail
                                // row where u is local and y₃ next.
                                b.insert(
                                    "consume-y3-sub",
                                    tail * at_tail,
                                    UintAddMsg {
                                        bound_ptr: bound.clone(),
                                        a_ptr: py.clone(),
                                        b_ptr: y3,
                                        c_ptr: u_local,
                                    },
                                    f2,
                                );
                                // double: y₁ = y₂ — the second equality
                                // certificate.
                                b.insert(
                                    "consume-y-eq",
                                    dbl * sel[PCOL_SLOPE].clone(),
                                    UintAddMsg {
                                        bound_ptr: bound,
                                        a_ptr: py,
                                        b_ptr: zero,
                                        c_ptr: qy,
                                    },
                                    f2,
                                );
                            },
                            col_deg,
                        );
                    },
                    col_deg,
                );
            },
            col_deg,
        );

        // ---- col 3: the mint column. Four Range16 consumes for the limbs
        //             of r−p−1 and r−q−1 (reconstructed in the main AIR),
        //             proving r_ptr > p_ptr ∧ r_ptr > q_ptr on a mint op —
        //             the well-foundedness the certificate rests on — plus
        //             the result-membership cert *provide* itself. All gated
        //             `at_res · mints`: one set per mint block. The provide
        //             is consumed by `r`'s point-store row (`EcPointStore`),
        //             discharging its on-curve obligation without the MAC
        //             trio; the bus balances because a fresh result is minted
        //             by exactly one op.
        // The col-0 binders moved their `group_local` / `r_local`; re-read
        // the res-row group / result cells for the cert provide.
        let cert_group: LB::Expr = local[CELL_GROUP].into();
        let cert_r: LB::Expr = local[CELL_R].into();
        builder.next_column(
            |col| {
                col.group(
                    "ec-add-mint",
                    |g| {
                        g.batch(
                            "mint",
                            LB::Expr::ONE,
                            |b| {
                                let gate = sel[PCOL_RES].clone() * mints.clone();
                                b.insert(
                                    "range16-rp-lo",
                                    gate.clone(),
                                    Range16Msg { w: rp_lo },
                                    f2,
                                );
                                b.insert(
                                    "range16-rp-hi",
                                    gate.clone(),
                                    Range16Msg { w: rp_hi },
                                    f2,
                                );
                                b.insert(
                                    "range16-rq-lo",
                                    gate.clone(),
                                    Range16Msg { w: rq_lo },
                                    f2,
                                );
                                b.insert(
                                    "range16-rq-hi",
                                    gate.clone(),
                                    Range16Msg { w: rq_hi },
                                    f2,
                                );
                                // The cert provide: −1 per mint op (negative ⇒
                                // provide), naming the fresh result `r` and
                                // its group.
                                b.insert(
                                    "provide-ecgroupadd-cert",
                                    LB::Expr::ZERO - gate,
                                    EcOnCurveCertMsg { group_ptr: cert_group, r_ptr: cert_r },
                                    f2,
                                );
                            },
                            mint_col_deg,
                        );
                    },
                    mint_col_deg,
                );
            },
            mint_col_deg,
        );
    }
}
