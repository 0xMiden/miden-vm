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
//! structurally disjoint: a `y = 0` self-add cannot satisfy `double` (its
//! slope pin `2λy ≡ 3x² + a` forces `s = 0`, impossible at a smooth curve's
//! 2-torsion point), so it can only take `cancel` (`2·(2-torsion) = ∞`).
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
//! Equality (`double`/`cancel`'s `x₁ = x₂`, `double`'s `y₁ = y₂`) is a
//! **native degree-2 constraint** on the operand coordinate-ptr columns
//! (`(cancel + dbl)·(px − qx)`, `dbl·(py − qy)`). The res-row `EcPoint`
//! consumes pin those columns to the operands' stored coordinates, and
//! the uint store interns by value, so a ptr-level equality is exactly
//! value equality — no UintAdd certificate, no limbs. Disequality
//! (`generic`'s `x₁ ≠ x₂`) rides the
//! **`nz` flag on `d`'s own `UintAdd` tuple**: `d = x₂ − x₁` is already
//! recorded as the arrangement `x₁ + d ≡ x₂` (the slope transient
//! `consume-d-sub`), and demanding `nz = 1` on that same tuple certifies
//! `d ≠ 0` — a limb-level certificate carried by the subtraction that's
//! already there, no separate inverse MAC or witness.
//!
//! The λ-float attack (a forged `d = 0` letting an attacker float the
//! chord slope) dies because a `nz = 1` provide only exists when the
//! `UintAdd` chiplet's own certificate holds (`d`'s limbs sum to a
//! Goldilocks-field-invertible nonzero value — see
//! [`crate::uint::add`]'s "Nonzero certificate"), deterministically, with
//! no β-dependent fingerprint and no completeness gap.
//!
//! `double` needs **no** analogous `y₁ ≠ 0` witness: its slope pin
//! `2·λ·y₁ ≡ s` with `s = 3·x² + a` is itself the nonzero guard — at
//! `y₁ = 0` it would force `s = 0`, which a **smooth** curve never permits
//! (`3·x² + a ≠ 0` at a simple root of `x³ + ax + b`), so the λ-float
//! attack dies the same way, for free. This rests on curve smoothness
//! (`4a³ + 27b² ≠ 0`) — the same anchored-curve well-formedness premise as
//! `b ≠ 0` (both trusted from the require layer / verifier curve anchoring,
//! not proven in-circuit). For the cofactor-1 curves (secp256k1, P-256,
//! bn254-G1) it is moot — prime order admits no 2-torsion, so no stored
//! finite point ever has `y = 0`; it bites only for ed25519's cofactor-8
//! image, whose smooth 2-torsion point routes through `cancel`.
//!
//! ## Certificates (consumed tuples)
//!
//! The slope and tail arrangements are recorded as ordinary uint ops
//! and consumed here with exact κ's — `double`'s constants vanish into
//! the MAC scales (`s ≡ 3·x² + a`; `2·λ·y ≡ s` with the shared
//! `r_ptr = s`), `cancel`'s `y₁ + y₂ ≡ 0` is the `is_c_zero` `UintAdd`
//! tuple, and the shared tail (`t = x₁+x₂`, the fused `x₃ = λ²−t` and
//! `y₃ = λ·e−y₁` mul-subtracts, `e = x₁−x₃`) is identical for both live
//! cases. The result `R` is bound by consuming
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
//! | 0 `slope` | `(slope_aux, λ, —, t)` | slope + predicate certs (local), tail certs (cells @ next) |
//! | 1 `tail`  | `(y₃, e, —, x₃)` | the two fused mul-subtracts + the live result consume (`r`/`group` @ next) |
//! | 2 `res`   | `(—, r, sbound, group)` | the provide + operand/PAI/group consumes (`p`/`q`/mult @ next) |
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
        NUM_SIGMA_VALUES, frac_col,
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
/// for `double`; cell 2 is unused.
pub const CELL_SLOPE_AUX: usize = 0;
pub const CELL_LAMBDA: usize = 1;
pub const CELL_T: usize = 3;
/// Row-1 (tail) cells: the fused result `y₃`, the `x₁ − x₃` witness `e`,
/// and `x₃`; cell 2 is unused.
pub const CELL_Y3: usize = 0;
pub const CELL_E: usize = 1;
pub const CELL_X3: usize = 3;
/// Row-2 (res) cells: the hosted `r`, scalar-bound, and group ptrs; cell 0
/// is reserved.
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

// Aux: 12 columns, flattened via `frac_col!` over the 21 fractions so
// every closing constraint stays at degree ≤ 3 → `log_quotient_degree`
// = 1:
// - col 0: the `EcGroupAdd` provide, alone — the gated running-sum anchor.
// - col 1: the `p` / `q` operand `EcPoint` consumes.
// - col 2: the live-result and cancel-PAI-result `EcPoint` consumes.
// - col 3: the `EcGroup` consume + the cancel `y₁+y₂≡0` certificate.
// - col 4: the generic case's `d`-subtract + chord certificates.
// - col 5: the double case's tangent-numerator + slope-pin certificates.
// - col 6: the generic case's `t`-add + fused `x₃` mul-subtract.
// - col 7: the shared tail's `e`-subtract + fused `y₃` mul-subtract.
// - col 8: the double case's fused `x₃` mul-subtract, alone (no partner left to pair).
// - col 9/10: the closure-cert ptr-ordering Range16 limb pairs.
// - col 11: the result-membership cert provide, alone.
const NUM_LOGUP_COLS: usize = 12;
const AUX_WIDTH: usize = 12;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [1, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 1];

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

        // Operand-coordinate ties for the `x₁ = x₂` cases. The coordinate
        // ptr columns are pinned to the operands' stored coordinates by the
        // res-row `EcPoint` consumes, and the store interns by value, so
        // these ptr-level equalities are exactly the value equalities the
        // old `is_b_zero` certificates proved — at degree 2, no UintAdd op:
        //  - `x_eq` (double ∨ cancel): `x₁ = x₂`, what makes the tail's `t = x₁ + x₂` the doubling
        //    `2x₁` and grounds the chord/tangent.
        //  - `dbl`: `y₁ = y₂`, which (with `inv·y ≡ b ≠ 0` ⟹ `y ≠ 0`) rules out the `P, −P` cancel
        //    branch, so the tangent is the genuine one — an in-cell `p = q` cannot forge a wrong
        //    tangent.
        let px_eq: AB::Expr = local[COL_PX].into();
        let qx_eq: AB::Expr = local[COL_QX].into();
        let py_eq: AB::Expr = local[COL_PY].into();
        let qy_eq: AB::Expr = local[COL_QY].into();
        let cancel_eq: AB::Expr = local[COL_CANCEL].into();
        let dbl_eq: AB::Expr = local[COL_DBL].into();
        builder.assert_zero((cancel_eq + dbl_eq.clone()) * (px_eq - qx_eq));
        builder.assert_zero(dbl_eq * (py_eq - qy_eq));

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

        let at_slope: LB::Expr = sel[PCOL_SLOPE].clone();
        let at_tail: LB::Expr = sel[PCOL_TAIL].clone();
        let at_res: LB::Expr = sel[PCOL_RES].clone();

        // Row-0 (slope) window: the slope transients (local) + the tail
        // transients (next). e / x₃ / y₃ all sit on the tail row, so both
        // fused mul-subtracts read their result here in one window.
        let slope_aux: LB::Expr = local[CELL_SLOPE_AUX].into();
        let lambda: LB::Expr = local[CELL_LAMBDA].into();
        let t: LB::Expr = local[CELL_T].into();
        let e: LB::Expr = next[CELL_E].into();
        let x3_next: LB::Expr = next[CELL_X3].into();
        let y3_next: LB::Expr = next[CELL_Y3].into();
        // Row-1 (tail) window: the tail transients (local) + the result
        // cells (next).
        let x3_local: LB::Expr = local[CELL_X3].into();
        let y3_local: LB::Expr = local[CELL_Y3].into();
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
        let single_deg = Deg { v: 1, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };

        // col 0: the `EcGroupAdd` provide, alone — the gated running-sum
        // anchor.
        frac_col!(
            builder,
            "ec-add-bindings",
            single_deg,
            (
                "provide-ecgroupadd",
                neg_mult * at_res.clone(),
                EcGroupAddMsg {
                    group_ptr: group_local.clone(),
                    p_ptr: p_ptr.clone(),
                    q_ptr: q_ptr.clone(),
                    r_ptr: r_local.clone(),
                },
                f2
            ),
        );
        // col 1 (paired, lqd-1): the `p` / `q` operand `EcPoint` consumes.
        // The case flags ARE the is_pai fields — a forged claim matches no
        // row.
        frac_col!(
            builder,
            "ec-add-bindings",
            pair_deg,
            (
                "consume-ecpoint-p",
                act.clone() * at_res.clone(),
                EcPointMsg {
                    point_ptr: p_ptr.clone(),
                    group_ptr: group_local.clone(),
                    x_ptr: px.clone(),
                    y_ptr: py.clone(),
                    is_pai: pai_p,
                },
                f2
            ),
            (
                "consume-ecpoint-q",
                act.clone() * at_res.clone(),
                EcPointMsg {
                    point_ptr: q_ptr.clone(),
                    group_ptr: group_local.clone(),
                    x_ptr: qx.clone(),
                    y_ptr: qy.clone(),
                    is_pai: pai_q,
                },
                f2
            ),
        );
        // col 2 (paired, lqd-1): the live result binds the computed
        // coordinates; cancel resolves to the group's PAI row.
        frac_col!(
            builder,
            "ec-add-bindings",
            pair_deg,
            (
                "consume-ecpoint-r",
                tail.clone() * at_tail,
                EcPointMsg {
                    point_ptr: r_next,
                    group_ptr: group_next,
                    x_ptr: x3_local,
                    y_ptr: y3_local,
                    is_pai: zero.clone(),
                },
                f2
            ),
            (
                "consume-ecpoint-r-pai",
                cancel.clone() * at_res.clone(),
                EcPointMsg {
                    point_ptr: r_local,
                    group_ptr: group_local.clone(),
                    x_ptr: zero.clone(),
                    y_ptr: zero.clone(),
                    is_pai: one.clone(),
                },
                f2
            ),
        );
        // col 3 (paired, lqd-1): the group binding + cancel's `y₁+y₂≡0`
        // certificate (the is_c_zero negation tuple).
        frac_col!(
            builder,
            "ec-add-bindings",
            pair_deg,
            (
                "consume-ecgroup",
                live * at_res.clone(),
                EcGroupMsg {
                    group_ptr: group_local.clone(),
                    a_ptr: a_ptr.clone(),
                    b_ptr: b_ptr.clone(),
                    bound_ptr: bound.clone(),
                    scalar_bound_ptr: sbound,
                },
                f2
            ),
            (
                "consume-cancel-zero",
                cancel.clone() * at_res.clone(),
                UintAddMsg {
                    bound_ptr: bound.clone(),
                    a_ptr: py.clone(),
                    b_ptr: qy.clone(),
                    c_ptr: zero.clone(),
                    nz: zero.clone(),
                },
                f2
            ),
        );

        // col 4 (paired, lqd-1): generic's d = x₂ − x₁ (the arrangement
        // x₁ + d ≡ x₂, certified `d ≠ 0` — `nz = 1` — in place of the
        // separate inverse modmul disequality) and the chord λ·d + y₁ ≡ y₂.
        frac_col!(
            builder,
            "ec-add-slope",
            pair_deg,
            (
                "consume-d-sub",
                generic.clone() * at_slope.clone(),
                UintAddMsg {
                    bound_ptr: bound.clone(),
                    a_ptr: px.clone(),
                    b_ptr: slope_aux.clone(),
                    c_ptr: qx.clone(),
                    nz: one.clone(),
                },
                f2
            ),
            (
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
                    is_sub: zero.clone(),
                },
                f2
            ),
        );
        // col 5 (paired, lqd-1): double's s ≡ 3·x² + a and its slope pin
        // 2·λ·y ≡ s = 3x² + a. No `y₁ ≠ 0` witness is needed: at `y = 0`,
        // the slope pin forces `s = 3x² + a = 0`, which together with the
        // curve equation `y² = x³ + ax + b` (giving `x³ + ax + b = 0`)
        // makes `x` a common root of the curve polynomial and its
        // derivative — impossible on a smooth curve (`4a³ + 27b² ≠ 0`). A
        // `y = 0` self-add thus can only take `cancel` (2·(2-torsion) =
        // ∞); this rests on the same anchored-curve smoothness assumption
        // as the `b ≠ 0` guard the disequality MACs rest on.
        frac_col!(
            builder,
            "ec-add-slope",
            pair_deg,
            (
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
                    is_sub: zero.clone(),
                },
                f2
            ),
            (
                "consume-tangent-2ly",
                dbl.clone() * at_slope.clone(),
                UintMulMsg {
                    kappa_a: two.clone(),
                    kappa_c: zero.clone(),
                    a_ptr: lambda.clone(),
                    b_ptr: py.clone(),
                    c_ptr: bound.clone(),
                    r_ptr: slope_aux.clone(),
                    bound_ptr: bound.clone(),
                    is_sub: zero.clone(),
                },
                f2
            ),
        );
        // The double/cancel `x₁ = x₂` and double's `y₁ = y₂` equalities are
        // native degree-2 constraints (see Phase 1), so no is_b_zero certs
        // here.

        // col 6 (paired, lqd-1): the shared tail. generic forms
        // `t = x₁ + x₂` then the fused `x₃ = λ² − t`. Mutually exclusive
        // with double's fused x₃ (col 8) — exactly one fires per live op.
        frac_col!(
            builder,
            "ec-add-tail",
            pair_deg,
            (
                "consume-t-add",
                generic.clone() * at_slope.clone(),
                UintAddMsg {
                    bound_ptr: bound.clone(),
                    a_ptr: px.clone(),
                    b_ptr: qx.clone(),
                    c_ptr: t.clone(),
                    nz: zero.clone(),
                },
                f2
            ),
            (
                "consume-x3-macsub-gen",
                generic.clone() * at_slope.clone(),
                UintMulMsg {
                    kappa_a: one.clone(),
                    kappa_c: one.clone(),
                    a_ptr: lambda.clone(),
                    b_ptr: lambda.clone(),
                    c_ptr: t,
                    r_ptr: x3_next.clone(),
                    bound_ptr: bound.clone(),
                    is_sub: one.clone(),
                },
                f2
            ),
        );
        // col 7 (paired, lqd-1): e = x₁ − x₃ (x₃ + e ≡ x₁), then the fused
        // y₃ = λ·e − y₁ — shared by both live cases.
        frac_col!(
            builder,
            "ec-add-tail",
            pair_deg,
            (
                "consume-e-sub",
                tail.clone() * at_slope.clone(),
                UintAddMsg {
                    bound_ptr: bound.clone(),
                    a_ptr: x3_next.clone(),
                    b_ptr: e.clone(),
                    c_ptr: px.clone(),
                    nz: zero.clone(),
                },
                f2
            ),
            (
                "consume-y3-macsub",
                tail * at_slope.clone(),
                UintMulMsg {
                    kappa_a: one.clone(),
                    kappa_c: one.clone(),
                    a_ptr: lambda.clone(),
                    b_ptr: e,
                    c_ptr: py.clone(),
                    r_ptr: y3_next,
                    bound_ptr: bound.clone(),
                    is_sub: one.clone(),
                },
                f2
            ),
        );
        // col 8: double's fused x₃ = λ² − 2·x₁, alone (no partner left to
        // pair) — folds `t = 2x₁` into the mul-subtract (κ_c = 2, c = x₁),
        // laying no separate `t` add.
        frac_col!(
            builder,
            "ec-add-tail",
            single_deg,
            (
                "consume-x3-macsub-dbl",
                dbl * at_slope,
                UintMulMsg {
                    kappa_a: one.clone(),
                    kappa_c: two,
                    a_ptr: lambda.clone(),
                    b_ptr: lambda,
                    c_ptr: px,
                    r_ptr: x3_next,
                    bound_ptr: bound.clone(),
                    is_sub: one,
                },
                f2
            ),
        );

        // ---- col 9/10: the mint columns. Four Range16 consumes for the
        //      limbs of r−p−1 and r−q−1 (reconstructed in the main AIR),
        //      proving r_ptr > p_ptr ∧ r_ptr > q_ptr on a mint op — the
        //      well-foundedness the certificate rests on. All gated
        //      `at_res · mints`: one set per mint block.
        let gate = sel[PCOL_RES].clone() * mints;
        frac_col!(
            builder,
            "ec-add-mint",
            pair_deg,
            ("range16-rp-lo", gate.clone(), Range16Msg { w: rp_lo }, f2),
            ("range16-rp-hi", gate.clone(), Range16Msg { w: rp_hi }, f2),
        );
        frac_col!(
            builder,
            "ec-add-mint",
            pair_deg,
            ("range16-rq-lo", gate.clone(), Range16Msg { w: rq_lo }, f2),
            ("range16-rq-hi", gate.clone(), Range16Msg { w: rq_hi }, f2),
        );
        // col 11: the result-membership cert provide, alone. −1 per mint
        // op (negative ⇒ provide), naming the fresh result `r` and its
        // group. Consumed by `r`'s point-store row (`EcPointStore`),
        // discharging its on-curve obligation without the MAC trio; the
        // bus balances because a fresh result is minted by exactly one op.
        let cert_group: LB::Expr = local[CELL_GROUP].into();
        let cert_r: LB::Expr = local[CELL_R].into();
        frac_col!(
            builder,
            "ec-add-mint",
            single_deg,
            (
                "provide-ecgroupadd-cert",
                LB::Expr::ZERO - gate,
                EcOnCurveCertMsg { group_ptr: cert_group, r_ptr: cert_r },
                f2
            ),
        );
    }
}
