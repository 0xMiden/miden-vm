//! EcGroupAdd chiplet — complete point addition over the [EC stores](crate::precompiles::ec).
//!
//! One operation proves `R = P + Q` for any stored operands by selecting from five cases. The AIR
//! consumes pointer-level certificates from the uint relation chiplets, so coordinate limbs do not
//! enter this trace. It constrains the selected case and binds the corresponding certificates to
//! the result.
//! ## The case lattice
//!
//! | case      | condition                              | result                    |
//! |-----------|----------------------------------------|---------------------------|
//! | `pai_p`   | `P = ∞`                                | `r_ptr = q_ptr` (tie)     |
//! | `pai_q`   | `Q = ∞`                                | `r_ptr = p_ptr` (tie)     |
//! | `cancel`  | finite, `x₁ = x₂`, `y₁ + y₂ ≡ 0`       | `R` = the group's PAI row |
//! | `double`  | finite, `x₁ = x₂`, `y₁ = y₂`, `y₁ ≠ 0` | tangent                   |
//! | `generic` | finite, `x₁ ≠ x₂`                      | chord                     |
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
//! A forged `d = 0` cannot leave the chord slope unconstrained because an `nz = 1` provider exists
//! only when the `UintAdd` chiplet's own certificate holds (`d`'s limbs sum to a
//! Goldilocks-field-invertible nonzero value — see
//! [`crate::precompiles::uint::add`]'s "Nonzero certificate"), deterministically, with
//! no β-dependent fingerprint and no completeness gap.
//!
//! `double` needs no separate `y₁ ≠ 0` witness: its slope pin
//! `2·λ·y₁ ≡ s` with `s = 3·x² + a` is itself the nonzero guard — at
//! `y₁ = 0` it would force `s = 0`, which a **smooth** curve never permits
//! (`3·x² + a ≠ 0` at a simple root of `x³ + ax + b`), so the slope remains constrained. This
//! relies on curve smoothness
//! (`4a³ + 27b² ≠ 0`) — the same anchored-curve well-formedness premise as
//! `b ≠ 0` (both trusted from the require layer / verifier curve anchoring,
//! not proven in-circuit). For the cofactor-1 curves (secp256k1, P-256,
//! bn254-G1) prime order admits no 2-torsion, so no stored finite point has `y = 0`. The case is
//! relevant only to the cofactor-8 image of ed25519, whose smooth 2-torsion point routes through
//! `cancel`.
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
//! Period **4**, 3 ptr cells/row (each row's 3 live transients/hosted
//! scalars fill the row exactly — no dead cell), one add op per block,
//! all-zero `act = 0` blocks as padding, read through the two-row
//! windows:
//!
//! | row       | cells 0–2            | emits                                                     |
//! |-----------|----------------------|-----------------------------------------------------------|
//! | 0 `slope` | `(slope_aux, λ, t)`  | slope/predicate certs; tail certs @ next                  |
//! | 1 `tail`  | `(y₃, e, x₃)`        | fused mul-subtracts; result consume (`r`/`group` @ next)  |
//! | 2 `res`   | `(r, sbound, group)` | provide; operand/PAI/group consumes (`p`/`q`/mult @ next) |
//! | 3 `term`  | `(mult, p, q)`       | `Range16`: `r − q − 1` limbs; constancy gate is zero      |
//!
//! The 21 main columns comprise three row-hosted cells, four operand-coordinate pointers, three
//! curve-parameter pointers, five case flags, `act`, `mints`, two reused ordering-limb cells, and
//! the beta/lambda pointers. The AIR also uses eight LogUp auxiliary columns and four periodic
//! one-hots.

use alloc::{borrow::Cow, vec, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::air::{BaseAir, LiftedAir, LiftedAirBuilder};
use miden_utils_sync::LazyLock;

use miden_stark::lookup::{
    Challenges,
    ConstraintLookupBuilder,
    Deg,
    LookupAir,
    LookupBatch,
    LookupBuilder,
    LookupColumn,
    LookupGroup,
    LookupMessage,
};
use crate::precompiles::{
    ec::{EcGroupMsg, EcPointMsg},
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS, frac_col},
    primitives::byte_pair_lut::Range16Msg,
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::{
        add::UintAddMsg,
        mul::UintMulMsg,
    },
    utils::{current_main, next_main},
};

// MESSAGES
// ================================================================================================

/// LogUp message for the [`EcGroupAdd`](BusId::EcGroupAdd) relation: the
/// 4-tuple `(group_ptr, p_ptr, q_ptr, r_ptr)` asserting `R = P + Q` in
/// the group. Provided here and consumed by transcript-eval and MSM relation AIRs.
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

/// Ptr cells per row (transients / hosted scalars by row role): each row
/// fills all 3 exactly, no dead cell.
pub const NUM_CELLS: usize = 3;
/// Operand coordinate ptrs (0 for a PAI operand, matching its store row).
pub const COL_PX: usize = 3;
pub const COL_PY: usize = 4;
pub const COL_QX: usize = 5;
pub const COL_QY: usize = 6;
/// Curve params + base-field modulus (read by certificates on rows 0–2).
pub const COL_A_PTR: usize = 7;
pub const COL_B_PTR: usize = 8;
pub const COL_BOUND_PTR: usize = 9;
/// The case near-one-hot (cycle-constant; Σ = act + pai_p·pai_q).
pub const COL_PAI_P: usize = 10;
pub const COL_PAI_Q: usize = 11;
pub const COL_CANCEL: usize = 12;
pub const COL_DBL: usize = 13;
pub const COL_GEN: usize = 14;
pub const COL_ACT: usize = 15;
/// Fresh-mint flag (closure certificate, Phase 1): set iff this op is the
/// *first* to mint its result point (`add_point_at` miss) on a generic /
/// double case — the op that owns `r`'s membership certificate. Witnessed,
/// pinned by the case guard `mints ⟹ generic ∨ double` and the strict
/// ordering `mints ⟹ r_ptr > p_ptr ∧ r_ptr > q_ptr` below. Cycle-constant.
pub const COL_MINTS: usize = 16;
/// Limbs of `r_ptr − p_ptr − 1` (16-bit lo / hi) — the witnessed,
/// Range16-checked difference proving `r_ptr > p_ptr` on `mints` ops. 0 off
/// mint ops. Hosted on the result row.
pub const COL_RP_LO: usize = 17;
pub const COL_RP_HI: usize = 18;
/// Limbs of `r_ptr − q_ptr − 1` — proving `r_ptr > q_ptr`. Hosted in the same cells
/// on the term row, visible through the result row's next-row window.
pub const COL_RQ_LO: usize = COL_RP_LO;
pub const COL_RQ_HI: usize = COL_RP_HI;
/// The group's GLV endomorphism `β`/`λ` ptrs (carried only to close the
/// `EcGroup` consume; the none-sentinel 0 for a group with no
/// endomorphism).
pub const COL_BETA_PTR: usize = 19;
pub const COL_LAMBDA_PTR: usize = 20;
pub const NUM_MAIN_COLS: usize = 21;

/// Block period: one add op = 4 rows.
pub const PERIOD: usize = 4;

// Row roles.
pub const ROW_SLOPE: usize = 0;
pub const ROW_TAIL: usize = 1;
pub const ROW_RES: usize = 2;
pub const ROW_TERM: usize = 3;

/// Row-0 cells: `slope_aux` is `d = x₂ − x₁` for `generic`, `s = 3x² + a`
/// for `double`; `t = x₁ + x₂` (generic only — double folds `t = 2x₁`
/// directly into the tail's mul-subtract instead).
pub const CELL_SLOPE_AUX: usize = 0;
pub const CELL_LAMBDA: usize = 1;
pub const CELL_T: usize = 2;
/// Row-1 (tail) cells: the fused result `y₃`, the `x₁ − x₃` witness `e`,
/// and `x₃`.
pub const CELL_Y3: usize = 0;
pub const CELL_E: usize = 1;
pub const CELL_X3: usize = 2;
/// Row-2 (res) cells: the hosted `r`, scalar-bound, and group ptrs.
pub const CELL_R: usize = 0;
pub const CELL_SBOUND: usize = 1;
pub const CELL_GROUP: usize = 2;
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

// Three selector groups hold one fraction per active row; five ordinary columns hold two
// fractions each. Column zero is the centered accumulator. Every closing constraint has degree
// three, so the AIR retains a twofold quotient evaluation domain.
const NUM_LOGUP_COLS: usize = 8;
const AUX_WIDTH: usize = NUM_LOGUP_COLS;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [1, 1, 1, 2, 2, 2, 2, 2];

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct EcGroupAddAir;

static PERIODIC_COLUMNS: LazyLock<[Vec<Felt>; NUM_PERIODIC]> = LazyLock::new(|| {
    array::from_fn(|i| {
        let mut col = vec![Felt::ZERO; PERIOD];
        col[ROLE_ROWS[i]] = Felt::ONE;
        col
    })
});

impl BaseAir<Felt> for EcGroupAddAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Borrowed(PERIODIC_COLUMNS.as_slice())
    }
}

impl LiftedAir<Felt, QuadFelt> for EcGroupAddAir {
    fn max_periodic_length(&self) -> usize {
        PERIOD
    }

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
        miden_stark::lookup::build_logup_aux_trace(&EcGroupAddAir, main, challenges)
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
                - act.clone()
                - pai_p.clone() * pai_q.clone(),
        );

        // Operand-coordinate ties for the `x₁ = x₂` cases. The coordinate
        // ptr columns are pinned to the operands' stored coordinates by the
        // res-row `EcPoint` consumes, and the store interns by value. These
        // pointer equalities therefore establish the required value equalities at degree two:
        //  - `x_eq` (double ∨ cancel): `x₁ = x₂`, what makes the tail's `t = x₁ + x₂` the doubling
        //    `2x₁` and grounds the chord/tangent.
        //  - `dbl`: `y₁ = y₂`. The tangent lookups below rule out zero y on the authenticated
        //    smooth curve, so this case cannot substitute the cancellation branch.
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
        let rq_lo: AB::Expr = next[COL_RQ_LO].into();
        let rq_hi: AB::Expr = next[COL_RQ_HI].into();
        let at_res: AB::Expr = sel[PCOL_RES].clone();
        builder.assert_zero(at_res.clone() * (AB::Expr::ONE - act) * next[TERM_CELL_MULT].into());
        builder.assert_zero(
            at_res.clone()
                * mints.clone()
                * (r_res.clone() - p_res - AB::Expr::ONE - rp_lo - two_16.clone() * rp_hi),
        );
        builder
            .assert_zero(at_res * mints * (r_res - q_res - AB::Expr::ONE - rq_lo - two_16 * rq_hi));

        // Cycle-constancy for metadata, excluding the row-hosted ordering limbs (the term row is
        // the block's last, so the not_term gate drops exactly at the
        // boundary).
        let not_term: AB::Expr = AB::Expr::ONE - sel[PCOL_TERM].clone();
        for col in (COL_PX..COL_RP_LO).chain(COL_BETA_PTR..NUM_MAIN_COLS) {
            let here: AB::Expr = local[col].into();
            let there: AB::Expr = next[col].into();
            builder.assert_zero(not_term.clone() * (there - here));
        }

        // Phase 2: LogUp.
        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for EcGroupAddAir
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
        let beta_ptr: LB::Expr = local[COL_BETA_PTR].into();
        let lambda_ptr: LB::Expr = local[COL_LAMBDA_PTR].into();
        let pai_p: LB::Expr = local[COL_PAI_P].into();
        let pai_q: LB::Expr = local[COL_PAI_Q].into();
        let cancel: LB::Expr = local[COL_CANCEL].into();
        let dbl: LB::Expr = local[COL_DBL].into();
        let generic: LB::Expr = local[COL_GEN].into();
        let act: LB::Expr = local[COL_ACT].into();
        let mints: LB::Expr = local[COL_MINTS].into();
        let rp_lo: LB::Expr = local[COL_RP_LO].into();
        let rp_hi: LB::Expr = local[COL_RP_HI].into();
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
        let group_deg = Deg { v: 2, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };
        let cert_group: LB::Expr = local[CELL_GROUP].into();
        let cert_r: LB::Expr = local[CELL_R].into();
        let cert_gate = sel[PCOL_RES].clone() * mints.clone();
        let gate = (sel[PCOL_RES].clone() + sel[PCOL_TERM].clone()) * mints;

        // Each group selects at most one affine denominator, so its closing constraint has
        // degree three. Row roles are fixed one-hots. The Boolean case flags and their sum
        // equation make generic, double, and cancel disjoint, including the two-PAI case.
        builder.next_column(
            |column| {
                column.group(
                    "ec-add-rows",
                    |group| {
                        group.insert(
                            "provide-ecgroupadd",
                            at_res.clone(),
                            neg_mult,
                            || EcGroupAddMsg {
                                group_ptr: group_local.clone(),
                                p_ptr: p_ptr.clone(),
                                q_ptr: q_ptr.clone(),
                                r_ptr: r_local.clone(),
                            },
                            group_deg,
                        );
                        group.insert(
                            "consume-ecpoint-r",
                            at_tail,
                            tail.clone(),
                            || EcPointMsg {
                                point_ptr: r_next,
                                group_ptr: group_next,
                                x_ptr: x3_local,
                                y_ptr: y3_local,
                                is_pai: zero.clone(),
                            },
                            group_deg,
                        );
                        group.insert(
                            "consume-e-sub",
                            at_slope.clone(),
                            tail.clone(),
                            || UintAddMsg {
                                bound_ptr: bound.clone(),
                                a_ptr: x3_next.clone(),
                                b_ptr: e.clone(),
                                c_ptr: px.clone(),
                                nz: zero.clone(),
                            },
                            group_deg,
                        );
                    },
                    group_deg,
                );
            },
            group_deg,
        );
        builder.next_column(
            |column| {
                column.group(
                    "ec-add-cases",
                    |group| {
                        group.insert(
                            "consume-d-sub",
                            generic.clone(),
                            at_slope.clone(),
                            || UintAddMsg {
                                bound_ptr: bound.clone(),
                                a_ptr: px.clone(),
                                b_ptr: slope_aux.clone(),
                                c_ptr: qx.clone(),
                                nz: one.clone(),
                            },
                            group_deg,
                        );
                        group.insert(
                            "consume-tangent-s",
                            dbl.clone(),
                            at_slope.clone(),
                            || UintMulMsg {
                                kappa_a: three,
                                kappa_c: one.clone(),
                                a_ptr: px.clone(),
                                b_ptr: px.clone(),
                                c_ptr: a_ptr.clone(),
                                r_ptr: slope_aux.clone(),
                                bound_ptr: bound.clone(),
                                is_sub: zero.clone(),
                            },
                            group_deg,
                        );
                        group.insert(
                            "consume-ecpoint-r-pai",
                            cancel.clone(),
                            at_res.clone(),
                            || EcPointMsg {
                                point_ptr: r_local,
                                group_ptr: group_local.clone(),
                                x_ptr: zero.clone(),
                                y_ptr: zero.clone(),
                                is_pai: one.clone(),
                            },
                            group_deg,
                        );
                    },
                    group_deg,
                );
            },
            group_deg,
        );
        builder.next_column(
            |column| {
                column.group(
                    "ec-add-cases",
                    |group| {
                        group.insert(
                            "consume-chord",
                            generic.clone(),
                            at_slope.clone(),
                            || UintMulMsg {
                                kappa_a: one.clone(),
                                kappa_c: one.clone(),
                                a_ptr: lambda.clone(),
                                b_ptr: slope_aux.clone(),
                                c_ptr: py.clone(),
                                r_ptr: qy.clone(),
                                bound_ptr: bound.clone(),
                                is_sub: zero.clone(),
                            },
                            group_deg,
                        );
                        // Together with consume-tangent-s, zero y would force 3*x^2 + a = 0.
                        // An authenticated point with y = 0 cannot satisfy this on a smooth
                        // curve, so doubling needs no separate nonzero-y witness.
                        group.insert(
                            "consume-tangent-2ly",
                            dbl.clone(),
                            at_slope.clone(),
                            || UintMulMsg {
                                kappa_a: two.clone(),
                                kappa_c: zero.clone(),
                                a_ptr: lambda.clone(),
                                b_ptr: py.clone(),
                                c_ptr: bound.clone(),
                                r_ptr: slope_aux.clone(),
                                bound_ptr: bound.clone(),
                                is_sub: zero.clone(),
                            },
                            group_deg,
                        );
                        group.insert(
                            "consume-cancel-zero",
                            cancel,
                            at_res.clone(),
                            || UintAddMsg {
                                bound_ptr: bound.clone(),
                                a_ptr: py.clone(),
                                b_ptr: qy.clone(),
                                c_ptr: zero.clone(),
                                nz: zero.clone(),
                            },
                            group_deg,
                        );
                    },
                    group_deg,
                );
            },
            group_deg,
        );
        // Authenticate both operands, including their point-at-infinity flags.
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
        // Bind curve parameters and the generic x-coordinate sum.
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
                    beta_ptr: beta_ptr.clone(),
                    lambda_ptr: lambda_ptr.clone(),
                },
                f2
            ),
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
        );
        // Authenticate the generic x result and the shared y result.
        frac_col!(
            builder,
            "ec-add-tail",
            pair_deg,
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
        // Authenticate the doubled x result and provide any fresh membership certificate.
        frac_col!(
            builder,
            "ec-add-tail",
            pair_deg,
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
            (
                "provide-ecgroupadd-cert",
                LB::Expr::ZERO - cert_gate,
                EcOnCurveCertMsg { group_ptr: cert_group, r_ptr: cert_r },
                f2
            ),
        );
        // Check both ordering limbs on result and term rows to ground certificate induction.
        frac_col!(
            builder,
            "ec-add-mint",
            pair_deg,
            ("range16-order-lo", gate.clone(), Range16Msg { w: rp_lo }, f2),
            ("range16-order-hi", gate, Range16Msg { w: rp_hi }, f2),
        );
    }
}
