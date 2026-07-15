//! EcMsm chiplet — symbolic multi-scalar-multiplication expressions.
//!
//! A **term** is a pair `(base_ptr, scalar_ptr)` ("`P × s`", the scalar
//! under the group's scalar bound); an **expression** is a run of term
//! rows sharing one `expr_ptr`, carrying a **value** point `val_ptr` with
//! the invariant `deref(val_ptr) = Σ deref(s)·deref(P)`. The prover lays
//! any addition chain via three rules — `intro` (`⟨P×1⟩`, val = P), `neg`
//! (every scalar negated), `combine` (term multisets union, scalars on a
//! shared base merge mod `n`, values add) — and the AIR checks only that
//! each step is sound, never which steps were taken.
//!
//! Layout is **variable-block** (the stack's first): one term per row, an
//! expression is a maximal run sharing `expr_ptr`, and the allocator chain
//! `expr_ptr' = expr_ptr + is_boundary` (with `is_boundary` marking the
//! run's last row) makes ptrs injective for free — the EcGroups idiom
//! generalized. Expression-level traffic (the `MsmExpr` head, the value
//! `EcGroupAdd`, the operand heads, the ordering checks) fires on the
//! boundary row, where the final cursors are co-resident.
//!
//! Soundness rests on **strict pointer ordering** (`a_expr < expr`,
//! `b_expr < expr` on every combine — grounds the induction against
//! circular derivations) and on `scalar_bound = #E` (the full curve order
//! annihilates every point, so the merge's `mod n` wrap is harmless —
//! cofactor-agnostic). See `docs/chiplets/ec-msm.md`.
//!
//! `intro`, `combine`, and `neg` build the expression; the eval `EcMsm`
//! absorb seam resolves a claim in-circuit, consuming the positionless
//! `MsmClaimTerm` set so the absorb — and the transcript root — follow the
//! caller's declared term order, not the chiplet's `idx` storage order.

pub mod require;
pub mod trace;

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    ec::{
        EcGroupMsg, EcPointMsg,
        add::{EcGroupAddMsg, EcOnCurveCertMsg},
    },
    logup::{
        Challenges, CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder,
        LookupColumn, LookupGroup, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
        NUM_SIGMA_VALUES, frac_col,
    },
    primitives::byte_pair_lut::Range16Msg,
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::{UintValMsg, add::UintAddMsg},
    utils::{current_main, next_main},
};

// MESSAGES
// ================================================================================================

/// LogUp message for the [`MsmTerm`](BusId::MsmTerm) relation: one term
/// `(expr_ptr, idx, base_ptr, scalar_ptr)` of an MSM expression — the
/// point `base_ptr` scaled by the stored uint `scalar_ptr`, at position
/// `idx` in expression `expr_ptr`. Provided once per term row at the
/// expression's use count; consumed by combine's term walk and by the
/// eval `EcMsm` absorb seam.
#[derive(Debug, Clone)]
pub struct MsmTermMsg<E> {
    pub expr_ptr: E,
    pub idx: E,
    pub base_ptr: E,
    pub scalar_ptr: E,
}

impl<E, EF> LookupMessage<E, EF> for MsmTermMsg<E>
where
    E: miden_core::field::Algebra<E>,
    EF: miden_core::field::Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::MsmTerm as usize,
            [
                self.expr_ptr.clone(),
                self.idx.clone(),
                self.base_ptr.clone(),
                self.scalar_ptr.clone(),
            ],
        )
    }
}

/// LogUp message for the [`MsmExpr`](BusId::MsmExpr) relation: the head
/// `(expr_ptr, group_ptr, val_ptr, k)` of an MSM expression — its `k`
/// terms sum (under `group_ptr`) to the stored point `val_ptr`. Provided
/// once per expression on its boundary row; consumed as an operand head
/// by combine/neg and at the eval `EcMsm` resolve.
#[derive(Debug, Clone)]
pub struct MsmExprMsg<E> {
    pub expr_ptr: E,
    pub group_ptr: E,
    pub val_ptr: E,
    pub k: E,
}

impl<E, EF> LookupMessage<E, EF> for MsmExprMsg<E>
where
    E: miden_core::field::Algebra<E>,
    EF: miden_core::field::Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::MsmExpr as usize,
            [
                self.expr_ptr.clone(),
                self.group_ptr.clone(),
                self.val_ptr.clone(),
                self.k.clone(),
            ],
        )
    }
}

/// LogUp message for the [`MsmClaimTerm`](BusId::MsmClaimTerm) relation:
/// one **positionless** term `(expr_ptr, base_ptr, scalar_ptr)` of an MSM
/// expression — the resolve-seam twin of [`MsmTermMsg`] without the `idx`
/// field. Provided once per term row at the expression's **resolve** use
/// count (`COL_CLAIM_MULT`); consumed by the eval `EcMsm` absorb seam,
/// which matches the claim's terms as an unordered set so the DAG absorb
/// order (and root) is the caller's, not the chiplet's `idx` storage order.
#[derive(Debug, Clone)]
pub struct MsmClaimTermMsg<E> {
    pub expr_ptr: E,
    pub base_ptr: E,
    pub scalar_ptr: E,
}

impl<E, EF> LookupMessage<E, EF> for MsmClaimTermMsg<E>
where
    E: miden_core::field::Algebra<E>,
    EF: miden_core::field::Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::MsmClaimTerm as usize,
            [self.expr_ptr.clone(), self.base_ptr.clone(), self.scalar_ptr.clone()],
        )
    }
}

// COLUMN LAYOUT
// ================================================================================================

/// Row-active flag (pads are all-zero tail rows; `mult = 0` self-gates the
/// provides, so no other gate needs it).
pub const COL_ACT: usize = 0;
/// Expression ptr — constant within a run, `+1` after each boundary
/// (`expr_ptr' = expr_ptr + is_boundary`); `1` on the first row.
pub const COL_EXPR_PTR: usize = 1;
/// Marks the last row of an expression's run; drives the allocator and
/// gates the expression-level (head / value / ordering) traffic.
pub const COL_IS_BOUNDARY: usize = 2;
/// The owning group's ptr (constant within a run).
pub const COL_GROUP_PTR: usize = 3;
/// The group's scalar-bound ptr (`= #E − 1`'s store ptr; constant within a
/// run). The bound every scalar (and merge) lives under.
pub const COL_SBOUND_PTR: usize = 4;
/// This term's position in the run (`0, 1, …`; resets to 0 at each run
/// start). The boundary's `idx + 1` is the expression's term count `k`.
pub const COL_IDX: usize = 5;
/// This term's base point ptr.
pub const COL_BASE: usize = 6;
/// This term's scalar ptr.
pub const COL_SCALAR: usize = 7;
/// The expression's value point ptr (constant within a run).
pub const COL_VAL: usize = 8;
/// **Op** use count — how often this expression is consumed as a
/// `combine` / `neg` operand. Drives the `MsmTerm` provide (every term
/// row) and part of the `MsmExpr` provide; constant within a run, 0 on
/// pads. (The eval resolve uses [`COL_CLAIM_MULT`] instead, so the two
/// consumers of a claim — combine-operand vs DAG-resolve — bill separate
/// provides.)
pub const COL_MULT: usize = 9;
/// Op-family one-hot (constant within a run): `is_intro + is_combine =
/// act`.
pub const COL_IS_INTRO: usize = 10;
pub const COL_IS_COMBINE: usize = 11;

// --- combine-only columns (0 on intro / pad rows) ---------------------
/// Operand A / B expression ptrs (constant within a combine run).
pub const COL_A_EXPR: usize = 12;
pub const COL_B_EXPR: usize = 13;
/// Merge-walk cursors into A / B (threaded within the run; 0 at run
/// start). The boundary's `i + take_a + take_both` is `k_a` (and likewise
/// `k_b`), tying the operand-head consume to its term count.
pub const COL_I: usize = 14;
pub const COL_J: usize = 15;
/// Per-row take one-hot: `take_a + take_b + take_both = is_combine`.
pub const COL_TAKE_A: usize = 16;
pub const COL_TAKE_B: usize = 17;
pub const COL_TAKE_BOTH: usize = 18;
/// Operand term cells consumed from `MsmTerm(A, i, …)` / `MsmTerm(B, j,
/// …)` (gated by the take flags).
pub const COL_BASE_A: usize = 19;
pub const COL_S_A: usize = 20;
pub const COL_BASE_B: usize = 21;
pub const COL_S_B: usize = 22;
/// Operand values (constant within a run; the boundary's `EcGroupAdd`
/// asserts `val = val_a + val_b`).
pub const COL_VAL_A: usize = 23;
pub const COL_VAL_B: usize = 24;
/// Group curve params, carried only to close the boundary's `EcGroup`
/// consume that pins `sbound` to the group (constant within a run).
pub const COL_A_PTR: usize = 25;
pub const COL_B_PTR: usize = 26;
pub const COL_BOUND_PTR: usize = 27;
/// Ordering witnesses (boundary): `expr − a_expr − 1 = a_diff_lo + 2¹⁶·
/// a_diff_hi ≥ 0`, each half range-checked — enforces `a_expr < expr`
/// (and `b_expr < expr`), the well-founded order.
pub const COL_A_DIFF_LO: usize = 28;
pub const COL_A_DIFF_HI: usize = 29;
pub const COL_B_DIFF_LO: usize = 30;
pub const COL_B_DIFF_HI: usize = 31;

// --- neg-only columns (0 on intro / combine / pad rows) ---------------
/// Op-family flag for `neg` — the third one-hot member (`is_intro +
/// is_combine + is_neg = act`). A `neg` is a **unary** walk over operand A:
/// one output term per A term, the base copied and the scalar negated (the
/// `is_c_zero` `UintAdd` `s_a + out_scalar ≡ 0`), the value negated via the
/// cancel `EcGroupAdd(group, val_a, val, ∞)`.
pub const COL_IS_NEG: usize = 32;
/// Neg-value cell (boundary only): the **shared x ptr** of the cheap value
/// negation `R = (x_a, −y_a)` — both the `EcPoint(val_a)` and `EcPoint(R)`
/// consumes carry it, so they pin `x_R = x_a` for free. (Reuses the slot the
/// old cancel-`EcGroupAdd` ∞ result used.)
pub const COL_NEG_X: usize = 33;
/// **Resolve** use count — how often this expression is resolved at the
/// eval `EcMsm` seam. Drives the `MsmClaimTerm` provide (every term row)
/// and the rest of the `MsmExpr` provide; constant within a run, 0 on
/// pads. Split from [`COL_MULT`] because the resolve seam consumes the
/// positionless `MsmClaimTerm` (set match) while combine consumes
/// `MsmTerm` (by `idx`) — disjoint consumers, distinct multiplicities.
pub const COL_CLAIM_MULT: usize = 34;
/// Neg-value cells (boundary only): the two y ptrs of `R = (x_a, −y_a)` —
/// `COL_NEG_YA = val_a.y`, `COL_NEG_YR = R.y` — pinned by the `EcPoint`
/// consumes and tied by the `is_c_zero` `UintAdd(y_a, y_R ≡ 0)` (the y-flip).
pub const COL_NEG_YA: usize = 35;
pub const COL_NEG_YR: usize = 36;
/// Neg-value flag (boundary only): 1 iff this neg freshly mints `R`, gating
/// the `EcOnCurveCert(group, R)` provide that vouches R's (trio-free)
/// membership — R on-curve because `val_a` is.
pub const COL_NEG_MINTED: usize = 37;
pub const NUM_MAIN_COLS: usize = 38;

// Aux: 11 columns, flattened via `frac_col!` over the 20 fractions so
// every closing constraint stays at degree ≤ 3 → `log_quotient_degree` =
// 1 (folding the intermediate 12-column flatten and the follow-on
// singleton-pack into one step):
//  col 0:  MsmTerm provide — alone, the gated running-sum anchor.
//  col 1:  MsmExpr provide + MsmClaimTerm provide.
//  col 2:  EcOnCurveCert provide (neg value R) + literal-1 UintVal (intro, one full-value message).
//  col 3:  MsmTerm consume A — alone, now that the literal-1 UintVal merged into col 2.
//  col 4:  MsmTerm consume B + UintAdd (take_both merge).
//  col 5:  UintAdd (neg scalar) + UintAdd (neg value y-flip).
//  col 6:  MsmExpr consume A (head) + MsmExpr consume B (head).
//  col 7:  EcGroupAdd (combine value) + EcPoint(val_a) (neg value coord).
//  col 8:  EcPoint(R) (neg value coord) + EcGroup (sbound pin).
//  col 9:  ordering Range16 — a_lo + a_hi.
//  col 10: ordering Range16 — b_lo + b_hi.
const NUM_LOGUP_COLS: usize = 11;
const AUX_WIDTH: usize = 11;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [1, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2];
/// `2¹⁶`, the high-half weight in the ordering decomposition.
const TWO16: u32 = 1 << 16;

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct EcMsmAir;

impl BaseAir<Felt> for EcMsmAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl LiftedAir<Felt, QuadFelt> for EcMsmAir {
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

        let act: AB::Expr = local[COL_ACT].into();
        let act_next: AB::Expr = next[COL_ACT].into();
        let is_boundary: AB::Expr = local[COL_IS_BOUNDARY].into();
        let is_intro: AB::Expr = local[COL_IS_INTRO].into();
        let is_combine: AB::Expr = local[COL_IS_COMBINE].into();
        let is_neg: AB::Expr = local[COL_IS_NEG].into();
        let neg_minted: AB::Expr = local[COL_NEG_MINTED].into();
        let idx: AB::Expr = local[COL_IDX].into();

        // Booleans.
        builder.assert_bool(local[COL_ACT]);
        builder.assert_bool(local[COL_IS_BOUNDARY]);
        builder.assert_bool(local[COL_IS_INTRO]);
        builder.assert_bool(local[COL_IS_COMBINE]);
        builder.assert_bool(local[COL_IS_NEG]);
        // The neg-value mint flag is boolean and lives only on neg rows — so a
        // forged `neg_minted` elsewhere can't provide a phantom `EcOnCurveCert`
        // (the provide is gated `−neg_minted · is_boundary`).
        builder.assert_bool(local[COL_NEG_MINTED]);
        builder.assert_zero((AB::Expr::ONE - is_neg.clone()) * neg_minted);

        // Activity is sticky-downward (pads are a tail), and the op-family
        // one-hot sums to `act` (so every active row is exactly one op and
        // pads are no op).
        builder.when_transition().assert_zero((AB::Expr::ONE - act.clone()) * act_next);
        builder.assert_zero(is_intro.clone() + is_combine.clone() + is_neg.clone() - act.clone());
        // A boundary only on active rows; pads carry `is_boundary = 0` so
        // the allocator freezes `expr_ptr` across the tail.
        builder.assert_zero((AB::Expr::ONE - act.clone()) * is_boundary.clone());
        // Pin the provide multiplicity to 0 on inactive rows (mirroring the
        // eval chip's `out_mult` pin): pads then provide *nothing* — the
        // `MsmTerm` provide (`−mult`, otherwise ungated by `act`) and the
        // `MsmExpr` provide both vanish — so a forged pad `mult` can't inject
        // phantom terms, independent of the consumer set.
        builder.assert_zero((AB::Expr::ONE - act.clone()) * local[COL_MULT].into());
        builder.assert_zero((AB::Expr::ONE - act) * local[COL_CLAIM_MULT].into());

        // Allocator: expr_ptr = 1 on the first row, `+1` after each
        // boundary. ptr → (run) is injective by construction.
        let expr_ptr: AB::Expr = local[COL_EXPR_PTR].into();
        let expr_ptr_next: AB::Expr = next[COL_EXPR_PTR].into();
        builder.when_first_row().assert_zero(expr_ptr - AB::Expr::ONE);
        builder
            .when_transition()
            .assert_zero(expr_ptr_next - local[COL_EXPR_PTR].into() - is_boundary.clone());

        // Cursor `idx` resets to 0 after a boundary, else `+1` — so the
        // first row of every run has idx 0 and the boundary's idx is k−1.
        let idx_next: AB::Expr = next[COL_IDX].into();
        builder.when_first_row().assert_zero(idx.clone());
        builder
            .when_transition()
            .assert_zero(idx_next - (AB::Expr::ONE - is_boundary.clone()) * (idx + AB::Expr::ONE));

        // Within-run constancy of the expression-level columns (vacuous on
        // intro's 1-row runs; load-bearing once combine lays multi-row
        // runs). Gated to non-boundary transitions.
        let not_boundary = AB::Expr::ONE - is_boundary.clone();
        for col in [
            COL_GROUP_PTR,
            COL_SBOUND_PTR,
            COL_VAL,
            COL_MULT,
            COL_CLAIM_MULT,
            COL_IS_INTRO,
            COL_IS_COMBINE,
            COL_IS_NEG,
            COL_A_EXPR,
            COL_B_EXPR,
            COL_VAL_A,
            COL_VAL_B,
            COL_A_PTR,
            COL_B_PTR,
            COL_BOUND_PTR,
        ] {
            let here: AB::Expr = local[col].into();
            let there: AB::Expr = next[col].into();
            builder.when_transition().assert_zero(not_boundary.clone() * (there - here));
        }

        // Intro: a 1-row run (boundary), value = base (a ptr equality; the
        // scalar's literal-1 rides the bus). idx = 0 falls out of the
        // cursor reset, so it needs no separate constraint.
        builder.assert_zero(is_intro.clone() * (AB::Expr::ONE - is_boundary.clone()));
        let base: AB::Expr = local[COL_BASE].into();
        let val: AB::Expr = local[COL_VAL].into();
        builder.assert_zero(is_intro * (val - base));

        // ---- combine ----------------------------------------------------
        // Per-row take one-hot: each combine row emits one output term.
        let take_a: AB::Expr = local[COL_TAKE_A].into();
        let take_b: AB::Expr = local[COL_TAKE_B].into();
        let take_both: AB::Expr = local[COL_TAKE_BOTH].into();
        builder.assert_bool(local[COL_TAKE_A]);
        builder.assert_bool(local[COL_TAKE_B]);
        builder.assert_bool(local[COL_TAKE_BOTH]);
        builder
            .assert_zero(take_a.clone() + take_b.clone() + take_both.clone() - is_combine.clone());

        // Cursors: 0 at run start, advance by the take on each in-run step
        // (reset to 0 across a boundary). The boundary's i + adv_i is k_a.
        let i_cur: AB::Expr = local[COL_I].into();
        let j_cur: AB::Expr = local[COL_J].into();
        let i_next: AB::Expr = next[COL_I].into();
        let j_next: AB::Expr = next[COL_J].into();
        builder.when_first_row().assert_zero(i_cur.clone());
        builder.when_first_row().assert_zero(j_cur.clone());
        // A neg row takes the next A term every row, so its cursor-i advance
        // is `is_neg` (the take flags are 0 off combine, pinned by the
        // one-hot above); j never advances on a neg.
        let adv_i = take_a.clone() + take_both.clone() + is_neg.clone();
        let adv_j = take_b.clone() + take_both.clone();
        builder
            .when_transition()
            .assert_zero(i_next - (AB::Expr::ONE - is_boundary.clone()) * (i_cur + adv_i));
        builder
            .when_transition()
            .assert_zero(j_next - (AB::Expr::ONE - is_boundary.clone()) * (j_cur + adv_j));

        // Output role-mix: take_a / take_both copy A's (base, s); take_b
        // copies B's. take_both's merged scalar is pinned by its UintAdd
        // consume (bus), so only the base and the non-merge scalars tie
        // here. take_both forces a shared base.
        let base_a: AB::Expr = local[COL_BASE_A].into();
        let base_b: AB::Expr = local[COL_BASE_B].into();
        let s_a: AB::Expr = local[COL_S_A].into();
        let s_b: AB::Expr = local[COL_S_B].into();
        let out_base: AB::Expr = local[COL_BASE].into();
        let out_scalar: AB::Expr = local[COL_SCALAR].into();
        // take_a / take_both / neg copy A's base; take_b copies B's. (neg's
        // out_scalar is bus-pinned by its `is_c_zero` UintAdd, like
        // take_both's merged scalar, so it needs no equality here.)
        builder.assert_zero(
            (take_a.clone() + take_both.clone() + is_neg.clone()) * (out_base - base_a.clone())
                + take_b.clone() * (local[COL_BASE].into() - base_b.clone()),
        );
        builder
            .assert_zero(take_a * (out_scalar - s_a) + take_b * (local[COL_SCALAR].into() - s_b));
        builder.assert_zero(take_both * (base_a - base_b));

        // Strict pointer ordering (boundary): expr − operand − 1 =
        // lo + 2¹⁶·hi, halves range-checked on the bus ⇒ a_expr, b_expr <
        // expr. This is the well-founded order grounding the induction
        // against circular derivations. The a-side applies to combine AND
        // neg (both consume operand A); the b-side only to combine.
        let bnd_a = (is_combine.clone() + is_neg) * is_boundary.clone();
        let bnd_b = is_combine * is_boundary;
        let two16 = AB::Expr::from(Felt::from(TWO16));
        let here_expr: AB::Expr = local[COL_EXPR_PTR].into();
        let a_expr: AB::Expr = local[COL_A_EXPR].into();
        let b_expr: AB::Expr = local[COL_B_EXPR].into();
        let a_lo: AB::Expr = local[COL_A_DIFF_LO].into();
        let a_hi: AB::Expr = local[COL_A_DIFF_HI].into();
        let b_lo: AB::Expr = local[COL_B_DIFF_LO].into();
        let b_hi: AB::Expr = local[COL_B_DIFF_HI].into();
        builder.assert_zero(
            bnd_a * (here_expr.clone() - a_expr - AB::Expr::ONE - a_lo - two16.clone() * a_hi),
        );
        builder.assert_zero(bnd_b * (here_expr - b_expr - AB::Expr::ONE - b_lo - two16 * b_hi));

        // Phase 2: LogUp.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for EcMsmAir
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

        let neg_mult: LB::Expr = LB::Expr::ZERO - local[COL_MULT].into();
        let neg_claim_mult: LB::Expr = LB::Expr::ZERO - local[COL_CLAIM_MULT].into();
        let is_boundary: LB::Expr = local[COL_IS_BOUNDARY].into();
        let is_intro: LB::Expr = local[COL_IS_INTRO].into();
        let is_combine: LB::Expr = local[COL_IS_COMBINE].into();
        let is_neg: LB::Expr = local[COL_IS_NEG].into();

        let expr_ptr: LB::Expr = local[COL_EXPR_PTR].into();
        let group_ptr: LB::Expr = local[COL_GROUP_PTR].into();
        let sbound_ptr: LB::Expr = local[COL_SBOUND_PTR].into();
        let idx: LB::Expr = local[COL_IDX].into();
        let base: LB::Expr = local[COL_BASE].into();
        let scalar: LB::Expr = local[COL_SCALAR].into();
        let val: LB::Expr = local[COL_VAL].into();

        let a_expr: LB::Expr = local[COL_A_EXPR].into();
        let b_expr: LB::Expr = local[COL_B_EXPR].into();
        let i_cur: LB::Expr = local[COL_I].into();
        let j_cur: LB::Expr = local[COL_J].into();
        let take_a: LB::Expr = local[COL_TAKE_A].into();
        let take_b: LB::Expr = local[COL_TAKE_B].into();
        let take_both: LB::Expr = local[COL_TAKE_BOTH].into();
        let base_a: LB::Expr = local[COL_BASE_A].into();
        let s_a: LB::Expr = local[COL_S_A].into();
        let base_b: LB::Expr = local[COL_BASE_B].into();
        let s_b: LB::Expr = local[COL_S_B].into();
        let val_a: LB::Expr = local[COL_VAL_A].into();
        let val_b: LB::Expr = local[COL_VAL_B].into();
        let a_ptr: LB::Expr = local[COL_A_PTR].into();
        let b_ptr: LB::Expr = local[COL_B_PTR].into();
        let bound_ptr: LB::Expr = local[COL_BOUND_PTR].into();
        let a_lo: LB::Expr = local[COL_A_DIFF_LO].into();
        let a_hi: LB::Expr = local[COL_A_DIFF_HI].into();
        let b_lo: LB::Expr = local[COL_B_DIFF_LO].into();
        let b_hi: LB::Expr = local[COL_B_DIFF_HI].into();
        // Cheap value-negation cells (boundary only): R = (neg_x, neg_yr) =
        // (val_a.x, −val_a.y); neg_ya = val_a.y. neg_minted gates R's cert.
        let neg_x: LB::Expr = local[COL_NEG_X].into();
        let neg_ya: LB::Expr = local[COL_NEG_YA].into();
        let neg_yr: LB::Expr = local[COL_NEG_YR].into();
        let neg_minted: LB::Expr = local[COL_NEG_MINTED].into();

        // Cursor advances (= the MsmTerm consume gates) and the boundary
        // gates for expression-level traffic. A neg advances cursor i every
        // row (no take flags), so `adv_i` carries `is_neg`. The a-side
        // boundary traffic (operand-A head, ordering, the `EcGroup` pin)
        // fires for combine AND neg; the b-side and the combine value for
        // combine only; the neg value for neg only.
        let adv_i = take_a + take_both.clone() + is_neg.clone();
        let adv_j = take_b + take_both.clone();
        let bnd_a = (is_combine.clone() + is_neg.clone()) * is_boundary.clone();
        let bnd_b = is_combine * is_boundary.clone();
        let bnd_neg = is_neg.clone() * is_boundary.clone();

        let one_deg = Deg { v: 1, u: 1 };
        let two_deg = Deg { v: 2, u: 1 };
        let single_deg = Deg { v: 1, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };

        // col 0: the MsmTerm provide, alone — the gated running-sum anchor.
        frac_col!(
            builder,
            "ec-msm-provide",
            single_deg,
            (
                "provide-msmterm",
                neg_mult.clone(),
                MsmTermMsg {
                    expr_ptr: expr_ptr.clone(),
                    idx: idx.clone(),
                    base_ptr: base.clone(),
                    scalar_ptr: scalar.clone(),
                },
                one_deg
            ),
        );
        // col 1 (paired, lqd-1): the expression head — consumed by
        // combine/neg operand heads (op uses) AND the eval resolve (claim
        // uses), so it provides at the *sum* — paired with the positionless
        // resolve-seam term (one per term row at the resolve count).
        frac_col!(
            builder,
            "ec-msm-provide",
            pair_deg,
            (
                "provide-msmexpr",
                (neg_mult.clone() + neg_claim_mult.clone()) * is_boundary.clone(),
                MsmExprMsg {
                    expr_ptr: expr_ptr.clone(),
                    group_ptr: group_ptr.clone(),
                    val_ptr: val.clone(),
                    k: idx.clone() + LB::Expr::ONE,
                },
                two_deg
            ),
            (
                "provide-msmclaimterm",
                neg_claim_mult.clone(),
                MsmClaimTermMsg {
                    expr_ptr: expr_ptr.clone(),
                    base_ptr: base.clone(),
                    scalar_ptr: scalar.clone(),
                },
                one_deg
            ),
        );
        // col 2 (paired, lqd-1): neg's value `R = −val_a` is a trio-free
        // cert point — vouch its on-curve membership here (R is on-curve
        // because val_a is), once, when this neg freshly mints R
        // (`neg_minted` on the boundary) — paired with intro's literal-1
        // UintVal, now sent as one full-value message instead of a
        // lo/hi pair.
        frac_col!(
            builder,
            "ec-msm-provide",
            pair_deg,
            (
                "provide-oncurvecert-neg",
                LB::Expr::ZERO - neg_minted.clone() * is_boundary.clone(),
                EcOnCurveCertMsg {
                    group_ptr: group_ptr.clone(),
                    r_ptr: val.clone()
                },
                two_deg
            ),
            (
                "consume-one",
                is_intro.clone(),
                UintValMsg {
                    ptr: scalar.clone(),
                    bound_ptr: sbound_ptr.clone(),
                    limbs: [
                        LB::Expr::ONE,
                        LB::Expr::ZERO,
                        LB::Expr::ZERO,
                        LB::Expr::ZERO,
                        LB::Expr::ZERO,
                        LB::Expr::ZERO,
                        LB::Expr::ZERO,
                        LB::Expr::ZERO,
                    ],
                },
                one_deg
            ),
        );
        // col 3: the combine term walk's operand-A consume, alone now
        // that the literal-1 UintVal it was paired with merged into col 2.
        frac_col!(
            builder,
            "ec-msm-walk",
            single_deg,
            (
                "consume-term-a",
                adv_i.clone(),
                MsmTermMsg {
                    expr_ptr: a_expr.clone(),
                    idx: i_cur.clone(),
                    base_ptr: base_a.clone(),
                    scalar_ptr: s_a.clone(),
                },
                one_deg
            ),
        );
        // col 4 (paired, lqd-1): the combine term walk's operand-B consume,
        // paired with the take_both scalar merge `s_a + s_b ≡ scalar (mod
        // sbound)`.
        frac_col!(
            builder,
            "ec-msm-walk",
            pair_deg,
            (
                "consume-term-b",
                adv_j.clone(),
                MsmTermMsg {
                    expr_ptr: b_expr.clone(),
                    idx: j_cur.clone(),
                    base_ptr: base_b.clone(),
                    scalar_ptr: s_b.clone(),
                },
                one_deg
            ),
            (
                "consume-uintadd",
                take_both.clone(),
                UintAddMsg {
                    bound_ptr: sbound_ptr.clone(),
                    a_ptr: s_a.clone(),
                    b_ptr: s_b.clone(),
                    c_ptr: scalar.clone(),
                    nz: LB::Expr::ZERO,
                },
                one_deg
            ),
        );
        // col 5 (paired, lqd-1): neg's scalar negation (`out_scalar = −s_a`,
        // the `is_c_zero` arrangement `s_a + out_scalar ≡ 0 (mod sbound)`,
        // one per term row), paired with neg's VALUE y-flip (`R.y =
        // −val_a.y`, the is_c_zero UintAdd `y_a + y_R ≡ 0` over the
        // COORDINATE field — once per neg, on the boundary). With x shared
        // (both EcPoint consumes, col 7/8) this pins `R = −val_a` without
        // any group law.
        frac_col!(
            builder,
            "ec-msm-walk",
            pair_deg,
            (
                "consume-uintadd-neg",
                is_neg.clone(),
                UintAddMsg {
                    bound_ptr: sbound_ptr.clone(),
                    a_ptr: s_a.clone(),
                    b_ptr: scalar.clone(),
                    c_ptr: LB::Expr::ZERO,
                    nz: LB::Expr::ZERO,
                },
                one_deg
            ),
            (
                "consume-uintadd-neg-y",
                bnd_neg.clone(),
                UintAddMsg {
                    bound_ptr: bound_ptr.clone(),
                    a_ptr: neg_ya.clone(),
                    b_ptr: neg_yr.clone(),
                    c_ptr: LB::Expr::ZERO,
                    nz: LB::Expr::ZERO,
                },
                two_deg
            ),
        );
        // col 6 (paired, lqd-1): the boundary expr-level operand head(s) —
        // `k` = the final cursor, so every operand term was walked exactly
        // once.
        frac_col!(
            builder,
            "ec-msm-heads",
            pair_deg,
            (
                "consume-head-a",
                bnd_a.clone(),
                MsmExprMsg {
                    expr_ptr: a_expr.clone(),
                    group_ptr: group_ptr.clone(),
                    val_ptr: val_a.clone(),
                    k: i_cur.clone() + adv_i.clone(),
                },
                two_deg
            ),
            (
                "consume-head-b",
                bnd_b.clone(),
                MsmExprMsg {
                    expr_ptr: b_expr.clone(),
                    group_ptr: group_ptr.clone(),
                    val_ptr: val_b.clone(),
                    k: j_cur.clone() + adv_j.clone(),
                },
                two_deg
            ),
        );
        // col 7 (paired, lqd-1): the value `EcGroupAdd` (combine's
        // `val = val_a + val_b`), paired with neg's CHEAP value negation
        // read of val_a's coords (R = val, read in col 8). Both EcPoint
        // consumes carry the same `neg_x`, so the store's provides pin
        // `R.x = val_a.x`; the y-flip UintAdd (col 5) ties `R.y = −val_a.y`.
        // No group law for neg — `val = −val_a`.
        frac_col!(
            builder,
            "ec-msm-heads",
            pair_deg,
            (
                "consume-ecgroupadd",
                bnd_b.clone(),
                EcGroupAddMsg {
                    group_ptr: group_ptr.clone(),
                    p_ptr: val_a.clone(),
                    q_ptr: val_b.clone(),
                    r_ptr: val.clone(),
                },
                two_deg
            ),
            (
                "consume-ecpoint-val-a",
                bnd_neg.clone(),
                EcPointMsg {
                    point_ptr: val_a.clone(),
                    group_ptr: group_ptr.clone(),
                    x_ptr: neg_x.clone(),
                    y_ptr: neg_ya.clone(),
                    is_pai: LB::Expr::ZERO,
                },
                two_deg
            ),
        );
        // col 8 (paired, lqd-1): neg's cheap value-negation read of R's
        // coords, paired with the `EcGroup` pin (sbound ↔ group) — both
        // combine and neg.
        frac_col!(
            builder,
            "ec-msm-heads",
            pair_deg,
            (
                "consume-ecpoint-neg",
                bnd_neg.clone(),
                EcPointMsg {
                    point_ptr: val.clone(),
                    group_ptr: group_ptr.clone(),
                    x_ptr: neg_x.clone(),
                    y_ptr: neg_yr.clone(),
                    is_pai: LB::Expr::ZERO,
                },
                two_deg
            ),
            (
                "consume-ecgroup",
                bnd_a.clone(),
                EcGroupMsg {
                    group_ptr: group_ptr.clone(),
                    a_ptr: a_ptr.clone(),
                    b_ptr: b_ptr.clone(),
                    bound_ptr: bound_ptr.clone(),
                    scalar_bound_ptr: sbound_ptr.clone(),
                },
                two_deg
            ),
        );

        // col 9/10 (paired, lqd-1): the ordering range checks — the two
        // 32-bit difference decompositions enforcing `a_expr, b_expr <
        // expr`.
        frac_col!(
            builder,
            "ec-msm-order",
            pair_deg,
            ("range-a-lo", bnd_a.clone(), Range16Msg { w: a_lo }, two_deg),
            ("range-a-hi", bnd_a, Range16Msg { w: a_hi }, two_deg),
        );
        frac_col!(
            builder,
            "ec-msm-order",
            pair_deg,
            ("range-b-lo", bnd_b.clone(), Range16Msg { w: b_lo }, two_deg),
            ("range-b-hi", bnd_b, Range16Msg { w: b_hi }, two_deg),
        );
    }
}
