//! EcMsm chiplet — symbolic multi-scalar-multiplication expressions.
//!
//! A **term** is a pair `(base_ptr, scalar_ptr)` ("`P × s`", the scalar
//! under the group's scalar bound); an **expression** is a run of term
//! rows sharing one `expr_ptr`, carrying a **value** point `val_ptr` with
//! the invariant `deref(val_ptr) = Σ deref(s)·deref(P)`. The prover lays
//! any addition chain via five rules — `intro` (`⟨P×1⟩`, val = P),
//! `intro_zero` (`⟨P×0⟩`, val = the identity), `intro_endo` (`⟨P×λ⟩`, val = φ(P)),
//! `neg` (every scalar negated), and `combine` (term multisets union, scalars on a shared base
//! merge mod `n`, values add) — and the AIR checks only that each step is sound, never which steps
//! were taken.
//!
//! Rows form variable-length expression blocks. Each row stores one term, and each maximal run
//! sharing `expr_ptr` is one expression. The allocator chain
//! `expr_ptr' = expr_ptr + is_boundary`, with `is_boundary` marking the run's final row, makes
//! expression pointers injective. The boundary row carries the expression-level traffic: the
//! `MsmExpr` head, the value's `EcGroupAdd`, the operand heads, and the ordering checks.
//!
//! Soundness rests on **strict pointer ordering** (`a_expr < expr`,
//! `b_expr < expr` on every combine — grounds the induction against
//! circular derivations) and on `scalar_bound = #E` (the full curve order
//! annihilates every point, so the merge's `mod n` wrap is harmless —
//! cofactor-agnostic).
//!
//! `intro`, `intro_zero`, `intro_endo`, `combine`, and `neg` build the expression; the
//! eval `EcMsm` absorb seam resolves a claim in-circuit, consuming the
//! positionless `MsmClaimTerm` multiset so the absorb — and the transcript root
//! — follow the caller's declared term order, not the chiplet's `idx`
//! storage order.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};

use crate::precompile::{
    ec::{
        EcGroupMsg, EcPointMsg,
        add::{EcGroupAddMsg, EcOnCurveCertMsg},
    },
    logup::{
        Challenges, ConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder,
        LookupColumn, LookupGroup, LookupMessage, NUM_LOGUP_VALUES, NUM_RANDOMNESS, frac_col,
    },
    primitives::byte_pair_lut::Range16Msg,
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::{UintValMsg, add::UintAddMsg, mul::UintMulMsg},
    utils::{current_main, next_main},
};

// MESSAGES
// ================================================================================================

/// LogUp message for the [`MsmTerm`](BusId::MsmTerm) relation: one term
/// `(expr_ptr, idx, base_ptr, scalar_ptr)` of an MSM expression — the
/// point `base_ptr` scaled by the stored uint `scalar_ptr`, at position
/// `idx` in expression `expr_ptr`. Provided once per term row at the
/// expression's use count; consumed by combine and neg term walks. The eval
/// `EcMsm` absorb seam instead consumes positionless [`MsmClaimTermMsg`]s.
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
/// on the expression's boundary row at its op use count plus
/// [`COL_IS_CLAIMED`]; consumed as an operand head by combine/neg and by
/// the boundary of the eval `EcMsm` claim the expression serves.
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
/// field. Provided once per term row of a claimed expression
/// ([`COL_IS_CLAIMED`]); consumed by the eval `EcMsm` absorb seam, which
/// matches the claim's terms as a multiset so the DAG absorb order (and
/// root) is the caller's, not the chiplet's `idx` storage order.
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
/// pads. (The eval claim uses [`COL_IS_CLAIMED`] instead, so the two
/// consumers of an expression — combine/neg operand vs transcript claim —
/// bill separate provides.)
pub const COL_MULT: usize = 9;
/// Two stored op-family flags. Together with [`COL_IS_NEG`], they determine
/// the residual `intro_endo` selector and form a one-hot encoding of every
/// active row.
pub const COL_IS_INTRO: usize = 10;
pub const COL_IS_COMBINE: usize = 11;

// --- operation witness columns ---------------------------------------
/// Operand A / B expression ptrs. Combine uses both; neg uses A only.
pub const COL_A_EXPR: usize = 12;
pub const COL_B_EXPR: usize = 13;
/// Walk cursors into A / B (threaded within the run; 0 at run start).
/// Combine uses both; neg uses A only. At the boundary, `i + take_a +
/// take_both + is_neg` is `k_a`; B similarly uses `j + take_b + take_both`.
/// These identities tie each operand-head consume to its term count.
pub const COL_I: usize = 14;
pub const COL_J: usize = 15;
/// Stored single-take selectors; `take_both = is_combine - take_a - take_b` is derived.
pub const COL_TAKE_A: usize = 16;
pub const COL_TAKE_B: usize = 17;
/// Operand scalars consumed from `MsmTerm(A, i, …)` / `MsmTerm(B, j, …)`. Both
/// consumes use the output base. Combine uses both sides; neg uses A only.
pub const COL_S_A: usize = 18;
pub const COL_S_B: usize = 19;
/// Operand values. Combine uses both; neg uses A only. On a combine
/// boundary, `EcGroupAdd` asserts `val = val_a + val_b`.
pub const COL_VAL_A: usize = 20;
pub const COL_VAL_B: usize = 21;
/// Group curve parameters used by combine, neg, and intro_endo to close the
/// boundary's `EcGroup` consume and pin `sbound` to the group.
pub const COL_A_PTR: usize = 22;
pub const COL_B_PTR: usize = 23;
pub const COL_BOUND_PTR: usize = 24;
/// A-side ordering witness on combine and neg boundaries:
/// `expr − a_expr − 1 = a_diff_lo + 2¹⁶·a_diff_hi`, with both 16-bit limbs
/// range-checked to enforce `a_expr < expr`.
pub const COL_A_DIFF_LO: usize = 25;
pub const COL_A_DIFF_HI: usize = 26;
/// B-side ordering witness. On combine boundaries it enforces `b_expr < expr`.
/// On certificate-minting neg and intro_endo rows, it enforces `val > val_a`
/// or `val > base`, respectively. Both limbs are range-checked.
pub const COL_B_DIFF_LO: usize = 27;
pub const COL_B_DIFF_HI: usize = 28;

// --- shared negation/endomorphism witness and resolve multiplicity -----
/// Op-family flag for `neg`. Together with `is_intro`, `is_combine`, and `is_intro_zero`, it
/// leaves `is_intro_endo` as the residual active operation. A `neg` is a **unary** walk over
/// operand A: one
/// output term per A term, the base copied and the scalar negated (the
/// `is_c_zero` `UintAdd` `s_a + out_scalar ≡ 0`), with the value's shared
/// x-coordinate and negated y-coordinate authenticated on the boundary.
pub const COL_IS_NEG: usize = 29;
/// Family value-relation cell, sharing combine's B-expression cell. For `neg`, this is the
/// shared x ptr of `R = (x_a, −y_a)`; for `intro_endo`, it is `P`'s x ptr. Neg runs carry it
/// on every row to preserve the shared cell's run constancy.
pub const COL_NEG_X: usize = COL_B_EXPR;
/// **Resolve** use count — how often this expression is resolved at the
/// eval `EcMsm` seam. Drives the `MsmClaimTerm` provide (every term row)
/// and the rest of the `MsmExpr` provide; constant within a run, 0 on
/// pads. This multiplicity records resolve uses of the positionless `MsmClaimTerm`; [`COL_MULT`]
/// records combine uses of `MsmTerm` indexed by `idx`.
/// Boolean: two resolves of one expression would only jointly consume twice
/// its claim terms, letting each absorb a different multiset, so every
/// resolve has an expression of its own.
pub const COL_IS_CLAIMED: usize = 30;
/// Family value-relation cells, sharing combine's B-value and B-scalar cells. For `neg`,
/// these are the two y ptrs of `R = (x_a, −y_a)`; for `intro_endo`, they are the shared y ptr
/// and `φ(P)`'s x ptr. Neg runs carry `COL_NEG_YA` throughout; `COL_NEG_YR` is boundary-only.
pub const COL_NEG_YA: usize = COL_VAL_B;
pub const COL_NEG_YR: usize = COL_S_B;
/// Family mint flag (boundary only): 1 iff a `neg` or `intro_endo` row
/// freshly mints its value, gating the common `EcOnCurveCert(group, val)`
/// provide.
pub const COL_NEG_MINTED: usize = 31;
/// The group's GLV endomorphism `β`/`λ` ptrs, used by combine, neg, and
/// intro_endo to close the boundary's `EcGroup` consume. Both are the
/// none-sentinel 0 for a group without an endomorphism.
pub const COL_BETA_PTR: usize = 32;
pub const COL_LAMBDA_PTR: usize = 33;

// `intro_endo` is the residual active operation after subtracting the four stored selectors. Its
// value relation reuses the negation columns; `intro_zero` reuses the base-coordinate pair as
// well. These operations are mutually exclusive, so each row gives the shared columns one meaning.
/// The introduced base point's x-coordinate pointer.
pub const COL_ENDO_BASE_X: usize = COL_NEG_X;
/// The introduced base point's y-coordinate pointer.
pub const COL_ENDO_Y: usize = COL_NEG_YA;
/// `φ(P)`'s x ptr (from the `EcPoint(val)` consume; tied to `β·x_P` by the
/// `UintMul` consume).
pub const COL_ENDO_VAL_X: usize = COL_NEG_YR;
/// Mint flag for `φ(P)`, shared with the negation operation.
pub const COL_ENDO_MINTED: usize = COL_NEG_MINTED;
/// Marks a row that introduces the MSM term `P × 0`.
///
/// The term evaluates to the curve's canonical point at infinity. Therefore,
/// unlike a normal `intro` row (`P × 1 = P`), this row cannot require `val`
/// to equal `base`. Instead, the EC-point lookup below verifies that `val` is
/// the point at infinity — and a second EC-point lookup verifies that `base`
/// is itself a genuine finite point of `group_ptr` (`is_pai = 0`), reusing
/// [`COL_ENDO_BASE_X`]/[`COL_ENDO_Y`] for its coordinates; the boundary's
/// `EcGroup` consume (shared with `combine`/`neg`/`intro_endo`) ties
/// `sbound_ptr` to `group_ptr` the same way. Without both ties, a base that
/// is off-group or the identity point would still satisfy every other
/// `intro_zero` constraint.
///
/// This is one of five mutually exclusive operation flags:
/// `is_intro + is_intro_endo + is_combine + is_neg + is_intro_zero = act`.
pub const COL_IS_INTRO_ZERO: usize = 34;
pub const NUM_MAIN_COLS: usize = 35;

// Aux: 12 columns, flattened via `frac_col!` over the 24 fractions so
// every closing constraint stays at degree ≤ 3 → `log_quotient_degree` =
// 1:
//  col 0:  MsmTerm provide + literal-1/0 UintVal, with the centered running-sum anchor.
//  col 1:  MsmExpr provide + MsmClaimTerm provide.
//  col 2:  merged EcOnCurveCert provide + EcPoint(val, is_pai = 1) (intro_zero).
//  col 3:  MsmTerm consume A + UintMul (intro_endo's x_φ = β·x_P).
//  col 4:  MsmTerm consume B + UintAdd (take_both merge).
//  col 5:  UintAdd (neg scalar) + UintAdd (neg value y-flip).
//  col 6:  MsmExpr consume A (head) + MsmExpr consume B (head).
//  col 7:  EcGroupAdd (combine value) + EcPoint(val_a) (neg value coord).
//  col 8:  EcPoint(R) (neg value coord) + EcGroup (sbound pin — combine, neg, intro_endo, and
//          intro_zero).
//  col 9:  ordering Range16 — a_lo + a_hi.
//  col 10: ordering Range16 — b_lo + b_hi.
//  col 11: EcPoint(base) (intro_endo/intro_zero coord) + EcPoint(val) (intro_endo coord).
const NUM_LOGUP_COLS: usize = 12;
const AUX_WIDTH: usize = NUM_LOGUP_COLS;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [2; NUM_LOGUP_COLS];
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
}

impl LiftedAir<Felt, QuadFelt> for EcMsmAir {
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
        crate::precompile::logup::build_logup_aux_trace(&EcMsmAir, main, challenges)
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
        let is_intro_zero: AB::Expr = local[COL_IS_INTRO_ZERO].into();
        let is_intro_endo = act.clone()
            - is_intro.clone()
            - is_combine.clone()
            - is_neg.clone()
            - is_intro_zero.clone();
        let minted: AB::Expr = local[COL_NEG_MINTED].into();
        let idx: AB::Expr = local[COL_IDX].into();

        // Booleans.
        builder.assert_bool(local[COL_ACT]);
        builder.assert_bool(local[COL_IS_BOUNDARY]);
        builder.assert_bool(local[COL_IS_INTRO]);
        builder.assert_bool(local[COL_IS_COMBINE]);
        builder.assert_bool(local[COL_IS_NEG]);
        builder.assert_bool(local[COL_IS_INTRO_ZERO]);
        builder.assert_zero(is_intro_endo.clone() * (is_intro_endo.clone() - AB::Expr::ONE));
        builder.assert_bool(local[COL_NEG_MINTED]);
        builder.assert_zero((AB::Expr::ONE - is_neg.clone() - is_intro_endo.clone()) * minted);

        // Activity is sticky-downward (pads are a tail). The residual's
        // Boolean constraint above makes every active row exactly one op and
        // every pad no op.
        builder.when_transition().assert_zero((AB::Expr::ONE - act.clone()) * act_next);
        // A boundary only on active rows; pads carry `is_boundary = 0` so
        // the allocator freezes `expr_ptr` across the tail.
        builder.assert_zero((AB::Expr::ONE - act.clone()) * is_boundary.clone());
        // Pin the provide multiplicity to 0 on inactive rows (mirroring the
        // eval chip's `out_mult` pin): pads then provide *nothing* — the
        // `MsmTerm` provide (`−mult`, otherwise ungated by `act`) and the
        // `MsmExpr` provide both vanish — so a forged pad `mult` can't inject
        // phantom terms, independent of the consumer set.
        builder.assert_zero((AB::Expr::ONE - act.clone()) * local[COL_MULT].into());
        builder.assert_zero((AB::Expr::ONE - act) * local[COL_IS_CLAIMED].into());
        // At most one claim per expression: each claim run must consume
        // exactly its own expression's claim terms.
        builder.assert_bool(local[COL_IS_CLAIMED]);

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

        // Expression-level columns remain constant within a run. This is vacuous for one-row intro
        // runs and required for multi-row combine runs. Boundary transitions are excluded.
        let not_boundary = AB::Expr::ONE - is_boundary.clone();
        for col in [
            COL_GROUP_PTR,
            COL_SBOUND_PTR,
            COL_VAL,
            COL_MULT,
            COL_IS_CLAIMED,
            COL_IS_INTRO,
            COL_IS_COMBINE,
            COL_IS_NEG,
            COL_IS_INTRO_ZERO,
            COL_A_EXPR,
            COL_B_EXPR,
            COL_VAL_A,
            COL_VAL_B,
            COL_A_PTR,
            COL_B_PTR,
            COL_BOUND_PTR,
            COL_BETA_PTR,
            COL_LAMBDA_PTR,
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

        // intro_endo: also a 1-row run (boundary). The value relation is
        // *not* `val = base` (that's plain intro's) — it's proved by the
        // LogUp coordinate relation below (§ intro_endo). The only native
        // constraint here is the scalar pin: the term's scalar is the
        // group's λ, never an AIR-known constant (see
        // [`msm::require::intro_endo`](crate::precompile::ec::msm::require::intro_endo)).
        builder.assert_zero(is_intro_endo.clone() * (AB::Expr::ONE - is_boundary.clone()));
        let lambda_ptr: AB::Expr = local[COL_LAMBDA_PTR].into();
        let scalar: AB::Expr = local[COL_SCALAR].into();
        builder.assert_zero(is_intro_endo.clone() * (scalar - lambda_ptr));

        // intro_zero: also a 1-row run (boundary). Neither the scalar (0)
        // nor the value (the group's PAI point) is an AIR-known constant
        // and neither is a native ptr equality (unlike plain intro's
        // `val = base`) — both ride LogUp consumes below (§ intro_zero):
        // the literal-0 `UintVal` and the `EcPoint(val, is_pai = 1)` tie.
        builder.assert_zero(is_intro_zero * (AB::Expr::ONE - is_boundary.clone()));

        // ---- combine ----------------------------------------------------
        // Per-row take one-hot: each combine row emits one output term.
        let take_a: AB::Expr = local[COL_TAKE_A].into();
        let take_b: AB::Expr = local[COL_TAKE_B].into();
        let take_both = is_combine.clone() - take_a.clone() - take_b.clone();
        builder.assert_bool(local[COL_TAKE_A]);
        builder.assert_bool(local[COL_TAKE_B]);
        builder.assert_bool(take_both.clone());

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
        let adv_j = take_b.clone() + take_both;
        builder
            .when_transition()
            .assert_zero(i_next - (AB::Expr::ONE - is_boundary.clone()) * (i_cur + adv_i));
        builder
            .when_transition()
            .assert_zero(j_next - (AB::Expr::ONE - is_boundary.clone()) * (j_cur + adv_j));

        // Operand consumes authenticate the output base directly. Single takes copy the
        // scalar; merged and negated scalars are authenticated by their UintAdd messages.
        let s_a: AB::Expr = local[COL_S_A].into();
        let s_b: AB::Expr = local[COL_S_B].into();
        let out_scalar: AB::Expr = local[COL_SCALAR].into();
        builder.assert_zero(take_a * (out_scalar.clone() - s_a) + take_b * (out_scalar - s_b));

        // Strict pointer ordering (boundary): expr − operand − 1 =
        // lo + 2¹⁶·hi, halves range-checked on the bus ⇒ a_expr, b_expr <
        // expr. This is the well-founded order grounding the induction
        // against circular derivations. The a-side applies to combine AND
        // neg (both consume operand A); the b-side to combine, and its limbs
        // carry the certificate ordering below on minting rows.
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
        builder.assert_zero(
            bnd_b
                * (here_expr
                    - b_expr
                    - AB::Expr::ONE
                    - b_lo.clone()
                    - two16.clone() * b_hi.clone()),
        );

        // Certificate ordering: a minted `EcOnCurveCert(group, val)` rests on
        // the membership of `val_a` (neg) or `base` (intro_endo), so `val`
        // must have the larger point ptr, as for EcGroupAdd's `r > p, q`.
        // Without it a point could certify itself, or a cycle of points each
        // other, with none of them on the curve.
        let cert_val: AB::Expr = local[COL_VAL].into();
        let cert_val_a: AB::Expr = local[COL_VAL_A].into();
        let cert_base: AB::Expr = local[COL_BASE].into();
        let cert_diff = b_lo + two16 * b_hi;
        // The two families share a mint-flag column; their selectors choose the source point.
        let neg_mint: AB::Expr =
            AB::Expr::from(local[COL_NEG_MINTED]) * AB::Expr::from(local[COL_IS_NEG]);
        let endo_mint: AB::Expr = AB::Expr::from(local[COL_ENDO_MINTED]) * is_intro_endo;
        builder.assert_zero(
            neg_mint * (cert_val.clone() - cert_val_a - AB::Expr::ONE - cert_diff.clone()),
        );
        builder.assert_zero(endo_mint * (cert_val - cert_base - AB::Expr::ONE - cert_diff));

        // Phase 2: LogUp.
        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for EcMsmAir
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

        let neg_mult: LB::Expr = LB::Expr::ZERO - local[COL_MULT].into();
        let neg_is_claimed: LB::Expr = LB::Expr::ZERO - local[COL_IS_CLAIMED].into();
        let act: LB::Expr = local[COL_ACT].into();
        let is_boundary: LB::Expr = local[COL_IS_BOUNDARY].into();
        let is_intro: LB::Expr = local[COL_IS_INTRO].into();
        let is_combine: LB::Expr = local[COL_IS_COMBINE].into();
        let is_neg: LB::Expr = local[COL_IS_NEG].into();
        let is_intro_zero: LB::Expr = local[COL_IS_INTRO_ZERO].into();
        let is_intro_endo =
            act - is_intro.clone() - is_combine.clone() - is_neg.clone() - is_intro_zero.clone();

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
        let take_both = is_combine.clone() - take_a.clone() - take_b.clone();
        let s_a: LB::Expr = local[COL_S_A].into();
        let s_b: LB::Expr = local[COL_S_B].into();
        let val_a: LB::Expr = local[COL_VAL_A].into();
        let val_b: LB::Expr = local[COL_VAL_B].into();
        let a_ptr: LB::Expr = local[COL_A_PTR].into();
        let b_ptr: LB::Expr = local[COL_B_PTR].into();
        let bound_ptr: LB::Expr = local[COL_BOUND_PTR].into();
        let beta_ptr: LB::Expr = local[COL_BETA_PTR].into();
        let lambda_ptr: LB::Expr = local[COL_LAMBDA_PTR].into();
        let a_lo: LB::Expr = local[COL_A_DIFF_LO].into();
        let a_hi: LB::Expr = local[COL_A_DIFF_HI].into();
        let b_lo: LB::Expr = local[COL_B_DIFF_LO].into();
        let b_hi: LB::Expr = local[COL_B_DIFF_HI].into();
        // The neg and intro_endo families reuse these four value-relation
        // cells. Their bus gates assign each cell its family-specific role.
        let neg_x: LB::Expr = local[COL_NEG_X].into();
        let neg_ya: LB::Expr = local[COL_NEG_YA].into();
        let neg_yr: LB::Expr = local[COL_NEG_YR].into();
        let minted: LB::Expr = local[COL_NEG_MINTED].into();
        let endo_base_x = neg_x.clone();
        let endo_y = neg_ya.clone();
        let endo_val_x = neg_yr.clone();

        // Cursor advances (= the MsmTerm consume gates) and the boundary
        // gates for expression-level traffic. A neg advances cursor i every
        // row (no take flags), so `adv_i` carries `is_neg`. The a-side
        // boundary traffic (operand-A head, ordering) fires for combine AND
        // neg; the b-side and the combine value for combine only; the neg
        // value for neg only. `bnd_group` is the wider `EcGroup`-pin gate:
        // combine, neg, intro_endo (which has no operand head / ordering of
        // its own, only the group pin authenticating β/λ), AND intro_zero
        // (which needs it to tie `sbound_ptr` to `group_ptr`, same as the
        // other three).
        let adv_i = take_a + take_both.clone() + is_neg.clone();
        let adv_j = take_b + take_both.clone();
        let bnd_a = (is_combine.clone() + is_neg.clone()) * is_boundary.clone();
        let bnd_b = is_combine.clone() * is_boundary.clone();
        let bnd_neg = is_neg.clone() * is_boundary.clone();
        let bnd_group =
            (is_combine + is_neg.clone() + is_intro_endo.clone() + is_intro_zero.clone())
                * is_boundary.clone();
        let bnd_endo = is_intro_endo * is_boundary.clone();
        // The b-side limbs are range-checked on combine boundaries and on
        // certificate-minting rows (see `COL_B_DIFF_LO`).
        let range_b_gate = bnd_b.clone() + minted.clone();
        let bnd_intro_zero = is_intro_zero.clone() * is_boundary.clone();

        let one_deg = Deg { v: 1, u: 1 };
        let two_deg = Deg { v: 2, u: 1 };
        let linear_pair_deg = Deg { v: 2, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };

        // col 0: MsmTerm provide and the literal scalar of the disjoint intro/intro_zero
        // families. Both messages stay affine, including the selected low scalar limb.
        frac_col!(
            builder,
            "ec-msm-provide",
            linear_pair_deg,
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
            (
                "consume-intro-scalar",
                is_intro.clone() + is_intro_zero.clone(),
                UintValMsg {
                    ptr: scalar.clone(),
                    bound_ptr: sbound_ptr.clone(),
                    limbs: [
                        is_intro.clone(),
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
        // col 1 (paired, lqd-1): the expression head — consumed by
        // combine/neg operand heads (op uses) AND the eval claim it serves
        // (if claimed), so it provides at the *sum* — paired with the
        // positionless claim term (one per term row of a claimed expression).
        frac_col!(
            builder,
            "ec-msm-provide",
            pair_deg,
            (
                "provide-msmexpr",
                (neg_mult.clone() + neg_is_claimed.clone()) * is_boundary.clone(),
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
                neg_is_claimed.clone(),
                MsmClaimTermMsg {
                    expr_ptr: expr_ptr.clone(),
                    base_ptr: base.clone(),
                    scalar_ptr: scalar.clone(),
                },
                one_deg
            ),
        );
        // col 2 (paired, lqd-1): neg and intro_endo share their mint flag and
        // mint the same typed `EcOnCurveCert(group_ptr, val)` tuple, paired with
        // intro_zero's point-at-infinity value relation.
        frac_col!(
            builder,
            "ec-msm-provide",
            pair_deg,
            (
                "provide-oncurvecert-neg-or-endo",
                LB::Expr::ZERO - minted * is_boundary.clone(),
                EcOnCurveCertMsg {
                    group_ptr: group_ptr.clone(),
                    r_ptr: val.clone()
                },
                two_deg
            ),
            (
                "consume-ecpoint-intro-zero-val",
                bnd_intro_zero.clone(),
                EcPointMsg {
                    point_ptr: val.clone(),
                    group_ptr: group_ptr.clone(),
                    x_ptr: LB::Expr::ZERO,
                    y_ptr: LB::Expr::ZERO,
                    is_pai: LB::Expr::ONE,
                },
                two_deg
            ),
        );
        // col 3 (paired, lqd-1): the combine/neg term walk's operand-A
        // consume, paired with intro_endo's x_φ = β·x_P certificate.
        frac_col!(
            builder,
            "ec-msm-walk",
            pair_deg,
            (
                "consume-term-a",
                adv_i.clone(),
                MsmTermMsg {
                    expr_ptr: a_expr.clone(),
                    idx: i_cur.clone(),
                    base_ptr: base.clone(),
                    scalar_ptr: s_a.clone(),
                },
                one_deg
            ),
            (
                "consume-uintmul-endo",
                bnd_endo.clone(),
                UintMulMsg {
                    kappa_a: LB::Expr::ONE,
                    kappa_c: LB::Expr::ZERO,
                    a_ptr: beta_ptr.clone(),
                    b_ptr: endo_base_x.clone(),
                    c_ptr: bound_ptr.clone(),
                    r_ptr: endo_val_x.clone(),
                    bound_ptr: bound_ptr.clone(),
                    is_sub: LB::Expr::ZERO,
                },
                two_deg
            ),
        );
        // col 4 (paired, lqd-1): the combine term walk's operand-B consume,
        // paired with the take_both scalar merge `s_a + s_b ≡ scalar (mod
        // sbound)`.
        frac_col!(
            builder,
            "ec-msm-walk",
            linear_pair_deg,
            (
                "consume-term-b",
                adv_j.clone(),
                MsmTermMsg {
                    expr_ptr: b_expr.clone(),
                    idx: j_cur.clone(),
                    base_ptr: base.clone(),
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
                bnd_group,
                EcGroupMsg {
                    group_ptr: group_ptr.clone(),
                    a_ptr: a_ptr.clone(),
                    b_ptr: b_ptr.clone(),
                    bound_ptr: bound_ptr.clone(),
                    scalar_bound_ptr: sbound_ptr.clone(),
                    beta_ptr: beta_ptr.clone(),
                    lambda_ptr: lambda_ptr.clone(),
                },
                two_deg
            ),
        );

        // col 9/10 (paired, lqd-1): the ordering range checks — the two
        // 32-bit difference decompositions enforcing `a_expr, b_expr <
        // expr`, and on minting rows `val > val_a` / `val > base`.
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
            ("range-b-lo", range_b_gate.clone(), Range16Msg { w: b_lo }, two_deg),
            ("range-b-hi", range_b_gate, Range16Msg { w: b_hi }, two_deg),
        );

        // col 11 (paired, lqd-1): intro_endo's coordinate relation — `P`'s
        // and `φ(P)`'s `EcPoint` consumes. Both messages use `endo_y`, so their matching store
        // providers constrain `y_φ = y_P`, analogous to the shared x-coordinate in `neg`.
        frac_col!(
            builder,
            "ec-msm-endo",
            pair_deg,
            (
                "consume-ecpoint-endo-or-zero-base",
                bnd_endo.clone() + bnd_intro_zero,
                EcPointMsg {
                    point_ptr: base.clone(),
                    group_ptr: group_ptr.clone(),
                    x_ptr: endo_base_x.clone(),
                    y_ptr: endo_y.clone(),
                    is_pai: LB::Expr::ZERO,
                },
                two_deg
            ),
            (
                "consume-ecpoint-endo-val",
                bnd_endo.clone(),
                EcPointMsg {
                    point_ptr: val.clone(),
                    group_ptr: group_ptr.clone(),
                    x_ptr: endo_val_x.clone(),
                    y_ptr: endo_y.clone(),
                    is_pai: LB::Expr::ZERO,
                },
                two_deg
            ),
        );
    }
}
