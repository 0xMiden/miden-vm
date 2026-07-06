//! [`EcMsmAir`] trace generation, the recording accumulator, and the
//! LogUp aux builder.
//!
//! Each expression lays a run of term rows (`intro`: one; `combine`: one
//! per output term). The variable block is the run sharing `expr_ptr`,
//! with the allocator `expr_ptr' = expr_ptr + is_boundary` threaded by the
//! AIR. Pad rows continue the allocator with `is_boundary = 0` (so
//! `expr_ptr` freezes and the cursors simply count up), touching no bus.

use std::collections::HashMap;

use miden_core::{Felt, field::QuadFelt};
use p3_matrix::dense::RowMajorMatrix;

use super::{
    COL_A_DIFF_HI, COL_A_DIFF_LO, COL_A_EXPR, COL_A_PTR, COL_ACT, COL_B_DIFF_HI, COL_B_DIFF_LO,
    COL_B_EXPR, COL_B_PTR, COL_BASE, COL_BASE_A, COL_BASE_B, COL_BOUND_PTR, COL_CLAIM_MULT,
    COL_EXPR_PTR, COL_GROUP_PTR, COL_I, COL_IDX, COL_IS_BOUNDARY, COL_IS_COMBINE, COL_IS_INTRO,
    COL_IS_NEG, COL_J, COL_MULT, COL_NEG_MINTED, COL_NEG_X, COL_NEG_YA, COL_NEG_YR, COL_S_A,
    COL_S_B, COL_SBOUND_PTR, COL_SCALAR, COL_TAKE_A, COL_TAKE_B, COL_TAKE_BOTH, COL_VAL, COL_VAL_A,
    COL_VAL_B, EcMsmAir, NUM_MAIN_COLS,
};
use crate::ec::trace::{EcGroupPtr, EcPointPtr};
use crate::logup::build_logup_aux_trace;
use crate::primitives::byte_pair_lut::BytePairLutRequires;
use crate::relations::ProvideMult;
use crate::uint::trace::{UintPtr, UintStoreRequires};

/// Handle to a recorded MSM expression — its allocator-assigned
/// `expr_ptr` (consecutive from 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EcExprPtr(pub u32);

impl EcExprPtr {
    pub fn addr(self) -> u32 {
        self.0
    }
}

/// One output row of a `combine` — the take one-hot, the cursors *before*
/// this row, the operand term cells consumed (per the take), and the
/// output term `(base, scalar)`. The require facade (and tests) compute
/// the merge walk and hand the rows here; the AIR re-checks them.
#[derive(Debug, Clone, Copy)]
pub struct CombineRow {
    pub take_a: bool,
    pub take_b: bool,
    pub take_both: bool,
    pub i: u32,
    pub j: u32,
    pub base_a: EcPointPtr,
    pub s_a: UintPtr,
    pub base_b: EcPointPtr,
    pub s_b: UintPtr,
    pub out_base: EcPointPtr,
    pub out_scalar: UintPtr,
}

/// One output row of a `neg` — the unary walk over operand A. `i` is the
/// cursor into A (advances every row); `base` is the term's base (copied
/// to the output) and `s_a` its scalar (consumed from A); `out_scalar` is
/// `−s_a`, the output term's scalar, pinned by the row's `is_c_zero`
/// `UintAdd` consume.
#[derive(Debug, Clone, Copy)]
pub struct NegRow {
    pub i: u32,
    pub base: EcPointPtr,
    pub s_a: UintPtr,
    pub out_scalar: UintPtr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExprKind {
    Intro,
    Combine,
    Neg,
}

#[derive(Debug, Clone, Copy, Default)]
struct RowVals {
    base: u32,
    scalar: u32,
    i: u32,
    j: u32,
    take_a: u32,
    take_b: u32,
    take_both: u32,
    base_a: u32,
    s_a: u32,
    base_b: u32,
    s_b: u32,
}

#[derive(Debug, Clone)]
struct ExprRecord {
    kind: ExprKind,
    group: u32,
    sbound: u32,
    val: u32,
    // combine/neg expression-level cells (0 for intro). `b_expr` / `val_b`
    // are combine-only; `pai` is neg-only.
    a_expr: u32,
    b_expr: u32,
    val_a: u32,
    val_b: u32,
    a_ptr: u32,
    b_ptr: u32,
    bound_ptr: u32,
    // neg-only value-negation cells (0 on intro/combine): the shared x ptr
    // (`val_a.x = val.x`), the two y ptrs (`val_a.y`, `val.y = −val_a.y`), and
    // whether `val` was freshly minted (gates the on-curve cert provide).
    neg_x: u32,
    neg_ya: u32,
    neg_yr: u32,
    neg_minted: u32,
    rows: Vec<RowVals>,
    /// **Op** use count — bumped per `combine` / `neg` operand use; drives
    /// the `MsmTerm` provides + part of `MsmExpr`.
    mult: ProvideMult,
    /// **Resolve** use count — bumped per eval `EcMsm` resolve; drives the
    /// `MsmClaimTerm` provides + the rest of `MsmExpr`.
    claim_mult: ProvideMult,
}

/// Relation identity of a recorded expression — the dedup key. An `intro`
/// is its base point; a `combine` / `neg` its operand expression ptr(s).
/// Mirrors [`EcAddRequires`](crate::ec::add::trace)'s `(group, p, q)` dedup:
/// two requests of the *same* derivation collapse onto one expression. The
/// strict pointer order (operand `<` result) keeps this sound — a dedup hit
/// returns an *earlier* expr, only ever referenced by *later* ones, so it
/// can never close a cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DedupKey {
    /// `⟨base × 1⟩` — keyed by the base point (which fixes group + bound).
    Intro(u32),
    /// `combine(a, b)` — keyed by the two operand expression ptrs.
    Combine(u32, u32),
    /// `neg(a)` — keyed by the operand expression ptr.
    Neg(u32),
}

/// The EcMsm recording accumulator: expressions in allocator order, each
/// with a mutable use count, plus a relation-identity dedup map.
#[derive(Debug, Default)]
pub struct EcMsmRequires {
    exprs: Vec<ExprRecord>,
    /// Relation identity → the expression it produced; a repeated derivation
    /// reuses the stored handle (see [`lookup_intro`](Self::lookup_intro)).
    dedup: HashMap<DedupKey, EcExprPtr>,
}

impl EcMsmRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// The expression a prior `intro` of `base` produced, if any — a repeat
    /// reuses it instead of laying a second `⟨base × 1⟩`.
    pub fn lookup_intro(&self, base: EcPointPtr) -> Option<EcExprPtr> {
        self.dedup.get(&DedupKey::Intro(base.addr())).copied()
    }

    /// The expression a prior `combine(a, b)` produced, if any.
    pub fn lookup_combine(&self, a: EcExprPtr, b: EcExprPtr) -> Option<EcExprPtr> {
        self.dedup
            .get(&DedupKey::Combine(a.addr(), b.addr()))
            .copied()
    }

    /// The expression a prior `neg(a)` produced, if any.
    pub fn lookup_neg(&self, a: EcExprPtr) -> Option<EcExprPtr> {
        self.dedup.get(&DedupKey::Neg(a.addr())).copied()
    }

    /// Record an `intro` — `⟨base × 1⟩` with `val = base`. `scalar` must be
    /// the store ptr of the value `1` under `sbound`. Returns the handle.
    pub fn intro(
        &mut self,
        group: EcGroupPtr,
        sbound: UintPtr,
        base: EcPointPtr,
        scalar: UintPtr,
    ) -> EcExprPtr {
        self.exprs.push(ExprRecord {
            kind: ExprKind::Intro,
            group: group.addr(),
            sbound: sbound.addr(),
            val: base.addr(),
            a_expr: 0,
            b_expr: 0,
            val_a: 0,
            val_b: 0,
            a_ptr: 0,
            b_ptr: 0,
            bound_ptr: 0,
            neg_x: 0,
            neg_ya: 0,
            neg_yr: 0,
            neg_minted: 0,
            rows: vec![RowVals {
                base: base.addr(),
                scalar: scalar.addr(),
                ..RowVals::default()
            }],
            mult: 0,
            claim_mult: 0,
        });
        let e = EcExprPtr(self.exprs.len() as u32);
        self.dedup.insert(DedupKey::Intro(base.addr()), e);
        e
    }

    /// Record a `combine(a, b) = c` with value `val = val_a + val_b` and
    /// the precomputed merge walk `rows`. `a_ptr`/`b_ptr`/`bound_ptr` are
    /// the group's curve params + base modulus (to close the `EcGroup`
    /// consume pinning `sbound`). The caller has already laid the value
    /// `EcGroupAdd`, the `take_both` `UintAdd`s, and the operand-head
    /// `EcGroup` demand. Returns the handle.
    #[allow(clippy::too_many_arguments)]
    pub fn combine(
        &mut self,
        group: EcGroupPtr,
        sbound: UintPtr,
        a_ptr: UintPtr,
        b_ptr: UintPtr,
        bound_ptr: UintPtr,
        a_expr: EcExprPtr,
        b_expr: EcExprPtr,
        val_a: EcPointPtr,
        val_b: EcPointPtr,
        val: EcPointPtr,
        rows: Vec<CombineRow>,
    ) -> EcExprPtr {
        let rows = rows
            .into_iter()
            .map(|r| RowVals {
                base: r.out_base.addr(),
                scalar: r.out_scalar.addr(),
                i: r.i,
                j: r.j,
                take_a: r.take_a as u32,
                take_b: r.take_b as u32,
                take_both: r.take_both as u32,
                base_a: r.base_a.addr(),
                s_a: r.s_a.addr(),
                base_b: r.base_b.addr(),
                s_b: r.s_b.addr(),
            })
            .collect();
        self.exprs.push(ExprRecord {
            kind: ExprKind::Combine,
            group: group.addr(),
            sbound: sbound.addr(),
            val: val.addr(),
            a_expr: a_expr.addr(),
            b_expr: b_expr.addr(),
            val_a: val_a.addr(),
            val_b: val_b.addr(),
            a_ptr: a_ptr.addr(),
            b_ptr: b_ptr.addr(),
            bound_ptr: bound_ptr.addr(),
            neg_x: 0,
            neg_ya: 0,
            neg_yr: 0,
            neg_minted: 0,
            rows,
            mult: 0,
            claim_mult: 0,
        });
        let e = EcExprPtr(self.exprs.len() as u32);
        self.dedup
            .insert(DedupKey::Combine(a_expr.addr(), b_expr.addr()), e);
        e
    }

    /// Record a `neg(a) = c` with value `val = −val_a` and the precomputed
    /// unary walk `rows` (one per term of A, base copied, scalar negated).
    /// `a_ptr`/`b_ptr`/`bound_ptr` are the group's curve params + base
    /// modulus (to close the `EcGroup` consume pinning `sbound`). The value is
    /// negated *cheaply* (no group law): `val = (x_a, −y_a)` is a trio-free
    /// cert point — `neg_x` is the shared x ptr (`val_a.x = val.x`), `neg_ya`
    /// / `neg_yr` the two y ptrs (the boundary consumes `EcPoint(val_a)` +
    /// `EcPoint(val)` to pin them and an `is_c_zero` `UintAdd(neg_ya, neg_yr)`
    /// to pin `y_R = −y_a`), and `minted` says whether the boundary provides
    /// the `EcOnCurveCert` for `val` (only on a fresh row). The caller has
    /// already laid the per-term scalar `is_c_zero` `UintAdd`s + the y-flip.
    /// Returns the handle.
    #[allow(clippy::too_many_arguments)]
    pub fn neg(
        &mut self,
        group: EcGroupPtr,
        sbound: UintPtr,
        a_ptr: UintPtr,
        b_ptr: UintPtr,
        bound_ptr: UintPtr,
        a_expr: EcExprPtr,
        val_a: EcPointPtr,
        val: EcPointPtr,
        neg_x: UintPtr,
        neg_ya: UintPtr,
        neg_yr: UintPtr,
        minted: bool,
        rows: Vec<NegRow>,
    ) -> EcExprPtr {
        let rows = rows
            .into_iter()
            .map(|r| RowVals {
                // out_base = base_a (the copied base); out_scalar = −s_a.
                base: r.base.addr(),
                scalar: r.out_scalar.addr(),
                i: r.i,
                base_a: r.base.addr(),
                s_a: r.s_a.addr(),
                ..RowVals::default()
            })
            .collect();
        self.exprs.push(ExprRecord {
            kind: ExprKind::Neg,
            group: group.addr(),
            sbound: sbound.addr(),
            val: val.addr(),
            a_expr: a_expr.addr(),
            b_expr: 0,
            val_a: val_a.addr(),
            val_b: 0,
            a_ptr: a_ptr.addr(),
            b_ptr: b_ptr.addr(),
            bound_ptr: bound_ptr.addr(),
            neg_x: neg_x.addr(),
            neg_ya: neg_ya.addr(),
            neg_yr: neg_yr.addr(),
            neg_minted: minted as u32,
            rows,
            mult: 0,
            claim_mult: 0,
        });
        let e = EcExprPtr(self.exprs.len() as u32);
        self.dedup.insert(DedupKey::Neg(a_expr.addr()), e);
        e
    }

    /// Bump an expression's **op** use count by `mult` — one per `combine` /
    /// `neg` operand use (drives `MsmTerm` + part of `MsmExpr`).
    pub fn consume_op(&mut self, expr: EcExprPtr, mult: ProvideMult) {
        self.exprs[expr.0 as usize - 1].mult += mult;
    }

    /// Bump an expression's **resolve** use count by `mult` — one per eval
    /// `EcMsm` resolve (drives `MsmClaimTerm` + the rest of `MsmExpr`). The
    /// resolve seam consumes the positionless `MsmClaimTerm`, so the absorb
    /// order is the caller's, decoupled from the chiplet's `idx`.
    pub fn consume_claim(&mut self, expr: EcExprPtr, mult: ProvideMult) {
        self.exprs[expr.0 as usize - 1].claim_mult += mult;
    }

    /// Count of recorded expressions (intros + combines + negs) — the
    /// chain-cost diagnostic for comparing addition-chain strategies.
    pub fn expr_count(&self) -> usize {
        self.exprs.len()
    }

    /// An expression's term list `(base, scalar)` in `idx` order — what a
    /// downstream combine walks.
    pub fn terms(&self, expr: EcExprPtr) -> Vec<(EcPointPtr, UintPtr)> {
        self.exprs[expr.0 as usize - 1]
            .rows
            .iter()
            .map(|r| (EcPointPtr::from_addr(r.base), UintPtr::from_addr(r.scalar)))
            .collect()
    }

    /// An expression's value point.
    pub fn value(&self, expr: EcExprPtr) -> EcPointPtr {
        EcPointPtr::from_addr(self.exprs[expr.0 as usize - 1].val)
    }

    /// An expression's group / scalar-bound handles.
    pub fn group(&self, expr: EcExprPtr) -> EcGroupPtr {
        EcGroupPtr::from_addr(self.exprs[expr.0 as usize - 1].group)
    }
    pub fn sbound(&self, expr: EcExprPtr) -> UintPtr {
        UintPtr::from_addr(self.exprs[expr.0 as usize - 1].sbound)
    }
}

/// Build the EcMsm main trace from the accumulator (consumed). Routes
/// each `intro`'s literal-1 `UintVal` demand into the uint store and each
/// boundary's ordering `Range16` halves into the BPL (four for `combine`,
/// two for `neg` — only the a-side), lays one row per term, and pads to a
/// power-of-two height with `act = 0` rows that continue the allocator
/// chain but touch no bus.
pub fn generate_trace(
    requires: EcMsmRequires,
    store: &mut UintStoreRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    let n_real: usize = requires.exprs.iter().map(|e| e.rows.len()).sum();
    let height = n_real.max(1).next_power_of_two().max(2);
    let mut vals = Vec::with_capacity(height * NUM_MAIN_COLS);

    for (e_idx, e) in requires.exprs.iter().enumerate() {
        let expr_ptr = e_idx as u32 + 1;
        let k = e.rows.len();
        let is_intro = e.kind == ExprKind::Intro;
        let is_combine = e.kind == ExprKind::Combine;
        let is_neg = e.kind == ExprKind::Neg;
        for (idx, rv) in e.rows.iter().enumerate() {
            let is_boundary = idx == k - 1;
            let mut r = [Felt::ZERO; NUM_MAIN_COLS];
            let mut set = |col: usize, v: u32| r[col] = Felt::from(v);
            set(COL_ACT, 1);
            set(COL_EXPR_PTR, expr_ptr);
            set(COL_IS_BOUNDARY, is_boundary as u32);
            set(COL_GROUP_PTR, e.group);
            set(COL_SBOUND_PTR, e.sbound);
            set(COL_IDX, idx as u32);
            set(COL_BASE, rv.base);
            set(COL_SCALAR, rv.scalar);
            set(COL_VAL, e.val);
            set(COL_MULT, e.mult);
            set(COL_CLAIM_MULT, e.claim_mult);
            set(COL_IS_INTRO, is_intro as u32);
            set(COL_IS_COMBINE, is_combine as u32);
            set(COL_IS_NEG, is_neg as u32);
            if is_combine {
                set(COL_A_EXPR, e.a_expr);
                set(COL_B_EXPR, e.b_expr);
                set(COL_I, rv.i);
                set(COL_J, rv.j);
                set(COL_TAKE_A, rv.take_a);
                set(COL_TAKE_B, rv.take_b);
                set(COL_TAKE_BOTH, rv.take_both);
                set(COL_BASE_A, rv.base_a);
                set(COL_S_A, rv.s_a);
                set(COL_BASE_B, rv.base_b);
                set(COL_S_B, rv.s_b);
                set(COL_VAL_A, e.val_a);
                set(COL_VAL_B, e.val_b);
                set(COL_A_PTR, e.a_ptr);
                set(COL_B_PTR, e.b_ptr);
                set(COL_BOUND_PTR, e.bound_ptr);
                if is_boundary {
                    let a_diff = expr_ptr - e.a_expr - 1;
                    let b_diff = expr_ptr - e.b_expr - 1;
                    set(COL_A_DIFF_LO, a_diff & 0xFFFF);
                    set(COL_A_DIFF_HI, a_diff >> 16);
                    set(COL_B_DIFF_LO, b_diff & 0xFFFF);
                    set(COL_B_DIFF_HI, b_diff >> 16);
                    bpl.require_range16((a_diff & 0xFFFF) as u16);
                    bpl.require_range16((a_diff >> 16) as u16);
                    bpl.require_range16((b_diff & 0xFFFF) as u16);
                    bpl.require_range16((b_diff >> 16) as u16);
                }
            } else if is_neg {
                // Unary walk over A: cursor i, the consumed term cells, the
                // operand value, group params, and the ∞ result slot. Only
                // the a-side ordering half (b-side is combine-only).
                set(COL_A_EXPR, e.a_expr);
                set(COL_I, rv.i);
                set(COL_BASE_A, rv.base_a);
                set(COL_S_A, rv.s_a);
                set(COL_VAL_A, e.val_a);
                set(COL_A_PTR, e.a_ptr);
                set(COL_B_PTR, e.b_ptr);
                set(COL_BOUND_PTR, e.bound_ptr);
                if is_boundary {
                    // The cheap value negation lives on the boundary: the
                    // shared x + the two y ptrs (pinned by the EcPoint consumes
                    // + the y-flip UintAdd) and the mint flag (gating the
                    // EcOnCurveCert provide for `val`).
                    set(COL_NEG_X, e.neg_x);
                    set(COL_NEG_YA, e.neg_ya);
                    set(COL_NEG_YR, e.neg_yr);
                    set(COL_NEG_MINTED, e.neg_minted);
                    let a_diff = expr_ptr - e.a_expr - 1;
                    set(COL_A_DIFF_LO, a_diff & 0xFFFF);
                    set(COL_A_DIFF_HI, a_diff >> 16);
                    bpl.require_range16((a_diff & 0xFFFF) as u16);
                    bpl.require_range16((a_diff >> 16) as u16);
                }
            } else {
                // intro: the literal-1 scalar's two UintVal halves.
                store.require_uintval(UintPtr::from_addr(rv.scalar));
            }
            vals.extend(r);
        }
    }

    // Pads: `expr_ptr` frozen at the next handle, `idx` counts up from 0.
    let pad_expr_ptr = requires.exprs.len() as u32 + 1;
    for pad_idx in 0..(height - n_real) as u32 {
        let mut r = [Felt::ZERO; NUM_MAIN_COLS];
        r[COL_EXPR_PTR] = Felt::from(pad_expr_ptr);
        r[COL_IDX] = Felt::from(pad_idx);
        vals.extend(r);
    }

    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}

// PROVER
// ================================================================================================

/// Witness-bearing companion to [`EcMsmAir`] — the aux trace is exactly
/// the LogUp columns (no register).
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&EcMsmAir, main, challenges)
}

#[cfg(test)]
mod tests {
    use p3_matrix::Matrix;

    use super::*;

    fn local_check(req: EcMsmRequires) {
        let mut store = UintStoreRequires::new();
        let mut bpl = BytePairLutRequires::new();
        let main = generate_trace(req, &mut store, &mut bpl);
        assert!(main.height().is_power_of_two());
        crate::tests::check_local(EcMsmAir, &main);
    }

    #[test]
    fn intro_constraints_hold() {
        let group = EcGroupPtr::from_addr(1);
        let sbound = UintPtr::from_addr(7);
        let one = UintPtr::from_addr(9);
        let mut req = EcMsmRequires::new();
        let g = req.intro(group, sbound, EcPointPtr::from_addr(3), one);
        let q = req.intro(group, sbound, EcPointPtr::from_addr(4), one);
        req.consume_op(g, 2);
        req.consume_op(q, 1);
        local_check(req);
    }

    #[test]
    fn combine_constraints_hold() {
        // ⟨G×1⟩ ⊕ ⟨Q×1⟩ = ⟨G×1, Q×1⟩ — disjoint bases, a pure-copy walk
        // (take_a then take_b). Exercises the cursors, role-mix, and the
        // strict-ordering decomposition.
        let group = EcGroupPtr::from_addr(1);
        let sbound = UintPtr::from_addr(7);
        let one = UintPtr::from_addr(9);
        let (g, q, r) = (
            EcPointPtr::from_addr(3),
            EcPointPtr::from_addr(4),
            EcPointPtr::from_addr(5),
        );
        let mut req = EcMsmRequires::new();
        let ga = req.intro(group, sbound, g, one);
        let qb = req.intro(group, sbound, q, one);
        let rows = vec![
            CombineRow {
                take_a: true,
                take_b: false,
                take_both: false,
                i: 0,
                j: 0,
                base_a: g,
                s_a: one,
                base_b: EcPointPtr::from_addr(0),
                s_b: UintPtr::from_addr(0),
                out_base: g,
                out_scalar: one,
            },
            CombineRow {
                take_a: false,
                take_b: true,
                take_both: false,
                i: 1,
                j: 0,
                base_a: EcPointPtr::from_addr(0),
                s_a: UintPtr::from_addr(0),
                base_b: q,
                s_b: one,
                out_base: q,
                out_scalar: one,
            },
        ];
        let c = req.combine(
            group,
            sbound,
            UintPtr::from_addr(2),
            UintPtr::from_addr(3),
            UintPtr::from_addr(1),
            ga,
            qb,
            g,
            q,
            r,
            rows,
        );
        req.consume_op(ga, 1);
        req.consume_op(qb, 1);
        req.consume_op(c, 1);
        local_check(req);
    }

    #[test]
    fn neg_constraints_hold() {
        // intro G, intro Q, combine → ⟨G×1, Q×1⟩, then neg → ⟨G×−1, Q×−1⟩.
        // The neg is a unary 2-row walk: cursor i advances every row (driven
        // by `is_neg`, not a take flag), each base copied, each scalar
        // negated, and only the a-side ordering decomposed.
        let group = EcGroupPtr::from_addr(1);
        let sbound = UintPtr::from_addr(7);
        let one = UintPtr::from_addr(9);
        let neg_one = UintPtr::from_addr(10);
        let (g, q, gq, ngq) = (
            EcPointPtr::from_addr(3),
            EcPointPtr::from_addr(4),
            EcPointPtr::from_addr(5),
            EcPointPtr::from_addr(6),
        );
        // The value-negation cells: shared x = gq.x, y_a = gq.y, y_R = ngq.y.
        let (neg_x, neg_ya, neg_yr) = (
            UintPtr::from_addr(4),
            UintPtr::from_addr(5),
            UintPtr::from_addr(6),
        );
        let (a_ptr, b_ptr, bound_ptr) = (
            UintPtr::from_addr(2),
            UintPtr::from_addr(3),
            UintPtr::from_addr(1),
        );
        let mut req = EcMsmRequires::new();
        let ga = req.intro(group, sbound, g, one);
        let qb = req.intro(group, sbound, q, one);
        let combine_rows = vec![
            CombineRow {
                take_a: true,
                take_b: false,
                take_both: false,
                i: 0,
                j: 0,
                base_a: g,
                s_a: one,
                base_b: EcPointPtr::from_addr(0),
                s_b: UintPtr::from_addr(0),
                out_base: g,
                out_scalar: one,
            },
            CombineRow {
                take_a: false,
                take_b: true,
                take_both: false,
                i: 1,
                j: 0,
                base_a: EcPointPtr::from_addr(0),
                s_a: UintPtr::from_addr(0),
                base_b: q,
                s_b: one,
                out_base: q,
                out_scalar: one,
            },
        ];
        let c = req.combine(
            group,
            sbound,
            a_ptr,
            b_ptr,
            bound_ptr,
            ga,
            qb,
            g,
            q,
            gq,
            combine_rows,
        );
        let neg_rows = vec![
            NegRow {
                i: 0,
                base: g,
                s_a: one,
                out_scalar: neg_one,
            },
            NegRow {
                i: 1,
                base: q,
                s_a: one,
                out_scalar: neg_one,
            },
        ];
        let n = req.neg(
            group, sbound, a_ptr, b_ptr, bound_ptr, c, gq, ngq, neg_x, neg_ya, neg_yr, true,
            neg_rows,
        );
        req.consume_op(ga, 1);
        req.consume_op(qb, 1);
        req.consume_op(c, 1);
        req.consume_op(n, 1);
        local_check(req);
    }

    #[test]
    #[should_panic]
    fn forged_pad_mult_rejected() {
        // A pad row (act = 0) with a nonzero `mult` would provide a phantom
        // `MsmTerm` (the provide is `−mult`, otherwise ungated by act). The
        // `(1-act)·mult = 0` pin must reject it locally — so this trace
        // fails `check_constraints`. (The honest counterpart is
        // `intro_constraints_hold`.)
        let mut store = UintStoreRequires::new();
        let mut bpl = BytePairLutRequires::new();
        let mut req = EcMsmRequires::new();
        let e = req.intro(
            EcGroupPtr::from_addr(1),
            UintPtr::from_addr(7),
            EcPointPtr::from_addr(3),
            UintPtr::from_addr(9),
        );
        req.consume_op(e, 1);
        let mut main = generate_trace(req, &mut store, &mut bpl);

        let pad = (0..main.height())
            .find(|&r| main.values[r * NUM_MAIN_COLS + COL_ACT] == Felt::ZERO)
            .expect("a pad row exists");
        main.values[pad * NUM_MAIN_COLS + COL_MULT] = Felt::ONE;

        crate::tests::check_local(EcMsmAir, &main);
    }

    #[test]
    #[should_panic]
    fn forged_take_flag_on_intro_rejected() {
        // The take one-hot `take_a + take_b + take_both = is_combine` is the
        // linchpin pinning the take flags (and thus the combine consumes) to
        // 0 off combine rows. A stray `take_a` on an intro row (is_combine =
        // 0) breaks it `1 ≠ 0`, so check_constraints rejects it locally —
        // no phantom MsmTerm-A consume from a non-combine row.
        let mut store = UintStoreRequires::new();
        let mut bpl = BytePairLutRequires::new();
        let mut req = EcMsmRequires::new();
        let e = req.intro(
            EcGroupPtr::from_addr(1),
            UintPtr::from_addr(7),
            EcPointPtr::from_addr(3),
            UintPtr::from_addr(9),
        );
        req.consume_op(e, 1);
        let mut main = generate_trace(req, &mut store, &mut bpl);

        let intro = (0..main.height())
            .find(|&r| main.values[r * NUM_MAIN_COLS + COL_ACT] == Felt::ONE)
            .expect("an active row exists");
        main.values[intro * NUM_MAIN_COLS + COL_TAKE_A] = Felt::ONE;

        crate::tests::check_local(EcMsmAir, &main);
    }
}
