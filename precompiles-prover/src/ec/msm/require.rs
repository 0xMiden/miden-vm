//! EcMsm recording layer — building MSM expressions (`intro` / `combine` /
//! `neg`) is *chiplet mechanism*: it walks term lists, merges scalars via
//! `UintAdd`, and records value group-ops via `EcGroupAdd`. That belongs
//! here, beside the chiplet, not in the DAG-only
//! [`Session`](crate::session), which just delegates (`msm_intro` etc.).
//!
//! Each function borrows the MSM accumulator
//! ([`EcMsmRequires`](crate::ec::msm::trace::EcMsmRequires)) plus the EC and
//! uint stores below it — the same three the `Session` holds — and
//! constructs the lower-layer `require` views as needed (mirroring how the
//! `Session` itself wired them).

use crate::{
    ec::{
        EcStores,
        msm::trace::{CombineRow, EcExprPtr, EcMsmRequires, NegRow},
        trace::EcPointPtr,
    },
    math::from_hex,
    uint::{UintRequire, UintStores, trace::UintPtr},
};

/// Promote a stored point `P` to the 1-term MSM expression `⟨P × 1⟩`
/// (value `= P`) — the base of any addition chain. The scalar `1` is
/// interned under the group's scalar bound. Returns the expression handle.
pub fn intro(
    msm: &mut EcMsmRequires,
    ec: &mut EcStores,
    uint: &mut UintStores,
    base: EcPointPtr,
) -> EcExprPtr {
    if let Some(e) = msm.lookup_intro(base) {
        return e; // a prior ⟨base × 1⟩ — reuse it
    }
    let group = ec.store.point_params(base).0;
    let sbound = ec
        .store
        .constrained_group_sbound(group)
        .expect("MSM requires an explicitly constrained group scalar bound");
    let (a_ptr, b_ptr, bound_ptr) = ec.store.group_params(group);
    let (base_group, base_coords) = ec.store.point_params(base);
    assert_eq!(base_group, group, "MSM intro base must belong to its group");
    let (base_x, base_y, base_is_pai) = match base_coords {
        Some((x, y)) => (x, y, false),
        None => (UintPtr::from_addr(0), UintPtr::from_addr(0), true),
    };
    let one = uint.require().intern(from_hex("1"), sbound);
    ec.store.require_ecpoint(base);
    ec.store.require_ecgroup(group);
    msm.intro(group, sbound, base, one, a_ptr, b_ptr, bound_ptr, base_x, base_y, base_is_pai)
}

/// Combine two MSM expressions: union their term multisets (scalars on a
/// shared base merge `mod` the scalar bound) and add their values. The
/// merge walks both base-ordered term lists ([`merge_terms`]); the value is
/// one `EcGroupAdd` (provided at mult 1). The operands' use counts are
/// bumped. Returns the combined expression handle.
pub fn combine(
    msm: &mut EcMsmRequires,
    ec: &mut EcStores,
    uint: &mut UintStores,
    a: EcExprPtr,
    b: EcExprPtr,
) -> EcExprPtr {
    if let Some(e) = msm.lookup_combine(a, b) {
        return e; // identical combine already laid — reuse it (no second
        // merge walk, value `EcGroupAdd`, or operand consume)
    }
    let group = msm.group(a);
    let sbound = msm.sbound(a);
    let a_terms = msm.terms(a);
    let b_terms = msm.terms(b);
    let val_a = msm.value(a);
    let val_b = msm.value(b);
    let (a_ptr, b_ptr, bound_ptr) = ec.store.group_params(group);

    let rows = merge_terms(&a_terms, &b_terms, &mut uint.require());

    let val = ec.require(uint.require()).add(val_a, val_b, 1);
    ec.store.require_ecgroup(group);

    let c = msm.combine(group, sbound, a_ptr, b_ptr, bound_ptr, a, b, val_a, val_b, val, rows);
    msm.consume_op(a, 1);
    msm.consume_op(b, 1);
    c
}

/// Negate an MSM expression: every term's scalar negated (the base kept),
/// the value negated. Each term's `out = −s` is an `is_c_zero` `UintAdd`
/// (`s + out ≡ 0`); the value is the cancel `EcGroupAdd` `val_a + val = ∞`
/// (so `val = −val_a`, the ∞ result slot pinned by `EcRequire::neg`). The
/// operand's use count is bumped. Returns the negated expression handle.
pub fn neg(
    msm: &mut EcMsmRequires,
    ec: &mut EcStores,
    uint: &mut UintStores,
    a: EcExprPtr,
) -> EcExprPtr {
    if let Some(e) = msm.lookup_neg(a) {
        return e; // a prior neg(a) — reuse it
    }
    let group = msm.group(a);
    let sbound = msm.sbound(a);
    let a_terms = msm.terms(a);
    let val_a = msm.value(a);
    let (a_ptr, b_ptr, bound_ptr) = ec.store.group_params(group);

    // Per term: keep the base, negate the scalar (one UintAdd each).
    let mut rows = Vec::with_capacity(a_terms.len());
    for (i, (base, s)) in a_terms.iter().enumerate() {
        let out_scalar = uint.require().neg(*s);
        rows.push(NegRow {
            i: i as u32,
            base: *base,
            s_a: *s,
            out_scalar,
        });
    }

    // Value: use the EC layer's cancel proof, which handles both finite
    // values and ∞ and grounds the result in the group-add chiplet.
    let (_, val, pai) = ec.require(uint.require()).neg(val_a, 1);
    ec.store.require_ecgroup(group);

    let c = msm.neg(group, sbound, a_ptr, b_ptr, bound_ptr, a, val_a, val, pai, rows);
    msm.consume_op(a, 1);
    c
}

/// The combine merge walk: a base-ordered two-pointer merge of two
/// expressions' term lists into [`CombineRow`]s. Disjoint bases copy
/// through one operand (`take_a` / `take_b`); a base shared by both merges
/// its two scalars into one — recorded as a `UintAdd` (mod the scalar
/// bound) via `uint`, the `take_both` row. Both cursors advance on
/// `take_both`, one on a single take.
///
/// Term lists are read in their stored (`idx`) order; the AIR re-checks
/// each row, so faithfulness rests on the prover's discipline of laying
/// operands in a consistent base order (equal bases must align to merge) —
/// it is *completeness*, not soundness (see `docs/chiplets/ec-msm.md §3`).
pub fn merge_terms(
    a_terms: &[(EcPointPtr, UintPtr)],
    b_terms: &[(EcPointPtr, UintPtr)],
    uint: &mut UintRequire<'_>,
) -> Vec<CombineRow> {
    let zero_pt = EcPointPtr::from_addr(0);
    let zero_u = UintPtr::from_addr(0);
    let (mut i, mut j) = (0usize, 0usize);
    let mut rows = Vec::new();
    while i < a_terms.len() || j < b_terms.len() {
        let (ci, cj) = (i as u32, j as u32);
        let a_first =
            j >= b_terms.len() || (i < a_terms.len() && a_terms[i].0.addr() < b_terms[j].0.addr());
        let b_first =
            i >= a_terms.len() || (j < b_terms.len() && b_terms[j].0.addr() < a_terms[i].0.addr());
        if a_first {
            let (base, s) = a_terms[i];
            rows.push(CombineRow {
                take_a: true,
                take_b: false,
                take_both: false,
                i: ci,
                j: cj,
                base_a: base,
                s_a: s,
                base_b: zero_pt,
                s_b: zero_u,
                out_base: base,
                out_scalar: s,
            });
            i += 1;
        } else if b_first {
            let (base, s) = b_terms[j];
            rows.push(CombineRow {
                take_a: false,
                take_b: true,
                take_both: false,
                i: ci,
                j: cj,
                base_a: zero_pt,
                s_a: zero_u,
                base_b: base,
                s_b: s,
                out_base: base,
                out_scalar: s,
            });
            j += 1;
        } else {
            // Shared base: merge the two scalars mod the scalar bound.
            let (base, sa) = a_terms[i];
            let (_, sb) = b_terms[j];
            let s_out = uint.add(sa, sb);
            rows.push(CombineRow {
                take_a: false,
                take_b: false,
                take_both: true,
                i: ci,
                j: cj,
                base_a: base,
                s_a: sa,
                base_b: base,
                s_b: sb,
                out_base: base,
                out_scalar: s_out,
            });
            i += 1;
            j += 1;
        }
    }
    rows
}
