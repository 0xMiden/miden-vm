//! EcMsm chiplet end-to-end tests — building MSM expressions through the
//! [`Session`] and closing the full 15-chiplet bus.
//!
//! Two flavours. The chiplet-only checks drive an *unused* final op
//! (combine or neg): its operands are consumed (their `MsmTerm` / `MsmExpr`
//! provides matched), it routes all external demand (`EcGroupAdd` value,
//! `EcGroup`, ordering `Range16`, intro `UintVal`, neg's `is_c_zero`
//! `UintAdd`), and its own provides sit at mult 0, closing every bus short
//! of the DAG claim. The `msm_resolve_*` tests then prove + verify the full
//! in-circuit resolve through the eval `EcMsm` seam — the positionless
//! `MsmClaimTerm` set match, so the absorb (root) order is the caller's.

use std::{format, string::String};

use k256::{ProjectivePoint, elliptic_curve::sec1::ToEncodedPoint};
use miden_core::Felt;
use miden_precompiles::CurveId;
use p3_matrix::Matrix;

use crate::{
    math::{U256, from_hex},
    session::{
        EcNode, Session,
        strategies::{joint_naf, joint_wnaf, straus, wnaf_msm, wnaf_table},
        verify_deferred,
    },
    tests::check_local_inputs,
    transcript::eval::{COL_IS_EC_MSM, COL_IS_MSM_LAST, COL_MSM_EXPR, TranscriptEvalAir},
};

/// secp256k1 VM-owned uint/group pointers.
const FP: u32 = CurveId::Secp256k1.base_domain().bound_ptr();
const GROUP_PTR: u32 = CurveId::Secp256k1.group_ptr();
const SN_PTR: u32 = CurveId::Secp256k1.scalar_domain().bound_ptr();

fn be_to_u256(bytes: impl AsRef<[u8]>) -> U256 {
    let hex: String = bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    from_hex(&hex)
}

fn k256_coords(p: &ProjectivePoint) -> (U256, U256) {
    let enc = p.to_affine().to_encoded_point(false);
    (
        be_to_u256(enc.x().expect("finite point")),
        be_to_u256(enc.y().expect("finite point")),
    )
}

fn create(s: &mut Session, x: U256, y: U256) -> EcNode {
    let xn = s.uint_leaf(x, FP);
    let yn = s.uint_leaf(y, FP);
    s.ec_create(GROUP_PTR, &xn, &yn)
}

/// `⟨G×1⟩ ⊕ ⟨2G×1⟩` (disjoint bases — a pure-copy walk, value `G + 2G =
/// 3G`). The combine is unused (mult 0): it consumes its operands and
/// routes the value/group/ordering/intro demand, closing the bus.
fn msm_two_intro_traces() -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let q_pt = create(&mut s, g2x, g2y);

    let ga = s.msm_intro(&g_pt);
    let qb = s.msm_intro(&q_pt);
    let _c = s.msm_combine(ga, qb);

    // The EC create nodes must be consumed; fold tautologies so the eval
    // bindings close (the real consumer is the future resolve seam).
    let claim_g = s.ec_is(&g_pt, &g_pt);
    let claim_q = s.ec_is(&q_pt, &q_pt);
    let root = s.assert_and_fold([claim_g, claim_q]);
    s.finish(root)
}

#[test]
fn msm_two_intro_combine_checks() {
    let traces = msm_two_intro_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn msm_two_intro_combine_proves() {
    verify_deferred(&msm_two_intro_traces().prove())
        .expect("EcMsm intro+combine round-trip must verify");
}

/// The same `⟨G×1⟩ ⊕ ⟨2G×1⟩` copy-walk as [`msm_two_intro_traces`], but the
/// group's **scalar field** is constrained to the curve order `n ≠ p`
/// ([`Session::constrain_scalar_bound`]) *before* the intros — so their
/// literal-1 scalars (and the group's `EcGroup` tuple) ride `n` while the
/// coordinates stay under `p`. This is the regression for the eval
/// scalar-bound plumbing: point-store rows and MSM consumes must read the
/// group's canonical scalar bound `n`, not fall back to the coordinate bound
/// `p`. The old `scalar_bound = coord_bound` hardcode dangled the `EcGroup`
/// bus here (provide `n`, consume `p`), so `check` tripped.
fn msm_scalar_bound_n_traces() -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let q_pt = create(&mut s, g2x, g2y);
    // Route the shared group's scalars under `n`, before the intros so their
    // literal-1 scalars intern under `n` (G and 2G share one group).
    s.constrain_scalar_bound(&g_pt, SN_PTR);

    let ga = s.msm_intro(&g_pt);
    let qb = s.msm_intro(&q_pt);
    let _c = s.msm_combine(ga, qb);

    let claim_g = s.ec_is(&g_pt, &g_pt);
    let claim_q = s.ec_is(&q_pt, &q_pt);
    let root = s.assert_and_fold([claim_g, claim_q]);
    s.finish(root)
}

#[test]
fn msm_scalar_bound_n_checks() {
    let traces = msm_scalar_bound_n_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn msm_scalar_bound_n_proves() {
    verify_deferred(&msm_scalar_bound_n_traces().prove())
        .expect("MSM under scalar bound n ≠ p must verify");
}

/// `⟨G×1⟩` negated to `⟨G×−1⟩` (value `−G` via the cancel `EcGroupAdd`,
/// scalar `−1` via the `is_c_zero` `UintAdd`). The neg is unused (mult 0):
/// it consumes its operand and routes the value/group/ordering/scalar
/// demand, closing the bus.
fn msm_intro_neg_traces() -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);

    let ga = s.msm_intro(&g_pt);
    let _n = s.msm_neg(ga);

    let claim_g = s.ec_is(&g_pt, &g_pt);
    let root = s.assert_and_fold([claim_g]);
    s.finish(root)
}

#[test]
fn msm_intro_neg_checks() {
    let traces = msm_intro_neg_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn msm_intro_neg_proves() {
    verify_deferred(&msm_intro_neg_traces().prove())
        .expect("EcMsm intro+neg round-trip must verify");
}

/// In-circuit resolve of the 1-term claim `R = 1·G` (`R = G`): `msm_intro`
/// then `msm_resolve` lays the eval `EcMsm` node (a single absorb row, the
/// IV its cap) binding the value, and the `Is` ties it to `G`. The claim
/// folds into the transcript root — the real DAG consumer of the MSM.
fn msm_resolve_one_term_traces() -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let expr = s.msm_intro(&g_pt);
    // The scalar `1`, leafed under the group's scalar-domain bound.
    let one = s.uint_leaf(from_hex("1"), SN_PTR);
    // R = 1·G = G.
    let value = s.ec_msm(expr, &[(g_pt, one)]);
    let claim = s.ec_is(&value, &g_pt);

    let root = s.assert_and_fold([claim]);
    s.finish(root)
}

#[test]
fn msm_resolve_one_term_checks() {
    let traces = msm_resolve_one_term_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn msm_resolve_one_term_proves() {
    verify_deferred(&msm_resolve_one_term_traces().prove())
        .expect("EcMsm 1-term resolve round-trip must verify");
}

/// In-circuit resolve of the 2-term claim `R = 1·G + 1·Q` (`R = G + Q`):
/// `msm_combine` builds `⟨G×1, Q×1⟩`, `msm_resolve` lays the **two-row**
/// absorb sponge (the second row's cap chained from the first's digest),
/// and the `Is` ties the value to `G + Q`. Exercises the capacity-threading
/// constraint across rows.
fn msm_resolve_two_term_traces() -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let q_pt = create(&mut s, g2x, g2y); // Q = 2G, a distinct base
    let ga = s.msm_intro(&g_pt);
    let qb = s.msm_intro(&q_pt);
    let expr = s.msm_combine(ga, qb); // ⟨G×1, Q×1⟩, value G + Q

    let one = s.uint_leaf(from_hex("1"), SN_PTR);
    let r_pt = s.ec_add(&g_pt, &q_pt); // R = G + Q
    let value = s.ec_msm(expr, &[(g_pt, one), (q_pt, one)]);
    let claim = s.ec_is(&value, &r_pt);

    let root = s.assert_and_fold([claim]);
    s.finish(root)
}

#[test]
fn msm_resolve_two_term_checks() {
    let traces = msm_resolve_two_term_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn msm_resolve_two_term_proves() {
    verify_deferred(&msm_resolve_two_term_traces().prove())
        .expect("EcMsm 2-term resolve round-trip must verify");
}

/// The packaged [`straus`] strategy: `3·G + 5·Q` with `Q = 2G` (so the
/// claim value is `13G`), built by the subset-table joint double-and-add
/// and resolved in-circuit. Validates the helper end to end.
fn msm_straus_traces() -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let q = g + g; // Q = 2G, a distinct base
    let r = (0..13).fold(ProjectivePoint::IDENTITY, |acc, _| acc + g); // 3·G + 5·Q = 13G
    let (gx, gy) = k256_coords(&g);
    let (qx, qy) = k256_coords(&q);
    let (rx, ry) = k256_coords(&r);

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let q_pt = create(&mut s, qx, qy);
    let r_pt = create(&mut s, rx, ry);

    // Straus over the 2-base table {∞, G, Q, G+Q} (scan length inferred).
    let acc = straus(&mut s, &[(g_pt, from_hex("3")), (q_pt, from_hex("5"))]);
    let s3 = s.uint_leaf(from_hex("3"), SN_PTR);
    let s5 = s.uint_leaf(from_hex("5"), SN_PTR);
    let value = s.ec_msm(acc, &[(g_pt, s3), (q_pt, s5)]);
    let claim = s.ec_is(&value, &r_pt);

    let root = s.assert_and_fold([claim]);
    s.finish(root)
}

#[test]
fn msm_straus_checks() {
    let traces = msm_straus_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn msm_straus_proves() {
    verify_deferred(&msm_straus_traces().prove()).expect("Straus strategy round-trip must verify");
}

/// The **separate wNAF** strategy on the same claim `3·G + 5·Q = 13G` — two
/// per-base windowed-NAF scalar-muls over precomputed odd-multiple tables
/// ([`wnaf_table`] stage 1, [`wnaf_msm`] stage 2), combined and resolved.
/// `G`'s table is built once and passed in (the reuse the two-stage split
/// buys); here it also drives the lone `Q`.
fn msm_wnaf_traces() -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let q = g + g; // Q = 2G, a distinct base
    let r = (0..13).fold(ProjectivePoint::IDENTITY, |acc, _| acc + g); // 3G + 5·2G = 13G
    let (gx, gy) = k256_coords(&g);
    let (qx, qy) = k256_coords(&q);
    let (rx, ry) = k256_coords(&r);

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let q_pt = create(&mut s, qx, qy);
    let r_pt = create(&mut s, rx, ry);

    // Stage 1: precompute each base's odd-multiple table (window 4 → {1,3,5,7}P).
    let g_table = wnaf_table(&mut s, &g_pt, 4);
    let q_table = wnaf_table(&mut s, &q_pt, 4);
    // Stage 2: separate scalar-muls over the tables, then combine.
    let acc = wnaf_msm(&mut s, &[(&g_table, from_hex("3")), (&q_table, from_hex("5"))]);

    let s3 = s.uint_leaf(from_hex("3"), SN_PTR);
    let s5 = s.uint_leaf(from_hex("5"), SN_PTR);
    let value = s.ec_msm(acc, &[(g_pt, s3), (q_pt, s5)]);
    let claim = s.ec_is(&value, &r_pt);

    let root = s.assert_and_fold([claim]);
    s.finish(root)
}

#[test]
fn msm_wnaf_checks() {
    let traces = msm_wnaf_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn msm_wnaf_proves() {
    verify_deferred(&msm_wnaf_traces().prove())
        .expect("separate-wNAF strategy round-trip must verify");
}

/// The packaged [`joint_naf`] strategy on the same claim `3·G + 5·Q = 13G`
/// — the signed table `{±P, ±Q, ±(P±Q)}` (via `neg` nodes) reaches the same
/// value by a different chain. Validates the signed strategy end to end.
fn msm_joint_naf_traces() -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let q = g + g; // Q = 2G
    let r = (0..13).fold(ProjectivePoint::IDENTITY, |acc, _| acc + g); // 3·G + 5·Q = 13G
    let (gx, gy) = k256_coords(&g);
    let (qx, qy) = k256_coords(&q);
    let (rx, ry) = k256_coords(&r);

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let q_pt = create(&mut s, qx, qy);
    let r_pt = create(&mut s, rx, ry);

    let acc = joint_naf(&mut s, &[(g_pt, from_hex("3")), (q_pt, from_hex("5"))]);
    let s3 = s.uint_leaf(from_hex("3"), SN_PTR);
    let s5 = s.uint_leaf(from_hex("5"), SN_PTR);
    let value = s.ec_msm(acc, &[(g_pt, s3), (q_pt, s5)]);
    let claim = s.ec_is(&value, &r_pt);

    let root = s.assert_and_fold([claim]);
    s.finish(root)
}

#[test]
fn msm_joint_naf_checks() {
    let traces = msm_joint_naf_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn msm_joint_naf_proves() {
    verify_deferred(&msm_joint_naf_traces().prove())
        .expect("joint_naf strategy round-trip must verify");
}

/// The **interleaved wNAF** strategy ([`joint_wnaf`], `w = 4`) on the same
/// claim `3·G + 5·Q = 13G` — one shared double-and-add ladder, each base
/// adding its own (signed, sparse) wNAF digit. Reaches the same value as
/// [`straus`] by a different chain (shared doublings, fewer adds); the GLV
/// example's 4-base lever. Validates it end to end.
fn msm_joint_wnaf_traces() -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let q = g + g; // Q = 2G, a distinct base
    let r = (0..13).fold(ProjectivePoint::IDENTITY, |acc, _| acc + g); // 3·G + 5·Q = 13G
    let (gx, gy) = k256_coords(&g);
    let (qx, qy) = k256_coords(&q);
    let (rx, ry) = k256_coords(&r);

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let q_pt = create(&mut s, qx, qy);
    let r_pt = create(&mut s, rx, ry);

    let acc = joint_wnaf(&mut s, &[(g_pt, from_hex("3")), (q_pt, from_hex("5"))], 4);
    let s3 = s.uint_leaf(from_hex("3"), SN_PTR);
    let s5 = s.uint_leaf(from_hex("5"), SN_PTR);
    let value = s.ec_msm(acc, &[(g_pt, s3), (q_pt, s5)]);
    let claim = s.ec_is(&value, &r_pt);

    let root = s.assert_and_fold([claim]);
    s.finish(root)
}

#[test]
fn msm_joint_wnaf_checks() {
    let traces = msm_joint_wnaf_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn msm_joint_wnaf_proves() {
    verify_deferred(&msm_joint_wnaf_traces().prove())
        .expect("joint_wnaf strategy round-trip must verify");
}

/// Relation-identity dedup: a repeated `intro` / `combine` collapses onto
/// the one expression it already produced (like every other chiplet), so a
/// strategy that re-derives a sub-expression pays for it once. The
/// collapsed claim `R = G + Q` still resolves + proves.
fn msm_dedup_traces() -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let q = g + g; // Q = 2G
    let (gx, gy) = k256_coords(&g);
    let (qx, qy) = k256_coords(&q);
    let (rx, ry) = k256_coords(&(g + q)); // R = G + Q

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let q_pt = create(&mut s, qx, qy);

    let ga = s.msm_intro(&g_pt);
    let ga_again = s.msm_intro(&g_pt);
    assert_eq!(ga, ga_again, "intro(G) must dedup");
    let qb = s.msm_intro(&q_pt);

    let c1 = s.msm_combine(ga, qb);
    let c2 = s.msm_combine(ga, qb);
    assert_eq!(c1, c2, "combine(G, Q) must dedup");
    assert_eq!(s.msm_expr_count(), 3, "only ⟨G⟩, ⟨Q⟩, ⟨G,Q⟩ laid — the repeats collapsed",);

    let one = s.uint_leaf(from_hex("1"), SN_PTR);
    let r_pt = create(&mut s, rx, ry);
    let value = s.ec_msm(c1, &[(g_pt, one), (q_pt, one)]);
    let claim = s.ec_is(&value, &r_pt);

    let root = s.assert_and_fold([claim]);
    s.finish(root)
}

#[test]
fn msm_dedup_checks() {
    let traces = msm_dedup_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn msm_dedup_proves() {
    verify_deferred(&msm_dedup_traces().prove()).expect("deduped MSM round-trip must verify");
}

/// The claim `⟨G×1, Q×1⟩` (value `G + Q`) resolved with the two `(base,
/// scalar)` pairs in a chosen order — `swap` reverses them. The chiplet stores
/// its terms in one fixed (base-ptr) order regardless; only the pair order
/// passed to `ec_msm` changes.
fn msm_two_term_ordered(swap: bool) -> crate::session::SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let q_pt = create(&mut s, g2x, g2y);
    let ga = s.msm_intro(&g_pt);
    let qb = s.msm_intro(&q_pt);
    let expr = s.msm_combine(ga, qb);

    let one = s.uint_leaf(from_hex("1"), SN_PTR);
    let r_pt = s.ec_add(&g_pt, &q_pt);
    let value = if swap {
        s.ec_msm(expr, &[(q_pt, one), (g_pt, one)])
    } else {
        s.ec_msm(expr, &[(g_pt, one), (q_pt, one)])
    };
    let claim = s.ec_is(&value, &r_pt);

    let root = s.assert_and_fold([claim]);
    s.finish(root)
}

/// The resolve seam matches the claim's terms as a positionless **set**
/// (`MsmClaimTerm`), so the absorb — and thus the transcript root — follows
/// the **caller's** term-pair order, not the chiplet's internal storage order
/// (and so not the addition-chain strategy). Both orders are valid; their
/// roots differ. This is the determinism contract: the root is a function of
/// the declared claim, decoupled from how the witness was built.
#[test]
fn msm_resolve_absorb_order_is_caller_declared() {
    let t_gq = msm_two_term_ordered(false);
    let t_qg = msm_two_term_ordered(true);

    // Extract roots first (order-independent of the borrow `check` takes).
    let root_gq = t_gq.public_root().as_array();
    let root_qg = t_qg.public_root().as_array();
    assert_ne!(
        root_gq, root_qg,
        "absorb order (hence root) must follow the caller's term-pair order",
    );

    // Both are sound — the seam balances for either order.
    t_gq.check();
    t_qg.check();
}

/// Fully-merged precondition: resolving with a duplicate base node (here both
/// slots are `G`, so `Q`'s term goes uncovered) is rejected at recording —
/// the canonical claim has one node per distinct base, which keeps the root a
/// function of the term *set*.
#[test]
#[should_panic(expected = "duplicate base")]
fn msm_resolve_duplicate_base_rejected() {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));

    let mut s = Session::new();

    let g_pt = create(&mut s, gx, gy);
    let q_pt = create(&mut s, g2x, g2y);
    let ga = s.msm_intro(&g_pt);
    let qb = s.msm_intro(&q_pt);
    let expr = s.msm_combine(ga, qb);

    let one = s.uint_leaf(from_hex("1"), SN_PTR);
    // Two G slots, no Q — a non-canonical (unmerged-shaped) base list.
    let _ = s.ec_msm(expr, &[(g_pt, one), (g_pt, one)]);
}

/// An absorb run must name **one** expression on every row. The boundary
/// binds the node's value via `MsmExpr(msm_expr, …)` and each row attributes
/// its term via `MsmClaimTerm(msm_expr, …)`; if `msm_expr` could change
/// mid-run, a prover could hash one expression's terms (a root-matching hash)
/// while binding the node to another expression's value — a forged value
/// under a correct hash that root-comparison would *not* catch. The within-run
/// constancy constraint forbids it: tamper a non-boundary row's `COL_MSM_EXPR`
/// and the local check rejects the trace.
#[test]
#[should_panic(expected = "constraint not satisfied")]
fn msm_resolve_run_expr_must_be_constant() {
    let traces = msm_resolve_two_term_traces();
    let eval = traces.mains()[7]; // the transcript-eval main
    let ncols = eval.width();

    // The first absorb row of a 2-term run is non-boundary.
    let row = (0..eval.height())
        .find(|&r| {
            eval.values[r * ncols + COL_IS_EC_MSM] == Felt::ONE
                && eval.values[r * ncols + COL_IS_MSM_LAST] == Felt::ZERO
        })
        .expect("a non-boundary absorb row");

    let mut forged = eval.clone();
    let here = forged.values[row * ncols + COL_MSM_EXPR];
    forged.values[row * ncols + COL_MSM_EXPR] = here + Felt::ONE;

    // Locally valid before the fix (no other constraint reads COL_MSM_EXPR);
    // the constancy constraint is what now rejects it.
    check_local_inputs(TranscriptEvalAir, &forged, traces.public_root().as_array().to_vec());
}
