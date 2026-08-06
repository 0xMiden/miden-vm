//! EC DAG layer tests — `EcCreate` / `EcBinOp(Add)` / `Is` end to
//! end through the [`Session`], the EC sibling of the uint DAG.
//!
//! Validation rides the canonical point dedup: `ec_add`'s result and an
//! independently `ec_create`d k256 KAT are *distinct* DAG nodes (distinct
//! hashes) that intern to one point ptr **iff** our circuit's sum equals
//! k256's — so the `ec_is` assert is both the k256 cross-check and the
//! two-chain dedup showcase. The prove/verify round-trip then closes
//! every bus (the EC node family activated: `EcGroupAdd` live at mult 1,
//! create rows consuming `EcPoint`, and add/sub rows consuming `EcGroupAdd`).

use std::{format, string::String, vec};

use k256::{ProjectivePoint, elliptic_curve::sec1::ToSec1Point};
use miden_air::lookup::Challenges;
use miden_core::{
    Felt,
    field::QuadFelt,
    utils::{Matrix, RowMajorMatrix},
};
use miden_precompiles::CurveId;
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::{
    math::{U256, from_hex},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::{Session, SessionTraces, verify_deferred},
    tests::bus_balance::session_stack_residual,
    transcript::eval::{
        COL_A_PTR, COL_B_PTR, COL_BOUND_PTR, COL_IS_EC_CREATE, COL_IS_EC_OP, COL_IS_EC_PAI,
        COL_IS_SUB, COL_LHS_BEGIN, COL_PTR, COL_RHS_BEGIN, DIGEST_WIDTH,
        NUM_MAIN_COLS as EVAL_COLS, TranscriptEvalAir,
    },
};

/// secp256k1 VM-owned uint/group pointers.
const FP: u32 = CurveId::Secp256k1.base_domain().bound_ptr();
const GROUP_PTR: u32 = CurveId::Secp256k1.group_ptr();

fn rand_qf(rng: &mut impl Rng) -> QuadFelt {
    QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())])
}

/// Big-endian field bytes → our `U256` (through the KAT hex path).
fn be_to_u256(bytes: impl AsRef<[u8]>) -> U256 {
    let hex: String = bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    from_hex(&hex)
}

/// Affine coordinates of a finite k256 point as our `U256` pair.
fn k256_coords(p: &ProjectivePoint) -> (U256, U256) {
    let enc = p.to_affine().to_sec1_point(false);
    (
        be_to_u256(enc.x().expect("finite point")),
        be_to_u256(enc.y().expect("finite point")),
    )
}

/// Build the `G + 2G = 3G` statement: create `G` and `2G`, `ec_add` them,
/// and `ec_is` the result against an independently created k256 `3G`. The
/// `ec_is` panics unless our circuit's sum lands on the k256 KAT's ptr.
fn ec_dag_3g_traces() -> SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));
    let (g3x, g3y) = k256_coords(&(g + g + g));

    let mut s = Session::new();

    let gx_n = s.uint_leaf(gx, FP);
    let gy_n = s.uint_leaf(gy, FP);
    let g2x_n = s.uint_leaf(g2x, FP);
    let g2y_n = s.uint_leaf(g2y, FP);
    let g_pt = s.ec_create(GROUP_PTR, &gx_n, &gy_n);
    let g2_pt = s.ec_create(GROUP_PTR, &g2x_n, &g2y_n);
    let r = s.ec_add(&g_pt, &g2_pt); // chord: G + 2G = 3G

    let g3x_n = s.uint_leaf(g3x, FP);
    let g3y_n = s.uint_leaf(g3y, FP);
    let expected = s.ec_create(GROUP_PTR, &g3x_n, &g3y_n);

    // k256 cross-check + two-chain dedup: `r` (add result) and `expected`
    // (k256 KAT) are distinct DAG nodes that must share one point ptr.
    let claim = s.ec_is(&r, &expected);
    let root = s.assert_and_fold([claim]);
    s.finish(root)
}

#[test]
fn ec_dag_add_matches_k256() {
    // Building the statement already cross-checks vs k256 (the `ec_is`
    // assert) and exercises the two-chain dedup; here we also close the
    // per-chiplet local constraints over the activated EC node family.
    let traces = ec_dag_3g_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn ec_dag_add_proves() {
    let traces = ec_dag_3g_traces();
    let proof = traces.prove();
    verify_deferred(&proof).expect("EC DAG round-trip must verify");
}

/// Create `G`; then `−G` via `ec_sub(∞, G)` and `3G − G = 2G` via
/// `ec_sub` (one `EcBinOp/Sub` row consuming the rearranged
/// `EcGroupAdd(g, R, Q, P)` — `R + Q = P`), each `ec_is`'d against the
/// independently created k256 KAT.
fn ec_dag_sub_from_pai_traces() -> SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));
    let (g3x, g3y) = k256_coords(&(g + g + g));
    let (ngx, ngy) = k256_coords(&(-g));

    let mut s = Session::new();

    let create = |s: &mut Session, x: U256, y: U256| {
        let xn = s.uint_leaf(x, FP);
        let yn = s.uint_leaf(y, FP);
        s.ec_create(GROUP_PTR, &xn, &yn)
    };

    let g_pt = create(&mut s, gx, gy);

    // −G via Sub from the group's point-at-infinity, checked vs k256.
    let inf = s.ec_pai(GROUP_PTR);
    let neg_g = s.ec_sub(&inf, &g_pt);
    let neg_kat = create(&mut s, ngx, ngy);
    let neg_claim = s.ec_is(&neg_g, &neg_kat);

    // 3G − G = 2G via Sub — one row, the rearranged R + Q = P relation.
    let g3_pt = create(&mut s, g3x, g3y);
    let diff = s.ec_sub(&g3_pt, &g_pt);
    let g2_kat = create(&mut s, g2x, g2y);
    let sub_claim = s.ec_is(&diff, &g2_kat);

    let root = s.assert_and_fold([neg_claim, sub_claim]);
    s.finish(root)
}

#[test]
fn ec_dag_sub_from_pai_matches_k256() {
    let traces = ec_dag_sub_from_pai_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn ec_dag_sub_from_pai_proves() {
    verify_deferred(&ec_dag_sub_from_pai_traces().prove())
        .expect("EC DAG sub-from-PAI/sub round-trip must verify");
}

/// Create ∞ via `ec_pai`, then the three group-law pass-throughs through
/// the DAG: ∞ + G = G, 2G + ∞ = 2G, ∞ + ∞ = ∞ — each `ec_is`'d against
/// the operand it must equal.
fn ec_dag_pai_traces() -> SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));

    let mut s = Session::new();

    let create = |s: &mut Session, x: U256, y: U256| {
        let xn = s.uint_leaf(x, FP);
        let yn = s.uint_leaf(y, FP);
        s.ec_create(GROUP_PTR, &xn, &yn)
    };

    let inf = s.ec_pai(GROUP_PTR);
    let g_pt = create(&mut s, gx, gy);
    let g2_pt = create(&mut s, g2x, g2y);

    let pp = s.ec_add(&inf, &g_pt); // ∞ + G = G (pai_p)
    let pq = s.ec_add(&g2_pt, &inf); // 2G + ∞ = 2G (pai_q)
    let bb = s.ec_add(&inf, &inf); // ∞ + ∞ = ∞ (both flags)

    let c1 = s.ec_is(&pp, &g_pt);
    let c2 = s.ec_is(&pq, &g2_pt);
    let c3 = s.ec_is(&bb, &inf);

    let root = s.assert_and_fold([c1, c2, c3]);
    s.finish(root)
}

#[test]
fn ec_dag_pai_passthroughs_hold() {
    let traces = ec_dag_pai_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn ec_dag_pai_proves() {
    verify_deferred(&ec_dag_pai_traces().prove()).expect("EC DAG PAI round-trip must verify");
}

/// `G + G = 2G` through the DAG — the tangent (double) arm, `ec_add(P, P)`,
/// validated vs k256. (The chiplet's double case was covered; this closes
/// the through-the-DAG coverage gap.)
fn ec_dag_double_traces() -> SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));

    let mut s = Session::new();

    let gx_n = s.uint_leaf(gx, FP);
    let gy_n = s.uint_leaf(gy, FP);
    let g_pt = s.ec_create(GROUP_PTR, &gx_n, &gy_n);
    let dbl = s.ec_add(&g_pt, &g_pt); // tangent: G + G = 2G

    let g2x_n = s.uint_leaf(g2x, FP);
    let g2y_n = s.uint_leaf(g2y, FP);
    let g2_kat = s.ec_create(GROUP_PTR, &g2x_n, &g2y_n);
    let claim = s.ec_is(&dbl, &g2_kat);

    let root = s.assert_and_fold([claim]);
    s.finish(root)
}

#[test]
fn ec_dag_double_matches_k256() {
    let traces = ec_dag_double_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn ec_dag_double_proves() {
    verify_deferred(&ec_dag_double_traces().prove()).expect("EC DAG double round-trip must verify");
}

// ============================================================================
// Adversarial DAG tamper tests — a *locally-valid* forgery of the eval row's
// EC fields (passes the eval AIR's own constraints) must still be caught by
// the cross-chiplet bus: a mismatched or dangling provide.
// ============================================================================

/// Net unmatched LogUp denominators across the full thirteen-chiplet
/// stack (0 ⟺ every bus closes), with the `eval` main replaced by
/// `eval_main`.
fn dag_residual(
    traces: &SessionTraces,
    eval_main: &RowMajorMatrix<Felt>,
    rng: &mut impl Rng,
) -> usize {
    dag_residual_with(traces, eval_main, traces.mains()[10], rng)
}

/// [`dag_residual`] with the `EcGroupAdd` (ec_add) main also overridden —
/// for forgeries that reroute provides across the eval *and* ec_add
/// chiplets at once (a single-main swap can't express those).
fn dag_residual_with(
    traces: &SessionTraces,
    eval_main: &RowMajorMatrix<Felt>,
    add_main: &RowMajorMatrix<Felt>,
    rng: &mut impl Rng,
) -> usize {
    let mains = traces.mains();
    let challenges = Challenges::new(rand_qf(rng), rand_qf(rng), MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    session_stack_residual(&mains, &[(5, eval_main), (10, add_main)], &challenges).len()
}

/// First row whose `col` flag is 1 (width taken from the matrix, so this
/// works on the eval *and* ec_add mains).
fn first_row_with_flag(main: &RowMajorMatrix<Felt>, col: usize) -> usize {
    let ncols = main.width();
    (0..main.height())
        .find(|&r| main.values[r * ncols + col] == Felt::ONE)
        .expect("no row with that flag")
}

/// First eval row that is an EC op (`is_ec_op`) carrying the shared op flag
/// `op_col` — the grouped encoding identifies an EC Add / Sub / Is by the
/// (family, op) pair rather than a dedicated column.
fn first_ec_op_row(main: &RowMajorMatrix<Felt>, op_col: usize) -> usize {
    (0..main.height())
        .find(|&r| {
            main.values[r * EVAL_COLS + COL_IS_EC_OP] == Felt::ONE
                && main.values[r * EVAL_COLS + op_col] == Felt::ONE
        })
        .expect("no ec-op row with that op flag")
}

/// Clone a main, overwriting cells of one row (width from the matrix).
fn tamper(
    main: &RowMajorMatrix<Felt>,
    row: usize,
    cells: &[(usize, Felt)],
) -> RowMajorMatrix<Felt> {
    let ncols = main.width();
    let mut m = main.clone();
    for &(col, v) in cells {
        m.values[row * ncols + col] = v;
    }
    m
}

/// Local constraint check on a (tampered) eval main — the forgery's *local*
/// validity, so soundness must come from the bus. The eval chip reads the
/// shared transcript root, so feed the real `air_inputs` (its row-0 pin).
fn eval_locally_holds(traces: &SessionTraces, eval_main: &RowMajorMatrix<Felt>) {
    crate::tests::check_local_inputs(
        TranscriptEvalAir,
        eval_main,
        traces.public_root().as_array().to_vec(),
    );
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn dag_pai_payload_must_be_true_true() {
    // A PAI VALUE node has no coordinate children. Its canonical payload is
    // `(TRUE_DIGEST, TRUE_DIGEST)`, i.e. zero digest in both rate halves.
    let traces = ec_dag_pai_traces();
    let eval = traces.mains()[5];
    let row = first_row_with_flag(eval, COL_IS_EC_PAI);
    let forged = tamper(eval, row, &[(COL_LHS_BEGIN, Felt::ONE)]);

    eval_locally_holds(&traces, &forged);
}

#[test]
fn dag_finite_forged_as_pai_unbalances() {
    // Claim a finite point is ∞: flip a EcCreate row to the PAI mode
    // (is_ec_create→0, is_ec_pai→1), zero its coord fields, and zero its
    // canonical PAI payload so the row stays locally valid. The bus catches
    // it — the finite point's EcPoint provide (is_pai = 0) loses its
    // consumer, and the coord children / Poseidon2 messages dangle.
    let traces = ec_dag_3g_traces();
    let mut rng = StdRng::seed_from_u64(0xec_da9_f01);
    let eval = traces.mains()[5];
    assert_eq!(dag_residual(&traces, eval, &mut rng), 0, "honest stack must balance");

    let row = first_row_with_flag(eval, COL_IS_EC_CREATE);
    let mut cells = vec![
        (COL_IS_EC_CREATE, Felt::ZERO),
        (COL_IS_EC_PAI, Felt::ONE),
        (COL_BOUND_PTR, Felt::ZERO),
        (COL_A_PTR, Felt::ZERO),
        (COL_B_PTR, Felt::ZERO),
    ];
    for i in 0..DIGEST_WIDTH {
        cells.push((COL_LHS_BEGIN + i, Felt::ZERO));
        cells.push((COL_RHS_BEGIN + i, Felt::ZERO));
    }
    let forged = tamper(eval, row, &cells);
    eval_locally_holds(&traces, &forged);
    assert_ne!(
        dag_residual(&traces, &forged, &mut rng),
        0,
        "the bus must catch a finite point forged as ∞",
    );
}

#[test]
fn dag_sub_result_forged_unbalances() {
    // A Sub row binds its result R on COL_PTR (locally free — bus-pinned)
    // and consumes the rearranged EcGroupAdd(g, R, Q, P). Repoint R: locally
    // valid, but the consume's operand-R no longer matches the EcGroupAdd
    // provide, and the Group binding the row provides (h ↔ R) dangles its
    // `ec_is` consumer — the rearrangement is load-bearing, not decorative.
    let traces = ec_dag_sub_from_pai_traces();
    let mut rng = StdRng::seed_from_u64(0xec_da9_f03);
    let eval = traces.mains()[5];
    assert_eq!(dag_residual(&traces, eval, &mut rng), 0, "honest stack must balance");

    let row = first_ec_op_row(eval, COL_IS_SUB);
    let r = eval.values[row * EVAL_COLS + COL_PTR]; // R = P − Q, the bound result
    let forged = tamper(eval, row, &[(COL_PTR, r + Felt::ONE)]);
    eval_locally_holds(&traces, &forged);
    assert_ne!(
        dag_residual(&traces, &forged, &mut rng),
        0,
        "the bus must catch a forged Sub result",
    );
}
