//! EC DAG layer tests — `EcCreate` / `EcBinOp(Add)` / `Is` end to
//! end through the [`Session`], the EC sibling of the uint DAG.
//!
//! Validation rides the canonical point dedup: `ec_add`'s result and an
//! independently `ec_create`d k256 KAT are *distinct* DAG nodes (distinct
//! hashes) that intern to one point ptr **iff** our circuit's sum equals
//! k256's — so the `ec_is` assert is both the k256 cross-check and the
//! two-chain dedup showcase. The prove/verify round-trip then closes
//! every bus (the EC node family activated: `EcGroupAdd` live at mult 1,
//! the eval chip consuming `EcGroup` / `EcPoint` / `EcGroupAdd`).

use std::collections::HashMap;

use k256::ProjectivePoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use miden_air::lookup::Challenges;
use miden_core::Felt;
use miden_core::field::QuadFelt;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::ec::EcPointStoreAir;
use crate::ec::add::{
    COL_CANCEL, COL_DBL, EcGroupAddAir, PERIOD as ADD_PERIOD, ROW_TERM, TERM_CELL_MULT,
};
use crate::ec::groups::EcGroupsAir;
use crate::hash::chunk::ChunkAir;
use crate::hash::keccak::node::KeccakNodeAir;
use crate::hash::keccak::round::KeccakRoundAir;
use crate::hash::keccak::sponge::KeccakSpongeAir;
use crate::math::{U256, from_hex};
use crate::primitives::bitwise64::Bitwise64Air;
use crate::primitives::byte_pair_lut::BytePairLutAir;
use crate::relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS};
use crate::session::{Session, SessionTraces};
use crate::tests::integration::fold_balance;
use crate::transcript::eval::{
    COL_A_PTR, COL_B_PTR, COL_IS_ADD, COL_IS_EC_CREATE, COL_IS_EC_OP, COL_IS_EC_PAI, COL_IS_IS,
    COL_IS_NEG, COL_IS_SUB, COL_PTR, NUM_MAIN_COLS as EVAL_COLS, TranscriptEvalAir,
};
use crate::transcript::poseidon2::Poseidon2Air;
use crate::uint::UintStoreAir;
use crate::uint::add::UintAddAir;
use crate::uint::mul::UintMulAir;

/// secp256k1: `p − 1`, curve `y² = x³ + 7` (a = 0, b = 7), pinned at the
/// protocol addresses below.
const P_MINUS_1: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E";
const FP: u32 = 1;
const A_PTR: u32 = 2;
const B_PTR: u32 = 3;

fn rand_qf(rng: &mut impl Rng) -> QuadFelt {
    QuadFelt::new([
        Felt::from(rng.random::<u32>()),
        Felt::from(rng.random::<u32>()),
    ])
}

/// Big-endian field bytes → our `U256` (through the KAT hex path).
fn be_to_u256(bytes: impl AsRef<[u8]>) -> U256 {
    let hex: String = bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    from_hex(&hex)
}

/// Affine coordinates of a finite k256 point as our `U256` pair.
fn k256_coords(p: &ProjectivePoint) -> (U256, U256) {
    let enc = p.to_affine().to_encoded_point(false);
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
    let modulus = s.pin_uint(FP, from_hex(P_MINUS_1), FP);
    let a_t = s.pin_uint(A_PTR, from_hex("0"), FP);
    let b_t = s.pin_uint(B_PTR, from_hex("7"), FP);

    let gx_n = s.uint_leaf(gx, FP);
    let gy_n = s.uint_leaf(gy, FP);
    let g2x_n = s.uint_leaf(g2x, FP);
    let g2y_n = s.uint_leaf(g2y, FP);
    let g_pt = s.ec_create(A_PTR, B_PTR, &gx_n, &gy_n);
    let g2_pt = s.ec_create(A_PTR, B_PTR, &g2x_n, &g2y_n);
    let r = s.ec_add(&g_pt, &g2_pt); // chord: G + 2G = 3G

    let g3x_n = s.uint_leaf(g3x, FP);
    let g3y_n = s.uint_leaf(g3y, FP);
    let expected = s.ec_create(A_PTR, B_PTR, &g3x_n, &g3y_n);

    // k256 cross-check + two-chain dedup: `r` (add result) and `expected`
    // (k256 KAT) are distinct DAG nodes that must share one point ptr.
    let claim = s.ec_is(&r, &expected);
    let root = s.assert_and_fold([modulus, a_t, b_t, claim]);
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
    proof.verify().expect("EC DAG round-trip must verify");
}

/// Create `G`; then `−G` via `ec_neg` (the cancel-case primitive) and
/// `3G − G = 2G` via `ec_sub` (one `EcBinOp/Sub` row consuming the
/// rearranged `EcGroupAdd(g, R, Q, P)` — `R + Q = P`), each `ec_is`'d
/// against the independently created k256 KAT.
fn ec_dag_neg_sub_traces() -> SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));
    let (g3x, g3y) = k256_coords(&(g + g + g));
    let (ngx, ngy) = k256_coords(&(-g));

    let mut s = Session::new();
    let modulus = s.pin_uint(FP, from_hex(P_MINUS_1), FP);
    let a_t = s.pin_uint(A_PTR, from_hex("0"), FP);
    let b_t = s.pin_uint(B_PTR, from_hex("7"), FP);

    let create = |s: &mut Session, x: U256, y: U256| {
        let xn = s.uint_leaf(x, FP);
        let yn = s.uint_leaf(y, FP);
        s.ec_create(A_PTR, B_PTR, &xn, &yn)
    };

    let g_pt = create(&mut s, gx, gy);

    // −G via Neg (cancel through the DAG), checked vs k256.
    let neg_g = s.ec_neg(&g_pt);
    let neg_kat = create(&mut s, ngx, ngy);
    let neg_claim = s.ec_is(&neg_g, &neg_kat);

    // 3G − G = 2G via Sub — one row, the rearranged R + Q = P relation.
    let g3_pt = create(&mut s, g3x, g3y);
    let diff = s.ec_sub(&g3_pt, &g_pt);
    let g2_kat = create(&mut s, g2x, g2y);
    let sub_claim = s.ec_is(&diff, &g2_kat);

    let root = s.assert_and_fold([modulus, a_t, b_t, neg_claim, sub_claim]);
    s.finish(root)
}

#[test]
fn ec_dag_neg_sub_matches_k256() {
    let traces = ec_dag_neg_sub_traces();
    traces.check();
}

#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn ec_dag_neg_sub_proves() {
    ec_dag_neg_sub_traces()
        .prove()
        .verify()
        .expect("EC DAG neg/sub round-trip must verify");
}

/// Create ∞ via `ec_pai`, then the three group-law pass-throughs through
/// the DAG: ∞ + G = G, 2G + ∞ = 2G, ∞ + ∞ = ∞ — each `ec_is`'d against
/// the operand it must equal.
fn ec_dag_pai_traces() -> SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));

    let mut s = Session::new();
    let modulus = s.pin_uint(FP, from_hex(P_MINUS_1), FP);
    let a_t = s.pin_uint(A_PTR, from_hex("0"), FP);
    let b_t = s.pin_uint(B_PTR, from_hex("7"), FP);

    let create = |s: &mut Session, x: U256, y: U256| {
        let xn = s.uint_leaf(x, FP);
        let yn = s.uint_leaf(y, FP);
        s.ec_create(A_PTR, B_PTR, &xn, &yn)
    };

    let inf = s.ec_pai(A_PTR, B_PTR, FP);
    let g_pt = create(&mut s, gx, gy);
    let g2_pt = create(&mut s, g2x, g2y);

    let pp = s.ec_add(&inf, &g_pt); // ∞ + G = G (pai_p)
    let pq = s.ec_add(&g2_pt, &inf); // 2G + ∞ = 2G (pai_q)
    let bb = s.ec_add(&inf, &inf); // ∞ + ∞ = ∞ (both flags)

    let c1 = s.ec_is(&pp, &g_pt);
    let c2 = s.ec_is(&pq, &g2_pt);
    let c3 = s.ec_is(&bb, &inf);

    let root = s.assert_and_fold([modulus, a_t, b_t, c1, c2, c3]);
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
    ec_dag_pai_traces()
        .prove()
        .verify()
        .expect("EC DAG PAI round-trip must verify");
}

/// `G + G = 2G` through the DAG — the tangent (double) arm, `ec_add(P, P)`,
/// validated vs k256. (The chiplet's double case was covered; this closes
/// the through-the-DAG coverage gap.)
fn ec_dag_double_traces() -> SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));

    let mut s = Session::new();
    let modulus = s.pin_uint(FP, from_hex(P_MINUS_1), FP);
    let a_t = s.pin_uint(A_PTR, from_hex("0"), FP);
    let b_t = s.pin_uint(B_PTR, from_hex("7"), FP);

    let gx_n = s.uint_leaf(gx, FP);
    let gy_n = s.uint_leaf(gy, FP);
    let g_pt = s.ec_create(A_PTR, B_PTR, &gx_n, &gy_n);
    let dbl = s.ec_add(&g_pt, &g_pt); // tangent: G + G = 2G

    let g2x_n = s.uint_leaf(g2x, FP);
    let g2y_n = s.uint_leaf(g2y, FP);
    let g2_kat = s.ec_create(A_PTR, B_PTR, &g2x_n, &g2y_n);
    let claim = s.ec_is(&dbl, &g2_kat);

    let root = s.assert_and_fold([modulus, a_t, b_t, claim]);
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
    ec_dag_double_traces()
        .prove()
        .verify()
        .expect("EC DAG double round-trip must verify");
}

// ============================================================================
// Adversarial DAG tamper tests — a *locally-valid* forgery of the eval row's
// EC fields (passes the eval AIR's own constraints) must still be caught by
// the cross-chiplet bus: a mismatched or dangling provide.
// ============================================================================

/// Net unmatched LogUp denominators across the full 14-chiplet stack
/// (0 ⟺ every bus closes), with the `eval` main replaced by `eval_main`.
fn dag_residual(traces: &SessionTraces, eval_main: &RowMajorMatrix<Felt>, rng: &mut impl Rng) -> usize {
    dag_residual_with(traces, eval_main, traces.mains()[13], rng)
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
    // 0.26 dropped per-chiplet public values; rebuild the σ/n `inv_n` slot
    // `fold_balance` (whose `pv` param is unchanged on this branch) still
    // reads, mirroring `tests::ec_add::stack_residual`.
    let challenges = Challenges::new(rand_qf(rng), rand_qf(rng), MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mut net: HashMap<QuadFelt, (Felt, String)> = HashMap::new();
    fold_balance(&ChunkAir, mains[0], &challenges, &mut net);
    fold_balance(&Poseidon2Air, mains[1], &challenges, &mut net);
    fold_balance(&KeccakRoundAir, mains[2], &challenges, &mut net);
    fold_balance(&Bitwise64Air, mains[3], &challenges, &mut net);
    fold_balance(&BytePairLutAir, mains[4], &challenges, &mut net);
    fold_balance(&KeccakSpongeAir, mains[5], &challenges, &mut net);
    fold_balance(&KeccakNodeAir, mains[6], &challenges, &mut net);
    fold_balance(&TranscriptEvalAir, eval_main, &challenges, &mut net);
    fold_balance(&UintStoreAir, mains[8], &challenges, &mut net);
    fold_balance(&UintAddAir, mains[9], &challenges, &mut net);
    fold_balance(&UintMulAir, mains[10], &challenges, &mut net);
    fold_balance(&EcGroupsAir, mains[11], &challenges, &mut net);
    fold_balance(&EcPointStoreAir, mains[12], &challenges, &mut net);
    fold_balance(&EcGroupAddAir, add_main, &challenges, &mut net);
    net.into_values().filter(|(m, _)| *m != Felt::ZERO).count()
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
/// `op_col` — the grouped encoding identifies an EC Neg / Sub / … by the
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
fn tamper(main: &RowMajorMatrix<Felt>, row: usize, cells: &[(usize, Felt)]) -> RowMajorMatrix<Felt> {
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
fn dag_finite_forged_as_pai_unbalances() {
    // Claim a finite point is ∞: flip a EcCreate row to the PAI mode
    // (is_ec_create→0, is_ec_pai→1) and zero its coords, so the row
    // stays locally valid. The bus catches it — the finite point's EcPoint
    // provide (is_pai = 0) loses its consumer, and the coord children's
    // Uint bindings dangle.
    let traces = ec_dag_3g_traces();
    let mut rng = StdRng::seed_from_u64(0xEC_DA9_F01);
    let eval = traces.mains()[7];
    assert_eq!(dag_residual(&traces, eval, &mut rng), 0, "honest stack must balance");

    let row = first_row_with_flag(eval, COL_IS_EC_CREATE);
    let forged = tamper(
        eval,
        row,
        &[
            (COL_IS_EC_CREATE, Felt::ZERO),
            (COL_IS_EC_PAI, Felt::ONE),
            (COL_A_PTR, Felt::ZERO),
            (COL_B_PTR, Felt::ZERO),
        ],
    );
    eval_locally_holds(&traces, &forged);
    assert_ne!(
        dag_residual(&traces, &forged, &mut rng),
        0,
        "the bus must catch a finite point forged as ∞",
    );
}

#[test]
fn dag_neg_infinity_slot_forged_unbalances() {
    // On a Neg row the cancel result (∞) rides the b_ptr slot. Repoint it
    // off the group's PAI: locally valid (b_ptr is bus-pinned, not local),
    // but the EcGroupAdd consume (group, P, R, b_ptr) no longer matches the
    // cancel provide (…, ∞).
    let traces = ec_dag_neg_sub_traces();
    let mut rng = StdRng::seed_from_u64(0xEC_DA9_F02);
    let eval = traces.mains()[7];
    assert_eq!(dag_residual(&traces, eval, &mut rng), 0, "honest stack must balance");

    let row = first_ec_op_row(eval, COL_IS_NEG);
    let pai = eval.values[row * EVAL_COLS + COL_B_PTR]; // the ∞ ptr (cancel result-slot)
    let forged = tamper(eval, row, &[(COL_B_PTR, pai + Felt::ONE)]);
    eval_locally_holds(&traces, &forged);
    assert_ne!(
        dag_residual(&traces, &forged, &mut rng),
        0,
        "the bus must catch a forged ∞ result-slot",
    );
}

#[test]
fn dag_sub_result_forged_unbalances() {
    // A Sub row binds its result R on COL_PTR (locally free — bus-pinned)
    // and consumes the rearranged EcGroupAdd(g, R, Q, P). Repoint R: locally
    // valid, but the consume's operand-R no longer matches the EcGroupAdd
    // provide, and the Group binding the row provides (h ↔ R) dangles its
    // `ec_is` consumer — the rearrangement is load-bearing, not decorative.
    let traces = ec_dag_neg_sub_traces();
    let mut rng = StdRng::seed_from_u64(0xEC_DA9_F03);
    let eval = traces.mains()[7];
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

/// `G + G = 2G` (the double arm, claimed against k256) plus an **unused**
/// `Neg(G)`. The double block's `EcGroupAdd(G, G, 2G)` provide and the
/// `Neg`'s cancel block `(G, −G, ∞)` are what the forgery below reroutes.
fn ec_dag_neg_double_traces() -> SessionTraces {
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_coords(&g);
    let (g2x, g2y) = k256_coords(&(g + g));

    let mut s = Session::new();
    let modulus = s.pin_uint(FP, from_hex(P_MINUS_1), FP);
    let a_t = s.pin_uint(A_PTR, from_hex("0"), FP);
    let b_t = s.pin_uint(B_PTR, from_hex("7"), FP);

    let gx_n = s.uint_leaf(gx, FP);
    let gy_n = s.uint_leaf(gy, FP);
    let g_pt = s.ec_create(A_PTR, B_PTR, &gx_n, &gy_n);
    let dbl = s.ec_add(&g_pt, &g_pt); // double: provides EcGroupAdd(G, G, 2G)
    let neg = s.ec_neg(&g_pt); // Neg: lays the cancel block (G, −G, ∞)
    // Consume the Neg with a tautology (`Neg(G) ≡ Neg(G)`) so it isn't a
    // stray node. Unlike an `Is` against a KAT, a self-`Is` pins the Neg's
    // result to *nothing external*, leaving the result-slot's soundness to
    // col 7 alone — exactly the surface under test.
    let neg_self = s.ec_is(&neg, &neg);

    let g2x_n = s.uint_leaf(g2x, FP);
    let g2y_n = s.uint_leaf(g2y, FP);
    let g2_kat = s.ec_create(A_PTR, B_PTR, &g2x_n, &g2y_n);
    let dbl_claim = s.ec_is(&dbl, &g2_kat);

    let root = s.assert_and_fold([modulus, a_t, b_t, dbl_claim, neg_self]);
    s.finish(root)
}

#[test]
fn dag_neg_result_forged_unbalances() {
    // The deep forgery the col-7 ∞-pin closes: bind `Neg(G)` to a *wrong*
    // finite point by repointing its EcGroupAdd result-slot (`b_ptr`) to a
    // real finite sum that already has a matching provide. Pick the wrong
    // result `R = G`; then `P + R = G + G = 2G`, which the double block
    // provides as `(G, G, 2G)`. Forge the Neg row's result (`ptr`) → G and
    // ∞-slot (`b_ptr`) → 2G, then serve the now-doubled `(G, G, 2G)` consume
    // by bumping the double block's provide mult 1→2 and zeroing the cancel
    // block's mult (the Neg no longer consumes it).
    //
    // col 6 (EcGroupAdd) and every other pre-fix bus still close — *without*
    // col 7 this forged `Neg(G) = G` is fully balanced (the soundness hole).
    // col 7's `EcPoint(b_ptr, is_pai = 1)` consume now reads
    // `EcPoint(2G, is_pai = 1)`, which no store row provides (2G is finite),
    // and the honest ∞ provide routed by `neg` loses its consumer — two
    // unmatched denominators. That pin is exactly what forces `R = −P`.
    let traces = ec_dag_neg_double_traces();
    let mut rng = StdRng::seed_from_u64(0xEC_DA9_F04);
    let eval = traces.mains()[7];
    let add = traces.mains()[13];
    assert_eq!(
        dag_residual_with(&traces, eval, add, &mut rng),
        0,
        "honest stack must balance",
    );

    // Operand `G`'s ptr (the Neg row's `a_ptr`), the Neg's honest result −G
    // (its `ptr`), and `2G`'s ptr (the double row's result).
    let neg_row = first_ec_op_row(eval, COL_IS_NEG);
    let ptr_g = eval.values[neg_row * EVAL_COLS + COL_A_PTR];
    let ptr_neg = eval.values[neg_row * EVAL_COLS + COL_PTR];
    let dbl_row = first_ec_op_row(eval, COL_IS_ADD);
    let ptr_2g = eval.values[dbl_row * EVAL_COLS + COL_PTR];

    // The self-`Is(neg, neg)` row consumes the Neg's binding at ptr(−G);
    // rebinding the Neg result means repointing that consume too — else col 5
    // catches the binding mismatch, masking col 7. (Match the ec-Is row: the
    // shared is_is flag also rides uint-Is rows, so gate on is_ec_op too.)
    let is_row = (0..eval.height())
        .find(|&r| {
            eval.values[r * EVAL_COLS + COL_IS_EC_OP] == Felt::ONE
                && eval.values[r * EVAL_COLS + COL_IS_IS] == Felt::ONE
                && eval.values[r * EVAL_COLS + COL_A_PTR] == ptr_neg
        })
        .expect("Is(neg, neg) row");

    // Forge the Neg row (result → G, ∞-slot → 2G) and the self-Is consume.
    let forged_eval = tamper(eval, neg_row, &[(COL_PTR, ptr_g), (COL_B_PTR, ptr_2g)]);
    let forged_eval = tamper(&forged_eval, is_row, &[(COL_A_PTR, ptr_g), (COL_B_PTR, ptr_g)]);

    // Reroute the ec_add provides: the double serves two consumers now, the
    // cancel none. Only the provide-mult term cell changes — the per-block
    // EcPoint operand consumes are mult-independent, so the store is
    // untouched (no cascade), isolating col 7 as the sole catch.
    let dbl_term = (first_row_with_flag(add, COL_DBL) / ADD_PERIOD) * ADD_PERIOD + ROW_TERM;
    let cancel_term = (first_row_with_flag(add, COL_CANCEL) / ADD_PERIOD) * ADD_PERIOD + ROW_TERM;
    let forged_add = tamper(add, dbl_term, &[(TERM_CELL_MULT, Felt::from(2u32))]);
    let forged_add = tamper(&forged_add, cancel_term, &[(TERM_CELL_MULT, Felt::ZERO)]);

    eval_locally_holds(&traces, &forged_eval);
    assert_ne!(
        dag_residual_with(&traces, &forged_eval, &forged_add, &mut rng),
        0,
        "col 7 must catch a Neg result bound to a finite point (∞-slot not ∞)",
    );
}
