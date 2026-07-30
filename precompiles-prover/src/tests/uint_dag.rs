//! DAG-level uint arithmetic: the eval chip's uint-op arm end-to-end.
//!
//! The flagship statement is a polynomial identity proved by two
//! *different* DAG shapes — `P(−x)` once by negating the point and once
//! by sign-flipping the odd coefficients into subtractions — closed by
//! the `is` predicate, which only works because canonical interning
//! lands equal values on one ptr. Around it: node dedup / `out_mult`
//! accounting, the stray-claim policy, and the forgeries the pointered
//! relations must catch (a forged result ptr; a re-encoded op id that
//! passes every local constraint and dies on the Poseidon2 cap bus).

use miden_air::lookup::Challenges;
use miden_core::{
    Felt,
    field::QuadFelt,
    utils::{Matrix, RowMajorMatrix},
};
use miden_precompiles::{K1_BASE_BOUND_PTR, K1_SCALAR_BOUND_PTR, UintDomain};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use super::uint::random_uint_below;
use crate::{
    math::{U256, add_reduce, from_limbs32, mac_reduce},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::{Session, SessionTraces, statements::horner_sign_paths, verify_deferred},
    tests::bus_balance::session_stack_residual,
    transcript::{
        eval::{
            COL_IS_ADD, COL_IS_MUL, COL_IS_SUB, COL_OUT_MULT, COL_PTR, COL_TAG_ARG0,
            NUM_MAIN_COLS as EVAL_NUM_MAIN_COLS, TranscriptEvalAir,
        },
        nodes::UintOpId,
    },
};

/// VM-owned fixed domains used by these DAG tests.
const FP: u32 = K1_BASE_BOUND_PTR;
const FQ: u32 = K1_SCALAR_BOUND_PTR;

fn domain_bound(domain: UintDomain) -> U256 {
    from_limbs32(&domain.minus_one())
}

fn fp_bound() -> U256 {
    domain_bound(UintDomain::K1Base)
}

fn fq_bound() -> U256 {
    domain_bound(UintDomain::K1Scalar)
}

fn random_challenges(rng: &mut impl Rng) -> [QuadFelt; 2] {
    core::array::from_fn(|_| {
        QuadFelt::new([Felt::new(rng.random()).unwrap(), Felt::new(rng.random()).unwrap()])
    })
}

fn assert_balanced(traces: &SessionTraces, rng: &mut impl Rng) {
    let [alpha, beta] = random_challenges(rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mains = traces.mains();
    let residual = session_stack_residual(&mains, &[], &challenges);
    assert!(
        residual.is_empty(),
        "uint-DAG stack imbalance: {} unmatched denom(s); e.g. net {:?} on {}",
        residual.len(),
        residual.first().map(|(m, _)| *m),
        residual.first().map(|(_, s)| s.as_str()).unwrap_or(""),
    );
}

/// First eval row with the given op flag set; panics if none.
fn find_op_row(eval: &RowMajorMatrix<Felt>, flag_col: usize) -> usize {
    (0..eval.height())
        .find(|r| eval.values[r * EVAL_NUM_MAIN_COLS + flag_col] == Felt::ONE)
        .expect("expected an op row in the eval trace")
}

// THE STATEMENT
// ================================================================================================

/// `P(−x)` two ways under the fixed secp256k1 base field, via the shared
/// [`horner_sign_paths`] construction: path A negates the point and
/// Horners with the original coefficients; path B sign-flips the odd
/// coefficients, absorbing every negation into a subtraction —
/// `((c₂ − c₃x)·x − c₁)·x + c₀` at degree 3. Two disjoint DAG shapes
/// (13 op nodes, all five ops), one value: the closing `uint_is` is
/// provable exactly because results intern canonically — including the
/// *intermediate* cross-path coincidences (`c₂ − c₃x` arises in both),
/// which also exercise distinct nodes consuming identically-shaped
/// relation tuples.
#[test]
fn horner_sign_alternation_full_stack() {
    let mut rng = StdRng::seed_from_u64(0x0da6_4011);
    let bound = fp_bound();
    let x_v = random_uint_below(&mut rng, bound);
    let c_v: [U256; 4] = core::array::from_fn(|_| random_uint_below(&mut rng, bound));

    let mut session = Session::new();
    let (acc_a, acc_b) = horner_sign_paths(&mut session, x_v, &c_v, FP);

    // Equal values, equal ptrs — across paths, down to the shared
    // intermediates (path A's first Horner step *is* path B's `c₂ − c₃x`).
    assert_eq!(acc_a.ptr, acc_b.ptr, "canonical interning must converge");
    assert_ne!(acc_a.hash(), acc_b.hash(), "but the DAG shapes differ");
    let claim = session.uint_is(&acc_a, &acc_b);

    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);

    // 22 eval rows (AND + zero + 6 leaves + 13 value ops + Is) pad to 32; fixed
    // uints live only in the store and verifier boundary correction, not eval rows.
    // The add relation count is unchanged; mul no longer has its own main
    // (shares the store's merged trace at index 7).
    let mains = traces.mains();
    assert_eq!(mains[5].height(), 32, "eval: 22 rows pad to 32");
    assert_eq!(mains[7].height(), 16, "uint-add: 7 two-row blocks pad to 8");

    traces.check();
    assert_balanced(&traces, &mut rng);
}

// DEDUP + SHARING
// ================================================================================================

/// A re-requested op collapses onto one node (keccak-style interning);
/// sharing rides `out_mult`. `w = r + r` then consumes the deduped `r`
/// twice on one row, and the closing `uint_is` lands on a fresh leaf of
/// the expected value — which dedups onto `w`'s ptr.
#[test]
fn op_dedup_collapses_repeated_nodes() {
    let mut rng = StdRng::seed_from_u64(0x0ded_0001);
    let bound = fp_bound();
    let x_v = random_uint_below(&mut rng, bound);
    let y_v = random_uint_below(&mut rng, bound);

    let mut session = Session::new();
    let x = session.uint_leaf(x_v, FP);
    let y = session.uint_leaf(y_v, FP);

    let r1 = session.uint_add(&x, &y);
    let r2 = session.uint_add(&x, &y);
    assert_eq!(r1.id, r2.id, "identical ops must collapse onto one node");

    let w = session.uint_add(&r1, &r2);
    let sum = add_reduce(x_v, y_v, bound);
    let expected = session.uint_leaf(add_reduce(sum, sum, bound), FP);
    assert_eq!(w.ptr, expected.ptr, "the expected leaf dedups onto w");
    let claim = session.uint_is(&w, &expected);

    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);

    // Two recorded add ops (r once, w once), not three.
    let mains = traces.mains();
    assert_eq!(mains[7].height(), 4, "uint-add: exactly two two-row blocks");
    // r's single row carries out_mult 2 (consumed twice by w).
    let eval = mains[5];
    let r_row = (0..eval.height())
        .find(|row| {
            eval.values[row * EVAL_NUM_MAIN_COLS + COL_IS_ADD] == Felt::ONE
                && eval.values[row * EVAL_NUM_MAIN_COLS + COL_PTR] == Felt::from(r1.ptr.addr())
        })
        .expect("r's op row");
    assert_eq!(
        eval.values[r_row * EVAL_NUM_MAIN_COLS + COL_OUT_MULT],
        Felt::from(2u32),
        "the deduped node is provided at its consumer count",
    );

    traces.check();
    assert_balanced(&traces, &mut rng);
}

// POLICY
// ================================================================================================

/// A value node no op ever consumed is a dead DAG branch — `finish`
/// rejects it as a stray claim.
#[test]
#[should_panic(expected = "stray uint value node")]
fn stray_value_node_panics_at_finish() {
    let mut rng = StdRng::seed_from_u64(0x057a_0001);
    let bound = fp_bound();
    let v = random_uint_below(&mut rng, bound);

    let mut session = Session::new();
    let _dangling = session.uint_leaf(v, FP);
    let root = session.assert_and_fold(core::iter::empty());
    let _ = session.finish(root);
}

/// `uint_is` over unequal values is an unprovable claim — the honest
/// prover refuses up front (canonically interned unequal values cannot
/// share a ptr).
#[test]
#[should_panic(expected = "unprovable")]
fn unequal_is_panics() {
    let mut rng = StdRng::seed_from_u64(0x057a_0002);
    let bound = fp_bound();
    let v = random_uint_below(&mut rng, bound);
    let w = v ^ U256::ONE;

    let mut session = Session::new();
    let a = session.uint_leaf(v, FP);
    let b = session.uint_leaf(w, FP);
    let _ = session.uint_is(&a, &b);
}

/// Operands under different moduli never meet in one op.
#[test]
#[should_panic(expected = "share a modulus")]
fn cross_modulus_op_panics() {
    let mut rng = StdRng::seed_from_u64(0x057a_0003);
    let bound_p = fp_bound();
    let bound_q = fq_bound();

    let mut session = Session::new();
    let a = session.uint_leaf(random_uint_below(&mut rng, bound_p), FP);
    let b = session.uint_leaf(random_uint_below(&mut rng, bound_q), FQ);
    let _ = session.uint_add(&a, &b);
}

/// A leaf value outside `[0, p)` is not internable.
#[test]
#[should_panic(expected = "exceeds its modulus bound")]
fn out_of_range_leaf_panics() {
    let bound = fp_bound();
    let v = bound + U256::ONE;

    let mut session = Session::new();
    let _ = session.uint_leaf(v, FP);
}

// FORGERIES
// ================================================================================================

/// A small honest stack with one mul node closed by `uint_is`, for the
/// tamper tests to corrupt.
fn mul_statement(rng: &mut impl Rng) -> SessionTraces {
    let bound = fp_bound();
    let x_v = random_uint_below(rng, bound);
    let y_v = random_uint_below(rng, bound);

    let mut session = Session::new();
    let x = session.uint_leaf(x_v, FP);
    let y = session.uint_leaf(y_v, FP);
    let r = session.uint_mul(&x, &y);
    let expected = session.uint_leaf(mac_reduce(1, x_v, y_v, 0, U256::ZERO, bound), FP);
    let claim = session.uint_is(&r, &expected);
    let root = session.assert_and_fold([claim]);
    session.finish(root)
}

/// Forging the result ptr on an op row: every local constraint still
/// holds (`ptr` is bus-pinned, not constraint-pinned), but both the
/// `UintMul` consume and the node's `Uint` provide now name a tuple
/// nothing provides / consumes — the bus catches it twice over.
#[test]
fn forged_result_ptr_unbalances() {
    let mut rng = StdRng::seed_from_u64(0xf043_0001);
    let traces = mul_statement(&mut rng);

    let mut tampered = traces.mains()[5].clone();
    let row = find_op_row(&tampered, COL_IS_MUL);
    tampered.values[row * EVAL_NUM_MAIN_COLS + COL_PTR] += Felt::ONE;

    let mut mains = traces.mains();
    mains[5] = &tampered;
    let [alpha, beta] = random_challenges(&mut rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let residual = session_stack_residual(&mains, &[], &challenges);
    assert!(!residual.is_empty(), "a forged r_ptr must unbalance the bus");
}

/// Re-encoding an op's discriminant — flag *and* `tag_arg0` swapped
/// consistently from `Add` to `Sub` — passes every local constraint
/// (the one-hot, the cap materialization, the ptr pins). What rejects it
/// is the bus: the row's cap message no longer matches the Poseidon2
/// perm that produced its hash, and the `UintAdd` consume re-wires to a
/// tuple no chiplet proved. The op id lives in the *hash*, not in local
/// algebra.
#[test]
fn reencoded_op_id_passes_constraints_but_unbalances() {
    let mut rng = StdRng::seed_from_u64(0xf043_0002);
    let bound = fp_bound();
    let x_v = random_uint_below(&mut rng, bound);
    let y_v = random_uint_below(&mut rng, bound);

    let mut session = Session::new();
    let x = session.uint_leaf(x_v, FP);
    let y = session.uint_leaf(y_v, FP);
    let r = session.uint_add(&x, &y);
    let expected = session.uint_leaf(add_reduce(x_v, y_v, bound), FP);
    let claim = session.uint_is(&r, &expected);
    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);

    let mut tampered = traces.mains()[5].clone();
    let row = find_op_row(&tampered, COL_IS_ADD);
    tampered.values[row * EVAL_NUM_MAIN_COLS + COL_IS_ADD] = Felt::ZERO;
    tampered.values[row * EVAL_NUM_MAIN_COLS + COL_IS_SUB] = Felt::ONE;
    tampered.values[row * EVAL_NUM_MAIN_COLS + COL_TAG_ARG0] = Felt::from(UintOpId::Sub as u8);

    // Locally indistinguishable from an honest Sub row… (the eval chip's
    // local check needs the honest transcript root it pins in row 0).
    crate::tests::check_local_inputs(TranscriptEvalAir, &tampered, traces.air_inputs());

    // …but the bus refuses the re-encoded cap + re-wired relation.
    let mut mains = traces.mains();
    mains[5] = &tampered;
    let [alpha, beta] = random_challenges(&mut rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let residual = session_stack_residual(&mains, &[], &challenges);
    assert!(!residual.is_empty(), "a re-encoded op id must unbalance");
}

// BUDGET
// ================================================================================================

/// The uint-op arm must not push the eval chip past `lqd = 1` — flattened
/// via `frac_col!`, every closing constraint stays at degree ≤ 3.
#[test]
fn eval_chip_stays_at_lqd_1() {
    assert_eq!(crate::tests::log_quotient_degree(&TranscriptEvalAir), 1);
}

/// The Horner statement proved and verified for real — `#[ignore]`d
/// (slow in debug); run explicitly or in release alongside the bench.
#[test]
#[ignore = "full prove/verify round-trip; run explicitly"]
fn horner_sign_alternation_proves() {
    let mut rng = StdRng::seed_from_u64(0x0da6_4012);
    let bound = fp_bound();
    let x_v = random_uint_below(&mut rng, bound);
    let c_v: [U256; 4] = core::array::from_fn(|_| random_uint_below(&mut rng, bound));

    let mut session = Session::new();
    let (acc_a, acc_b) = horner_sign_paths(&mut session, x_v, &c_v, FP);
    let claim = session.uint_is(&acc_a, &acc_b);

    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);
    verify_deferred(&traces.prove()).expect("the uint-DAG stack must verify");
}
