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

use std::collections::HashMap;

use miden_air::lookup::{
    Challenges, LookupAir,
    debug::{check_trace_balance, trace::DebugTraceBuilder},
};
use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::LiftedAir;
use miden_precompiles::{K1_BASE_BOUND_PTR, R1_BASE_BOUND_PTR, UintDomain, curve_coefficients};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{Rng, SeedableRng, rngs::StdRng};

use super::uint::random_uint_below;
use crate::{
    hash::{
        chunk::ChunkAir,
        keccak::{node::KeccakNodeAir, round::KeccakRoundAir, sponge::KeccakSpongeAir},
    },
    logup::LookupMessage,
    math::{U256, add_reduce, from_limbs32, mac_reduce},
    primitives::{bitwise64::Bitwise64Air, byte_pair_lut::BytePairLutAir},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::{NUM_CHIPLETS, Session, SessionTraces, statements::horner_sign_paths},
    transcript::{
        eval::{
            COL_IS_ADD, COL_IS_MUL, COL_IS_SUB, COL_OUT_MULT, COL_PARAM_A, COL_PTR,
            NUM_MAIN_COLS as EVAL_NUM_MAIN_COLS, TranscriptEvalAir,
        },
        nodes::UintOpId,
        poseidon2::Poseidon2Air,
    },
    uint::{UintStoreAir, UintValMsg, add::UintAddAir, mul::UintMulAir},
};

/// VM-owned fixed domains used by these DAG tests.
const FP: u32 = K1_BASE_BOUND_PTR;
const FQ: u32 = R1_BASE_BOUND_PTR;

fn domain_bound(domain: UintDomain) -> U256 {
    from_limbs32(&domain.minus_one())
}

fn fp_bound() -> U256 {
    domain_bound(UintDomain::K1Base)
}

fn fq_bound() -> U256 {
    domain_bound(UintDomain::R1Base)
}

fn random_challenges(rng: &mut impl Rng) -> [QuadFelt; 2] {
    core::array::from_fn(|_| {
        QuadFelt::new([Felt::new(rng.random()).unwrap(), Felt::new(rng.random()).unwrap()])
    })
}

/// Fold one chiplet's per-denom balance into the cross-chiplet
/// accumulator. `net[denom] = (multiplicity summed across chiplets, a
/// sample message repr for the failure diagnostic)`. Local copy of the
/// `integration.rs` helper, on the 0.26 signature: bus balance ignores
/// public values, so the `pv` slot is `&[]` (the σ/n `inv_n` input is
/// gone) and the `A` bound resolves to `miden_lifted_air::LiftedAir`.
fn fold_balance<A>(
    air: &A,
    main: &RowMajorMatrix<Felt>,
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, (Felt, String)>,
) where
    A: LiftedAir<Felt, QuadFelt>,
    for<'a> A: LookupAir<DebugTraceBuilder<'a>>,
{
    let periodic = air.periodic_columns();
    let combined = crate::tests::combined_lookup_main(air, main);
    let lookup_main = combined.as_ref().unwrap_or(main);
    let report = check_trace_balance(air, lookup_main, &periodic, &[], &[], challenges);
    for u in report.unmatched {
        let entry = net.entry(u.denom).or_insert((Felt::ZERO, String::new()));
        entry.0 += u.net_multiplicity;
        if entry.1.is_empty()
            && let Some(c) = u.contributions.first()
        {
            entry.1 = c.msg_repr.clone();
        }
    }
}

/// Net the uint-DAG chiplet stack over every bus and return the unbalanced denominators
/// (empty ⟺ the multiset closes). Mirrors the fixed-UintVal boundary consumes injected by
/// `ChipletMultiAir::eval_external`.
fn stack_residual(
    mains: &[&RowMajorMatrix<Felt>; NUM_CHIPLETS],
    challenges: &Challenges<QuadFelt>,
) -> Vec<(Felt, String)> {
    let mut net: HashMap<QuadFelt, (Felt, String)> = HashMap::new();
    fold_balance(&ChunkAir, mains[0], challenges, &mut net);
    fold_balance(&Poseidon2Air, mains[1], challenges, &mut net);
    fold_balance(&KeccakRoundAir, mains[2], challenges, &mut net);
    fold_balance(&Bitwise64Air, mains[3], challenges, &mut net);
    fold_balance(&BytePairLutAir, mains[4], challenges, &mut net);
    fold_balance(&KeccakSpongeAir, mains[5], challenges, &mut net);
    fold_balance(&KeccakNodeAir, mains[6], challenges, &mut net);
    fold_balance(&TranscriptEvalAir, mains[7], challenges, &mut net);
    fold_balance(&UintStoreAir, mains[8], challenges, &mut net);
    fold_balance(&UintAddAir, mains[9], challenges, &mut net);
    fold_balance(&UintMulAir, mains[10], challenges, &mut net);
    fold_fixed_uint_external_balance(challenges, &mut net);
    net.into_values().filter(|(m, _)| *m != Felt::ZERO).collect()
}

fn fold_fixed_uint_external_balance(
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, (Felt, String)>,
) {
    for domain in UintDomain::ALL {
        fold_fixed_uint_external(
            challenges,
            net,
            domain.bound_ptr(),
            domain.bound_ptr(),
            domain.minus_one(),
        );
    }
    for coefficient in curve_coefficients() {
        fold_fixed_uint_external(
            challenges,
            net,
            coefficient.ptr,
            coefficient.bound_ptr,
            coefficient.value,
        );
    }
}

fn fold_fixed_uint_external(
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, (Felt, String)>,
    ptr: u32,
    bound_ptr: u32,
    value: [u32; 8],
) {
    for offset in 0..2 {
        let start = offset * 4;
        let msg = UintValMsg {
            ptr: Felt::from(ptr),
            bound_ptr: Felt::from(bound_ptr),
            offset: Felt::from(offset as u32),
            limbs: core::array::from_fn(|i| Felt::from(value[start + i])),
        };
        let entry = net.entry(msg.encode(challenges)).or_insert((Felt::ZERO, String::new()));
        entry.0 += Felt::ONE;
        if entry.1.is_empty() {
            entry.1 =
                format!("fixed UintVal external ptr={ptr} bound_ptr={bound_ptr} offset={offset}");
        }
    }
}

fn assert_balanced(traces: &SessionTraces, rng: &mut impl Rng) {
    let [alpha, beta] = random_challenges(rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let residual = stack_residual(&traces.mains(), &challenges);
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
    // The add/mul relation counts are unchanged, and the store's dynamic rows plus
    // the 13 fixed rows still pad to 32 blocks.
    let mains = traces.mains();
    assert_eq!(mains[7].height(), 32, "eval: 22 rows pad to 32");
    assert_eq!(mains[9].height(), 128, "uint-add: 7 blocks pad to 8");
    assert_eq!(mains[10].height(), 128, "uint-mul: 6 blocks pad to 8");
    assert_eq!(mains[8].height(), 256, "store: 28 blocks pad to 32");

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
    assert_eq!(mains[9].height(), 32, "uint-add: exactly two blocks");
    // r's single row carries out_mult 2 (consumed twice by w).
    let eval = mains[7];
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

    let mut tampered = traces.mains()[7].clone();
    let row = find_op_row(&tampered, COL_IS_MUL);
    tampered.values[row * EVAL_NUM_MAIN_COLS + COL_PTR] += Felt::ONE;

    let mut mains = traces.mains();
    mains[7] = &tampered;
    let [alpha, beta] = random_challenges(&mut rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let residual = stack_residual(&mains, &challenges);
    assert!(!residual.is_empty(), "a forged r_ptr must unbalance the bus");
}

/// Re-encoding an op's discriminant — flag *and* `param_a` swapped
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

    let mut tampered = traces.mains()[7].clone();
    let row = find_op_row(&tampered, COL_IS_ADD);
    tampered.values[row * EVAL_NUM_MAIN_COLS + COL_IS_ADD] = Felt::ZERO;
    tampered.values[row * EVAL_NUM_MAIN_COLS + COL_IS_SUB] = Felt::ONE;
    tampered.values[row * EVAL_NUM_MAIN_COLS + COL_PARAM_A] = Felt::from(UintOpId::Sub as u8);

    // Locally indistinguishable from an honest Sub row… (the eval chip's
    // local check needs the honest transcript root it pins in row 0).
    crate::tests::check_local_inputs(TranscriptEvalAir, &tampered, traces.air_inputs());

    // …but the bus refuses the re-encoded cap + re-wired relation.
    let mut mains = traces.mains();
    mains[7] = &tampered;
    let [alpha, beta] = random_challenges(&mut rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let residual = stack_residual(&mains, &challenges);
    assert!(!residual.is_empty(), "a re-encoded op id must unbalance");
}

// BUDGET
// ================================================================================================

/// The uint-op arm must not push the eval chip past `lqd = 2` — the
/// whole point of splitting the op fractions across two extra aux
/// columns instead of packing them into cols 0–2.
#[test]
fn eval_chip_stays_at_lqd_2() {
    assert_eq!(crate::tests::log_quotient_degree(&TranscriptEvalAir), 2);
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
    traces.prove().verify().expect("the uint-DAG stack must verify");
}
