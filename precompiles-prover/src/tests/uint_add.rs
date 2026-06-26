//! UintAdd tests — modular addition `a + b ≡ c (mod p)` via vertical
//! Schwartz–Zippel over the [`UintStore`](crate::uint), with the binary
//! carry / borrow chains and the `UintVal` bus balanced against the store.

use std::collections::HashMap;

use miden_air::lookup::{
    Challenges, LookupAir,
    debug::{check_trace_balance, trace::DebugTraceBuilder},
};
use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::LiftedAir;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::{
    math::{U256, add_reduce, sub_reduce},
    primitives::byte_pair_lut::{BytePairLutAir, BytePairLutRequires, generate_trace as bpl_trace},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    tests::uint::{random_modulus, random_uint_below},
    uint::{
        UintStoreAir,
        add::{
            NUM_MAIN_COLS, PERIOD, UintAddAir,
            trace::{UintAddRequires, generate_trace},
        },
        trace::{UintStoreRequires, generate_trace as store_trace},
    },
};

fn rand_qf(rng: &mut impl Rng) -> QuadFelt {
    QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())])
}

/// Accumulate one chiplet's net per-denom LogUp multiplicity. Mirrors
/// `tests::uint::fold_balance`.
fn fold_balance<A>(
    air: &A,
    main: &RowMajorMatrix<Felt>,
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, Felt>,
) where
    A: LiftedAir<Felt, QuadFelt>,
    for<'a> A: LookupAir<DebugTraceBuilder<'a>>,
{
    let periodic = air.periodic_columns();
    let combined = crate::tests::combined_lookup_main(air, main);
    let lookup_main = combined.as_ref().unwrap_or(main);
    let report = check_trace_balance(air, lookup_main, &periodic, &[], &[], challenges);
    for u in report.unmatched {
        *net.entry(u.denom).or_insert(Felt::ZERO) += u.net_multiplicity;
    }
}

/// One add op `a + b ≡ c (mod p)` over a backing store (mod @1, a @2,
/// b @3, the interned sum) under a random asymmetric modulus. Returns
/// `(UintAddRequires, UintStoreRequires, k)`.
fn sample_add(
    rng: &mut impl Rng,
    force_reduction: bool,
) -> (UintAddRequires, UintStoreRequires, u32) {
    let bound = random_modulus(rng); // p − 1
    let (a, b) = if force_reduction {
        // a, b near the top so a + b ≥ p (k = 1): use a = b = bound (= p−1).
        (bound, bound)
    } else {
        (random_uint_below(rng, bound), random_uint_below(rng, bound))
    };
    let c = add_reduce(a, b, bound);
    let k = u32::from(a + b > bound); // bound < 2²⁵⁵, so the sum can't wrap

    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let (a_ptr, b_ptr) = if force_reduction {
        // a = b = bound is the modulus row itself — operand ptrs may
        // coincide.
        (fp, fp)
    } else {
        (store.intern_pinned(2, a, fp), store.intern_pinned(3, b, fp))
    };
    let c_ptr = store.intern(c, fp);
    let mut add = UintAddRequires::new();
    add.record(a_ptr, b_ptr, c_ptr, fp, 0);
    (add, store, k)
}

#[test]
fn add_constraints_hold() {
    let mut rng = StdRng::seed_from_u64(0xadd_1);
    let (add, mut store, k) = sample_add(&mut rng, false);
    let main = generate_trace(add, &mut store);
    assert_eq!(main.height(), PERIOD, "one op = one period-16 block");

    // The carry rows (cpos at 11/12, cneg at 13/14) must carry: a real op
    // exercises γ⁺ / γ⁻, not a degenerate carry-free sum.
    let carries_nonzero = (11..15)
        .flat_map(|r| (0..4).map(move |c| (r, c)))
        .any(|(r, c)| main.values[r * NUM_MAIN_COLS + c] != Felt::ZERO);
    assert!(carries_nonzero, "the add must carry across limbs");
    let _ = k;

    crate::tests::check_local(UintAddAir, &main);
}

#[test]
fn add_with_reduction() {
    // k = 1: a + b ≥ p, so the modulus is subtracted. Exercises the k·bound
    // term + the −k correction in the SZ.
    let mut rng = StdRng::seed_from_u64(0xadd_c0de);
    let (add, mut store, k) = sample_add(&mut rng, true);
    assert_eq!(k, 1, "forced reduction must set k = 1");
    let main = generate_trace(add, &mut store);

    crate::tests::check_local(UintAddAir, &main);
}

#[test]
#[should_panic]
fn add_rejects_wrong_result() {
    // Tamper the witnessed result c: a + b − c − k·p ≠ 0 ⇒ the SZ `id` is
    // nonzero at the term row and check_constraints rejects.
    let mut rng = StdRng::seed_from_u64(0xbad_add);
    let (add, mut store, _k) = sample_add(&mut rng, false);
    let mut main = generate_trace(add, &mut store);
    // c_lo is row 5; bump its low limb.
    main.values[5 * NUM_MAIN_COLS] += Felt::from(1u32);

    crate::tests::check_local(UintAddAir, &main);
}

#[test]
fn add_buses_balance_against_store() {
    let mut rng = StdRng::seed_from_u64(0xba1_add);
    let bound = random_modulus(&mut rng);
    let a = random_uint_below(&mut rng, bound);
    let b = random_uint_below(&mut rng, bound);
    let c = add_reduce(a, b, bound);

    // Store: modulus @1 (self-ref), a @2, b @3, the sum interned. The
    // store pads the block count to a power of two with self-referential
    // zeros itself.
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let a_ptr = store.intern_pinned(2, a, fp);
    let b_ptr = store.intern_pinned(3, b, fp);
    let c_ptr = store.intern(c, fp);

    let mut add = UintAddRequires::new();
    add.record(a_ptr, b_ptr, c_ptr, fp, 0);

    // The add's trace pass routes its UintVal demand into the store, so
    // the store's provide multiplicities cover the operand + modulus
    // consumes; the store's pass drives the Range16 demand into BPL.
    let add_main = generate_trace(add, &mut store);
    let mut bpl = BytePairLutRequires::new();
    let store_main = store_trace(store, &mut bpl);
    let bpl_main = bpl_trace(bpl);

    let [alpha, beta] = [rand_qf(&mut rng), rand_qf(&mut rng)];
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let mut net: HashMap<QuadFelt, Felt> = HashMap::new();
    fold_balance(&UintAddAir, &add_main, &challenges, &mut net);
    fold_balance(&UintStoreAir, &store_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);

    let residual = net.values().filter(|m| **m != Felt::ZERO).count();
    assert_eq!(
        residual, 0,
        "UintVal (operands + modulus) balances add↔store; Range16 ↔ BPL; UintAdd dormant",
    );
}

#[test]
fn duplicate_relations_collapse() {
    // Recording the same arrangement twice lays ONE block, the provide
    // multiplicities accumulating on its term row — the relation-level
    // interning that lets two consumers (e.g. an eval op node and an EC
    // certificate) share a block.
    let mut rng = StdRng::seed_from_u64(0xded0_add);
    let bound = random_modulus(&mut rng);
    let a = random_uint_below(&mut rng, bound);
    let b = random_uint_below(&mut rng, bound);

    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let a_ptr = store.intern_pinned(2, a, fp);
    let b_ptr = store.intern_pinned(3, b, fp);
    let c_ptr = store.intern(add_reduce(a, b, bound), fp);

    let mut add = UintAddRequires::new();
    add.record(a_ptr, b_ptr, c_ptr, fp, 1);
    add.record(a_ptr, b_ptr, c_ptr, fp, 1);

    let main = generate_trace(add, &mut store);
    assert_eq!(main.height(), PERIOD, "duplicates collapse onto one block");
    let term_row = PERIOD - 1;
    assert_eq!(
        main.values[term_row * NUM_MAIN_COLS],
        Felt::from(2u32),
        "the collapsed block provides at the accumulated mult",
    );
}

#[test]
fn sub_as_arrangement() {
    // z = x − y is provable as the add arrangement y + z ≡ x (mod p): feed
    // (a, b, c) = (y, z, x). Constraints hold + buses balance.
    let mut rng = StdRng::seed_from_u64(0x50b);
    let bound = random_modulus(&mut rng);
    let x = random_uint_below(&mut rng, bound);
    let y = random_uint_below(&mut rng, bound);
    let z = sub_reduce(x, y, bound);
    // Sanity: y + z ≡ x (mod p).
    assert_eq!(add_reduce(y, z, bound), x, "y + z ≡ x must hold");

    // Store: modulus @1, y @2, z @3, x @4 — feed (a, b, c) = (y, z, x).
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let y_ptr = store.intern_pinned(2, y, fp);
    let z_ptr = store.intern_pinned(3, z, fp);
    let x_ptr = store.intern_pinned(4, x, fp);
    let mut add = UintAddRequires::new();
    add.record(y_ptr, z_ptr, x_ptr, fp, 0);
    let main = generate_trace(add, &mut store);

    crate::tests::check_local(UintAddAir, &main);
}

#[test]
fn add_pad_blocks_stay_off_the_bus() {
    // Three ops pad to four blocks (height 64). The all-zero padding block
    // has act = 0, so it emits no UintVal consumes — with the zero sentinel
    // gone there is no provider for `(0, 0, off, 0…)` tuples, and an
    // ungated pad block would unbalance the bus. Constraints must also
    // hold across the act = 0 rows.
    let mut rng = StdRng::seed_from_u64(0x9ad_b10c);
    let bound = random_modulus(&mut rng);
    let operands: Vec<U256> = (0..3).map(|_| random_uint_below(&mut rng, bound)).collect();

    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let mut add = UintAddRequires::new();
    // ops: x0+x1, x1+x2, x0+x0 — sums interned canonically.
    let ptrs: Vec<_> = operands
        .iter()
        .enumerate()
        .map(|(i, x)| store.intern_pinned(2 + i as u32, *x, fp))
        .collect();
    let pairs = [(0usize, 1usize), (1, 2), (0, 0)];
    for (l, r) in pairs {
        let c_ptr = store.intern(add_reduce(operands[l], operands[r], bound), fp);
        add.record(ptrs[l], ptrs[r], c_ptr, fp, 0);
    }
    let add_main = generate_trace(add, &mut store);
    assert_eq!(add_main.height(), 64, "3 ops pad to 4 blocks");
    let mut bpl = BytePairLutRequires::new();
    let store_main = store_trace(store, &mut bpl);
    let bpl_main = bpl_trace(bpl);

    crate::tests::check_local(UintAddAir, &add_main);

    let [alpha, beta] = [rand_qf(&mut rng), rand_qf(&mut rng)];
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mut net: HashMap<QuadFelt, Felt> = HashMap::new();
    fold_balance(&UintAddAir, &add_main, &challenges, &mut net);
    fold_balance(&UintStoreAir, &store_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);
    let residual = net.values().filter(|m| **m != Felt::ZERO).count();
    assert_eq!(residual, 0, "the act = 0 pad block contributes nothing");
}

#[test]
#[should_panic]
fn add_inactive_block_cannot_provide() {
    // H1 regression. The provide is gated by `sel[TERM]`, not `act`, and the
    // operand consumes ARE act-gated — so an `act = 0` block with zeroed
    // limbs (the SZ `id` closes on 0 + 0 − 0 = 0) and a witnessed term-row
    // mult would provide a *false* `UintAdd` tuple onto the bus. The
    // `term_sel·(1−act)·mult = 0` constraint must reject a nonzero pad mult.
    let mut rng = StdRng::seed_from_u64(0xac7_f0e);
    let bound = random_modulus(&mut rng);
    let operands: Vec<U256> = (0..3).map(|_| random_uint_below(&mut rng, bound)).collect();
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let mut add = UintAddRequires::new();
    let ptrs: Vec<_> = operands
        .iter()
        .enumerate()
        .map(|(i, x)| store.intern_pinned(2 + i as u32, *x, fp))
        .collect();
    for (l, r) in [(0usize, 1usize), (1, 2), (0, 0)] {
        let c_ptr = store.intern(add_reduce(operands[l], operands[r], bound), fp);
        add.record(ptrs[l], ptrs[r], c_ptr, fp, 0);
    }
    let mut add_main = generate_trace(add, &mut store);
    assert_eq!(add_main.height(), 64, "3 ops pad to 4 blocks");
    // Pad block = block 3 (rows 48..63); its term row is 63, TERM_CELL_MULT = 0.
    add_main.values[63 * NUM_MAIN_COLS] = Felt::from(1u32);
    crate::tests::check_local(UintAddAir, &add_main);
}

#[test]
fn negation_holds_and_balances() {
    // a + (−a) ≡ 0 (mod p) via add_to_zero: c is the unstored zero, so there
    // is no result ptr and no c lookup. Constraints hold and — crucially —
    // the buses balance with *no* zero provider in the store.
    let mut rng = StdRng::seed_from_u64(0x4e6);
    let bound = random_modulus(&mut rng);
    let a = random_uint_below(&mut rng, bound);
    assert_ne!(a, U256::ZERO, "need a ≠ 0");
    let a_neg = sub_reduce(U256::ZERO, a, bound); // p − a ∈ (0, p), the additive inverse

    // Store: modulus @1, a @2, a_neg @3 — no zero result anywhere.
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let a_ptr = store.intern_pinned(2, a, fp);
    let neg_ptr = store.intern_pinned(3, a_neg, fp);
    let mut add = UintAddRequires::new();
    add.record_to_zero(a_ptr, neg_ptr, fp, 0);
    // The trace pass routes the add's UintVal demand: a / a_neg /
    // modulus only (no c), so the buses balance without any stored
    // zero.
    let main = generate_trace(add, &mut store);

    // Constraints: the −c(β) term is dropped, the SZ still closes
    // (a + a_neg = p = k·p with k = 1).
    crate::tests::check_local(UintAddAir, &main);

    let mut bpl = BytePairLutRequires::new();
    let store_main = store_trace(store, &mut bpl);
    let bpl_main = bpl_trace(bpl);

    let [alpha, beta] = [rand_qf(&mut rng), rand_qf(&mut rng)];
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mut net: HashMap<QuadFelt, Felt> = HashMap::new();
    fold_balance(&UintAddAir, &main, &challenges, &mut net);
    fold_balance(&UintStoreAir, &store_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);
    let residual = net.values().filter(|m| **m != Felt::ZERO).count();
    assert_eq!(residual, 0, "negation balances with no stored zero result");
}

#[test]
fn equality_certificate_holds_and_balances() {
    // a + 0 ≡ c with a, c the same stored uint (canonical interning lands
    // equal values on one ptr): the is_b_zero block proves value equality
    // with no b lookup and no zero pin. Constraints hold, buses balance.
    let mut rng = StdRng::seed_from_u64(0xe0_0001);
    let bound = random_modulus(&mut rng);
    let a = random_uint_below(&mut rng, bound);

    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let a_ptr = store.intern_pinned(2, a, fp);
    // A second handle to the same value via canonical interning.
    let c_ptr = store.intern(a, fp);
    assert_eq!(a_ptr, c_ptr, "equal values intern onto one ptr");

    let mut add = UintAddRequires::new();
    add.record_eq(a_ptr, c_ptr, fp, 0);
    // The trace pass consumes the add and routes its UintVal demand
    // (the `a` operand + modulus; no `b`, the unstored zero).
    let main = generate_trace(add, &mut store);

    // b rows (2–4) stay zero; the B-hub flags is_b_zero.
    assert_eq!(main.values[3 * NUM_MAIN_COLS], Felt::ONE, "B-hub flag set");
    assert_eq!(main.values[2 * NUM_MAIN_COLS], Felt::ZERO, "b_lo limbs zero");

    crate::tests::check_local(UintAddAir, &main);

    let mut bpl = BytePairLutRequires::new();
    let store_main = store_trace(store, &mut bpl);
    let bpl_main = bpl_trace(bpl);

    let [alpha, beta] = [rand_qf(&mut rng), rand_qf(&mut rng)];
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mut net: HashMap<QuadFelt, Felt> = HashMap::new();
    fold_balance(&UintAddAir, &main, &challenges, &mut net);
    fold_balance(&UintStoreAir, &store_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);
    let residual = net.values().filter(|m| **m != Felt::ZERO).count();
    assert_eq!(residual, 0, "the equality certificate balances with no b");
}

#[test]
#[should_panic]
fn is_b_zero_rejects_unequal_values() {
    // Forge the is_b_zero flag onto an honest a + b = c block (zeroing the
    // b rows so the suppressed consumes don't betray it first): the SZ id
    // now reads a − c − k·p ≠ 0 and the term-row assert rejects.
    let mut rng = StdRng::seed_from_u64(0xe0_bad);
    let (add, mut store, _k) = sample_add(&mut rng, false);
    let mut main = generate_trace(add, &mut store);
    main.values[3 * NUM_MAIN_COLS] = Felt::ONE; // B-hub: is_b_zero := 1
    for row in [2, 4] {
        for c in 0..4 {
            main.values[row * NUM_MAIN_COLS + c] = Felt::ZERO; // b limbs
        }
    }
    for row in 0..16 {
        main.values[row * NUM_MAIN_COLS + 5] = Felt::ZERO; // COL_B_PTR
    }

    crate::tests::check_local(UintAddAir, &main);
}

#[test]
#[should_panic]
fn is_b_zero_rejects_named_operand_ptr() {
    // The tuple sentinel is constraint-tied on the b side too:
    // is_b_zero · b_ptr = 0.
    let mut rng = StdRng::seed_from_u64(0xe0_5e47);
    let bound = random_modulus(&mut rng);
    let a = random_uint_below(&mut rng, bound);

    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let a_ptr = store.intern_pinned(2, a, fp);
    let mut add = UintAddRequires::new();
    add.record_eq(a_ptr, a_ptr, fp, 0);
    let mut main = generate_trace(add, &mut store);
    // Forge a b_ptr into the flagged block (cycle-constant, all 16 rows).
    for r in 0..16 {
        main.values[r * NUM_MAIN_COLS + 5] = Felt::from(3u32); // COL_B_PTR
    }

    crate::tests::check_local(UintAddAir, &main);
}

#[test]
#[should_panic]
fn is_c_zero_rejects_named_result_ptr() {
    // The tuple sentinel is constraint-tied: is_c_zero · c_ptr = 0. A
    // prover claiming a zero result while naming a real c_ptr in the tuple
    // must be rejected.
    let mut rng = StdRng::seed_from_u64(0xc0_5e47);
    let bound = random_modulus(&mut rng);
    let a = random_uint_below(&mut rng, bound);
    let a_neg = sub_reduce(U256::ZERO, a, bound);

    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let a_ptr = store.intern_pinned(2, a, fp);
    let neg_ptr = store.intern_pinned(3, a_neg, fp);
    let mut add = UintAddRequires::new();
    add.record_to_zero(a_ptr, neg_ptr, fp, 0);
    let mut main = generate_trace(add, &mut store);
    // Forge a c_ptr into the flagged block (cycle-constant, all 16 rows).
    for r in 0..16 {
        main.values[r * NUM_MAIN_COLS + 6] = Felt::from(4u32); // COL_C_PTR
    }

    crate::tests::check_local(UintAddAir, &main);
}
