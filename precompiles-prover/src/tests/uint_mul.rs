//! UintMul tests — the scaled-MAC vertical Schwartz–Zippel (constraints
//! + the 17-limb quotient), the liquid-layout witness placement, the
//! `UintLimbs`/`UintVal`/`Range16` buses balanced against the store and
//! the byte-pair LUT, and the act-gated padding.

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
    math::{U256, from_limbs16, mac_reduce, to_limbs16},
    primitives::byte_pair_lut::{BytePairLutAir, BytePairLutRequires, generate_trace as bpl_trace},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    tests::uint::{random_modulus, random_uint_below},
    uint::{
        UintStoreAir,
        mul::{
            NUM_MAIN_COLS, PERIOD, ROW_Q_HI, ROW_R, UintMulAir,
            trace::{UintMulRequires, canonical_q, gamma_halves, generate_trace, op_block},
        },
        trace::{UintPtr, UintStoreRequires, generate_trace as store_trace},
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

/// A store with a random modulus pinned at ptr 1 (self-ref) and the
/// given operand values at ptrs 2.. — the shared fixture base. Returns
/// the store plus the modulus + operand handles.
fn store_with(bound: U256, operands: &[U256]) -> (UintStoreRequires, UintPtr, Vec<UintPtr>) {
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound);
    let ptrs = operands
        .iter()
        .enumerate()
        .map(|(i, v)| store.intern_pinned(2 + i as u32, *v, fp))
        .collect();
    (store, fp, ptrs)
}

/// Record `κₐ·a·b + κ_c·c ≡ r (mod p)` with `a@2, b@3, c@4` against the
/// modulus at 1, interning `r` canonically. Returns `r`'s handle.
#[allow(clippy::too_many_arguments)]
fn record_mac(
    store: &mut UintStoreRequires,
    fp: UintPtr,
    ptrs: &[UintPtr],
    mul: &mut UintMulRequires,
    kappa_a: u16,
    a: U256,
    kappa_c: u16,
    c: U256,
    b: U256,
    bound: U256,
) -> UintPtr {
    let r = mac_reduce(kappa_a, a, b, kappa_c, c, bound);
    let r_ptr = store.intern(r, fp);
    mul.record(kappa_a, ptrs[0], ptrs[1], kappa_c, ptrs[2], r_ptr, fp, 0);
    r_ptr
}

/// Lay the mul + store + BPL traces (the mul pass routes its store
/// demand and Range16 checks), then constraint-check + full
/// three-chiplet balance for the recorded fixture. Returns the mul
/// main for shape asserts — the one laying, since a second
/// `generate_trace` would double-route the demand.
fn check_and_balance(
    mut store: UintStoreRequires,
    mul: UintMulRequires,
    rng: &mut impl Rng,
) -> RowMajorMatrix<Felt> {
    let mut bpl = BytePairLutRequires::new();
    let mul_main = generate_trace(mul, &mut store, &mut bpl);
    let store_main = store_trace(store, &mut bpl);
    let bpl_main = bpl_trace(bpl);

    crate::tests::check_local(UintMulAir, &mul_main);

    let [alpha, beta] = [rand_qf(rng), rand_qf(rng)];
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mut net: HashMap<QuadFelt, Felt> = HashMap::new();
    fold_balance(&UintMulAir, &mul_main, &challenges, &mut net);
    fold_balance(&UintStoreAir, &store_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);
    let residual = net.values().filter(|m| **m != Felt::ZERO).count();
    assert_eq!(
        residual, 0,
        "UintLimbs/UintVal balance mul↔store; Range16 ↔ BPL; UintMul dormant",
    );
    mul_main
}

#[test]
fn mac_reduce_small_values() {
    // Hand-checked: p = 97, 3·(5·7) + 2·3 = 111 ≡ 14 (mod 97).
    let r = mac_reduce(3, U256::from(5u8), U256::from(7u8), 2, U256::from(3u8), U256::from(96u8));
    assert_eq!(r, U256::from(14u8));
}

#[test]
fn mul_constraints_hold() {
    let mut rng = StdRng::seed_from_u64(0x301);
    let bound = random_modulus(&mut rng);
    let a = random_uint_below(&mut rng, bound);
    let b = random_uint_below(&mut rng, bound);
    let c = random_uint_below(&mut rng, bound);

    let (mut store, fp, ptrs) = store_with(bound, &[a, b, c]);
    let mut mul = UintMulRequires::new();
    record_mac(&mut store, fp, &ptrs, &mut mul, 1, a, 1, c, b, bound);

    let (op, _) = mul.ops[0];
    let main = generate_trace(mul, &mut store, &mut BytePairLutRequires::new());
    assert_eq!(main.height(), PERIOD, "one op = one period-16 block");

    // The carries must be exercised: some γ cell pair differs from the
    // zero encoding (lo, hi) = (0, 2¹⁵).
    let vals = op.resolve(&store);
    let gammas = crate::uint::mul::trace::gamma_halves(&op, &vals, &canonical_q(&op, &vals));
    assert!(
        gammas.iter().any(|&(lo, hi)| (lo, hi) != (0, 1 << 15)),
        "a random MAC must carry",
    );

    crate::tests::check_local(UintMulAir, &main);
}

#[test]
fn mul_scaled_17_limb_quotient() {
    // κₐ = 3 against a near-2²⁵⁵ modulus with a = b = p − 1 pushes the
    // quotient past 2²⁵⁶: the 17th limb (q_hi cell 6) must be live, and
    // constraints + buses must still close (the ECC `3x²` shape).
    let mut rng = StdRng::seed_from_u64(0x3_5ca1e);
    let mut bound16 = to_limbs16(random_modulus(&mut rng));
    bound16[15] = 0x7fff;
    let bound = from_limbs16(&bound16);
    let c = random_uint_below(&mut rng, bound);

    // a = b = bound is the modulus row itself (@1) — canonical interning
    // keeps one row per value, so the convolution operands ride it.
    let (mut store, fp, ptrs) = store_with(bound, &[c]);
    let mut mul = UintMulRequires::new();
    let r = mac_reduce(3, bound, bound, 2, c, bound);
    let r_ptr = store.intern(r, fp);
    mul.record(3, fp, fp, 2, ptrs[0], r_ptr, fp, 0);

    let main = check_and_balance(store, mul, &mut rng);
    let q16 = main.values[ROW_Q_HI * NUM_MAIN_COLS + 6];
    assert_ne!(q16, Felt::ZERO, "κₐ = 3 at full size must spill into q₁₆");
}

#[test]
fn mul_ops_balance_with_padding() {
    // Three ops (two scaled, one squaring a@2 by itself) pad to four
    // blocks; the all-zero act = 0 padding block must stay off every bus.
    let mut rng = StdRng::seed_from_u64(0x3_9ad5);
    let bound = random_modulus(&mut rng);
    let a = random_uint_below(&mut rng, bound);
    let b = random_uint_below(&mut rng, bound);
    let c = random_uint_below(&mut rng, bound);

    let (mut store, fp, ptrs) = store_with(bound, &[a, b, c]);
    let mut mul = UintMulRequires::new();
    record_mac(&mut store, fp, &ptrs, &mut mul, 1, a, 1, c, b, bound);
    record_mac(&mut store, fp, &ptrs, &mut mul, 3, a, 0, c, b, bound);
    // Squaring is just mul(x, x): both convolution operands at ptr 2.
    let r = mac_reduce(1, a, a, 1, c, bound);
    let r_ptr = store.intern(r, fp);
    mul.record(1, ptrs[0], ptrs[0], 1, ptrs[2], r_ptr, fp, 0);

    let mul_main = check_and_balance(store, mul, &mut rng);
    assert_eq!(mul_main.height(), 64, "3 ops pad to 4 blocks");
}

#[test]
fn mul_div_arrangement() {
    // z = x ÷ y is provable as y·z + 0·c ≡ x: κ_c = 0 kills the addend,
    // so c_ptr can dummy onto the modulus — no zero uint needed.
    let mut rng = StdRng::seed_from_u64(0xd1f);
    let bound = random_modulus(&mut rng);
    let y = random_uint_below(&mut rng, bound);
    let z = random_uint_below(&mut rng, bound);
    let x = mac_reduce(1, y, z, 0, bound, bound);

    let (mut store, fp, ptrs) = store_with(bound, &[y, z]);
    let x_ptr = store.intern(x, fp);
    let mut mul = UintMulRequires::new();
    // (a, b, c, r) = (y@2, z@3, modulus@1 with κ_c = 0, x).
    mul.record(1, ptrs[0], ptrs[1], 0, fp, x_ptr, fp, 0);

    check_and_balance(store, mul, &mut rng);
}

#[test]
fn mul_zero_operand() {
    // a = 0 degenerates the product: S = 0 through the b-rows, q = 0,
    // r = c. The zero-heavy block must still satisfy constraints and
    // balance (the layout-by-structure regression shape).
    let mut rng = StdRng::seed_from_u64(0x0_face);
    let bound = random_modulus(&mut rng);
    let zero = U256::ZERO;
    let b = random_uint_below(&mut rng, bound);
    let c = random_uint_below(&mut rng, bound);

    let (mut store, fp, ptrs) = store_with(bound, &[zero, b, c]);
    let mut mul = UintMulRequires::new();
    let r_ptr = record_mac(&mut store, fp, &ptrs, &mut mul, 1, zero, 1, c, b, bound);
    let r = store.uint(r_ptr).value;
    assert_eq!(r, c, "0·b + c must reduce to c");

    check_and_balance(store, mul, &mut rng);
}

#[test]
#[should_panic]
fn mul_rejects_wrong_result() {
    // Tamper the looked-up r limbs: the SZ id is nonzero at the term row
    // and check_constraints rejects (the bus would also mismatch, but the
    // identity fails first).
    let mut rng = StdRng::seed_from_u64(0xbad_3);
    let bound = random_modulus(&mut rng);
    let a = random_uint_below(&mut rng, bound);
    let b = random_uint_below(&mut rng, bound);
    let c = random_uint_below(&mut rng, bound);

    let (mut store, fp, ptrs) = store_with(bound, &[a, b, c]);
    let mut mul = UintMulRequires::new();
    record_mac(&mut store, fp, &ptrs, &mut mul, 1, a, 1, c, b, bound);
    let mut main = generate_trace(mul, &mut store, &mut BytePairLutRequires::new());
    main.values[ROW_R * NUM_MAIN_COLS] += Felt::from(1u32);

    crate::tests::check_local(UintMulAir, &main);
}

#[test]
fn mul_q_range_checks_are_load_bearing() {
    // Re-encode the same quotient value with a 17-bit limb pair
    // (q'₀ = q₀ + 2¹⁶, q'₁ = q₁ − 1): the synthetic division still
    // closes — q(t) is unchanged, so the SZ identity holds and
    // check_constraints PASSES. Only the Range16 consume of the oversized
    // limb has no provider: the forged block must surface as a bus
    // residual, proving the range checks (not the identity) reject it.
    let mut rng = StdRng::seed_from_u64(0x9_f0e6e);
    let bound = random_modulus(&mut rng);
    let a = random_uint_below(&mut rng, bound);
    let b = random_uint_below(&mut rng, bound);
    let c = random_uint_below(&mut rng, bound);

    let (mut store, fp, ptrs) = store_with(bound, &[a, b, c]);
    let mut mul = UintMulRequires::new();
    record_mac(&mut store, fp, &ptrs, &mut mul, 1, a, 1, c, b, bound);

    let (op, mult) = mul.ops[0];
    let vals = op.resolve(&store);
    let mut q = canonical_q(&op, &vals);
    assert!(q[1] >= 1, "fixture needs a borrowable q₁ (reseed if not)");
    q[0] += 1 << 16;
    q[1] -= 1;
    let forged = op_block(&op, &vals, &q, &gamma_halves(&op, &vals, &q), mult);

    // The honest pass routes store demand + the canonical-q Range16
    // checks into the buses …
    let mut bpl = BytePairLutRequires::new();
    let mut mul_main = generate_trace(mul, &mut store, &mut bpl);
    // … then the laid block is replaced by the forged encoding.
    mul_main.values[..PERIOD * NUM_MAIN_COLS].copy_from_slice(&forged);

    // The identity still closes: constraints pass on the forged trace.
    crate::tests::check_local(UintMulAir, &mul_main);

    // …but the bus does not: the 17-bit limb's Range16 is unprovidable.
    let store_main = store_trace(store, &mut bpl);
    let bpl_main = bpl_trace(bpl);

    let [alpha, beta] = [rand_qf(&mut rng), rand_qf(&mut rng)];
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mut net: HashMap<QuadFelt, Felt> = HashMap::new();
    fold_balance(&UintMulAir, &mul_main, &challenges, &mut net);
    fold_balance(&UintStoreAir, &store_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);
    let residual = net.values().filter(|m| **m != Felt::ZERO).count();
    assert_ne!(
        residual, 0,
        "an oversized q limb must unbalance Range16 — the checks are load-bearing",
    );
}
