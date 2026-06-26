//! UintStore tests — vertical Schwartz–Zippel range-membership (3a), the
//! `UintVal` bus (3b-1), and `Range16` limb checks balanced against the
//! byte-pair LUT (3b-2).

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
    math::{U256, from_limbs16, to_limbs16, to_limbs32},
    primitives::byte_pair_lut::{BytePairLutAir, BytePairLutRequires, generate_trace as bpl_trace},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    uint::{
        NUM_MAIN_COLS, UintStoreAir,
        trace::{UintStoreRequires, generate_trace},
    },
};

fn rand_qf(rng: &mut impl Rng) -> QuadFelt {
    QuadFelt::new([Felt::from(rng.random::<u32>()), Felt::from(rng.random::<u32>())])
}

/// A random modulus (the stored bound `p − 1`): all 16 limbs nonzero, the
/// lo / hi 4×32 halves independently random (no all-ones or Mersenne
/// symmetry that could mask a half-handling bug), with the top limb in
/// `[0x100, 0x7FFF]` so the bound sits below 2²⁵⁵ and a uniformly random
/// 256-bit uint reasonably often exceeds it.
pub(crate) fn random_modulus(rng: &mut impl Rng) -> U256 {
    let mut m: [u16; 16] = core::array::from_fn(|_| rng.random::<u16>().max(1));
    m[15] = (rng.random::<u16>() & 0x7fff).max(0x100);
    from_limbs16(&m)
}

/// A uniformly random uint strictly below `bound` (so it stores in range):
/// the top limb is reduced below the bound's, the lower limbs are free — so
/// `comp = bound − v` borrows across varied limbs and the carries spread.
pub(crate) fn random_uint_below(rng: &mut impl Rng, bound: U256) -> U256 {
    let mut v: [u16; 16] = core::array::from_fn(|_| rng.random::<u16>());
    v[15] = rng.random::<u16>() % to_limbs16(bound)[15];
    from_limbs16(&v)
}

/// Carries c₀..c₆ of the 8×32-bit addition `v32 + comp32` (the trace's
/// stored carries; the top carry c₇ has no slot — which is the whole point).
fn carries32(v32: &[u32; 8], comp32: &[u32; 8]) -> [u16; 7] {
    let mut c = [0u16; 7];
    let mut carry: u64 = 0;
    for j in 0..7 {
        let s = v32[j] as u64 + comp32[j] as u64 + carry;
        carry = s >> 32;
        c[j] = carry as u16;
    }
    c
}

/// A store with a random modulus at ptr 1 (self-referential) and values
/// referencing it — the extremes `v = p−1` (the modulus itself, comp = 0)
/// and `v = 0`, plus a random in-range value (whose block carries).
fn sample_store(rng: &mut impl Rng) -> UintStoreRequires {
    let bound = random_modulus(rng);
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound); // modulus (self-ref)
    store.intern_pinned(2, random_uint_below(rng, bound), fp); // random in-range value
    store.intern_pinned(3, U256::ZERO, fp); // the v = 0 extreme
    store
}

/// Accumulate one chiplet's net per-denom LogUp multiplicity (a balanced
/// system leaves zero residual). Mirrors the cross-chiplet guard in
/// `tests::integration`.
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

#[test]
fn uint_store_constraints_hold() {
    let mut rng = StdRng::seed_from_u64(0xace1);
    let store = sample_store(&mut rng);
    let main = generate_trace(store, &mut BytePairLutRequires::new());
    assert_eq!(main.height(), 32, "3 uints + 1 padding block × 8 rows");

    // The random value at ptr 2 borrows across limbs in `comp = bound − v`,
    // so its block carries — confirm we exercise the carry booleanity + SZ
    // carry term, not a degenerate no-carry bound. Block index 1 = rows
    // 8–15; the carries live in the bound rows' spare cells: γ₀..γ₃ in
    // bound-lo (offset 5) cells 4–7, γ₄..γ₆ in bound-hi (offset 6) cells
    // 4–6. Some γⱼ must be nonzero.
    let carried = (4..8).any(|j| main.values[(8 + 5) * NUM_MAIN_COLS + j] != Felt::ZERO)
        || (4..7).any(|j| main.values[(8 + 6) * NUM_MAIN_COLS + j] != Felt::ZERO);
    assert!(carried, "random value block must carry (comp = bound − v borrowed)",);

    crate::tests::check_local(UintStoreAir, &main);
}

#[test]
fn uint_store_buses_balance_against_bpl() {
    let mut rng = StdRng::seed_from_u64(0xba1a);
    let store = sample_store(&mut rng);

    // The byte-pair LUT provides exactly the Range16 demand the store
    // consumes (every v / comp 16-bit limb + ptr gaps) — driven by the
    // store's own trace pass.
    let mut bpl = BytePairLutRequires::new();
    let uint_main = generate_trace(store, &mut bpl);
    let bpl_main = bpl_trace(bpl);

    let [alpha, beta] = [rand_qf(&mut rng), rand_qf(&mut rng)];
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let mut net: HashMap<QuadFelt, Felt> = HashMap::new();
    fold_balance(&UintStoreAir, &uint_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);

    let residual = net.values().filter(|m| **m != Felt::ZERO).count();
    assert_eq!(
        residual, 0,
        "UintVal self-balances within the store; Range16 balances against BPL",
    );
}

#[test]
#[should_panic]
fn uint_store_rejects_tampered_value() {
    let mut rng = StdRng::seed_from_u64(0xbad5eed);
    let bound = random_modulus(&mut rng);
    let mut store = UintStoreRequires::new();
    store.pin_modulus(1, bound); // modulus (self-ref)
    let mut main = generate_trace(store, &mut BytePairLutRequires::new());
    // Tamper a v limb of the modulus block (row 0, col 0): v + comp ≠ bound
    // ⇒ SZ `id ≠ 0`.
    main.values[0] = main.values[0] + Felt::from(1u32);

    crate::tests::check_local(UintStoreAir, &main);
}

#[test]
#[should_panic]
fn uint_store_rejects_out_of_range_value() {
    // A prover tries to pass an out-of-range uint (v > bound) by forging a
    // wrapped comp = (bound − v) mod 2²⁵⁶, so the stored limbs of v + comp
    // equal bound. The 256-bit addition then overflows (top carry c₇ = 1),
    // but the trace has no c₇ slot (only c₀..c₆) — so the SZ leaves a
    // 2³²·β⁷ residual, id ≠ 0 at the term row, and check_constraints rejects.
    let mut rng = StdRng::seed_from_u64(0xb00d_0035);
    let bound = random_modulus(&mut rng);
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound); // modulus (self-ref)
    store.intern_pinned(2, random_uint_below(&mut rng, bound), fp); // in-range placeholder
    let mut main = generate_trace(store, &mut BytePairLutRequires::new());

    // Out-of-range value: top limb above the bound's (bit 15 set ⇒ v > bound,
    // as the bound's top limb is < 2¹⁵). Forge its wrapped comp = (bound − v)
    // mod 2²⁵⁶ + carries.
    let mut v = to_limbs16(random_uint_below(&mut rng, bound));
    v[15] = to_limbs16(bound)[15] | 0x8000;
    let v256 = from_limbs16(&v);
    let comp256 = bound.wrapping_sub(v256);
    let comp = to_limbs16(comp256);
    let c = carries32(&to_limbs32(v256), &to_limbs32(comp256));

    // Patch uint@2's block (rows 8–15): v_lo (8), v_hi (10), comp_lo (11),
    // comp_hi (12), and the carries hosted in the bound rows' spare cells
    // (γ₀..γ₃ in row 13 cells 4–7, γ₄..γ₆ in row 14 cells 4–6). The bound
    // halves + hub + per-row metadata stay.
    let base = 8;
    for i in 0..8 {
        main.values[base * NUM_MAIN_COLS + i] = Felt::from(v[i]);
        main.values[(base + 2) * NUM_MAIN_COLS + i] = Felt::from(v[8 + i]);
        main.values[(base + 3) * NUM_MAIN_COLS + i] = Felt::from(comp[i]);
        main.values[(base + 4) * NUM_MAIN_COLS + i] = Felt::from(comp[8 + i]);
    }
    for (j, &cj) in c.iter().enumerate() {
        let (row, cell) = if j < 4 { (5, 4 + j) } else { (6, j) };
        main.values[(base + row) * NUM_MAIN_COLS + cell] = Felt::from(cj);
    }

    crate::tests::check_local(UintStoreAir, &main);
}

#[test]
fn uint_store_gaps_and_self_ref_padding() {
    let mut rng = StdRng::seed_from_u64(0x6a9);
    let bound = random_modulus(&mut rng);
    // Modulus at ptr 5 (self-ref; the first block needs no anchor); a value
    // at ptr 9 (gap 3); a self-referential zero uint at ptr 100 (gap 90) —
    // it nets out on its own (provide −1 + consume +1, both `(100, 100, ·)`).
    // Auto-padding appends a fourth zero block at ptr 101 (gap 0).
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(5, bound);
    store.intern_pinned(9, random_uint_below(&mut rng, bound), fp);
    store.pin_modulus(100, U256::ZERO);

    let mut bpl = BytePairLutRequires::new();
    let uint_main = generate_trace(store, &mut bpl);
    let bpl_main = bpl_trace(bpl);

    // Constraints hold, including the gap tie on the real boundaries.
    crate::tests::check_local(UintStoreAir, &uint_main);

    // UintVal self-balances (incl. the self-ref padding); Range16 limbs +
    // ptr-gaps balance against BPL.
    let [alpha, beta] = [rand_qf(&mut rng), rand_qf(&mut rng)];
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mut net: HashMap<QuadFelt, Felt> = HashMap::new();
    fold_balance(&UintStoreAir, &uint_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);
    let residual = net.values().filter(|m| **m != Felt::ZERO).count();
    assert_eq!(residual, 0, "non-trivial gaps + self-ref padding still balance");
}

#[test]
fn uint_store_empty_pads_to_one_block() {
    // No interned uints: generate_trace lays a single self-referential zero
    // padding block (ptr 1), so an idle store still has a valid
    // power-of-two trace whose buses net out (provide mult 1 = its own
    // bound consume; Range16 zeros against BPL).
    let mut rng = StdRng::seed_from_u64(0xe39);
    let store = UintStoreRequires::new();
    let mut bpl = BytePairLutRequires::new();
    let main = generate_trace(store, &mut bpl);
    assert_eq!(main.height(), 8, "one padding block");

    crate::tests::check_local(UintStoreAir, &main);

    let bpl_main = bpl_trace(bpl);
    let [alpha, beta] = [rand_qf(&mut rng), rand_qf(&mut rng)];
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let mut net: HashMap<QuadFelt, Felt> = HashMap::new();
    fold_balance(&UintStoreAir, &main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);
    let residual = net.values().filter(|m| **m != Felt::ZERO).count();
    assert_eq!(residual, 0, "an empty store still closes its buses");
}
