use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::{BaseAir, LiftedAir};

use crate::{
    primitives::{
        bitwise64::{
            A_BYTES_RANGE, AUX_PROVIDE, B_LIMBS_RANGE, Bitwise64Air, Bitwise64Requires,
            COL_IS_LOGIC, COL_IS_ROL, COL_IS_XORROL_CAP, COL_OP_OR_K, LANE_WIDTH, Logic64Op,
            NUM_AUX_COLS, NUM_LANES, NUM_MAIN_COLS, generate_trace, lane_base,
        },
        byte_pair_lut::{BytePairLutRequires, BytePairOp},
    },
    utils::split_u64_u32,
};

fn test_alpha_beta() -> [QuadFelt; 2] {
    [QuadFelt::from(Felt::from(7u8)), QuadFelt::from(Felt::from(11u8))]
}

/// Prover-driven aux-trace build, used as the test entry point for
/// every aux-shape check.
fn build_aux(
    requires: Bitwise64Requires,
) -> (RowMajorMatrix<Felt>, RowMajorMatrix<QuadFelt>, QuadFelt) {
    let main = generate_trace(requires);
    let flat = test_alpha_beta();
    let (aux, aux_values) = Bitwise64Air.build_aux_trace(&main, &[], &[], &flat);
    assert_eq!(
        aux_values.len(),
        1,
        "Bitwise64 exposes exactly one aux value (single σ at col 0)",
    );
    (main, aux, aux_values[0])
}

#[test]
fn op_apply_matches_native() {
    let a = 0xdead_beef_cafe_babeu64;
    let b = 0x0123_4567_89ab_cdefu64;
    assert_eq!(Logic64Op::AndNot.apply(a, b), (!a) & b);
    assert_eq!(Logic64Op::Xor.apply(a, b), a ^ b);
}

#[test]
fn op_tags_match_byte_pair() {
    assert_eq!(Logic64Op::AndNot.tag(), BytePairOp::AndNot.tag());
    assert_eq!(Logic64Op::Xor.tag(), BytePairOp::Xor.tag());
}

#[test]
fn empty_requires_yields_min_height_zero_rows() {
    // 0.26 rejects traces shorter than 2 rows (`TraceHeightTooSmall`), so an
    // empty chip pads to the two-row minimum. All-zero rows are off-bus
    // (act = 0), so the pad contributes nothing to σ.
    let trace = generate_trace(Bitwise64Requires::new());
    assert_eq!(trace.height(), 2);
    assert_eq!(trace.width(), NUM_MAIN_COLS);
    for v in &trace.values {
        assert_eq!(*v, Felt::ZERO);
    }
}

#[test]
fn single_logic_emits_real_then_trailing_carrier() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    let a = 0x1122_3344_5566_7788u64;
    let b = 0xaabb_ccdd_eeff_0011u64;
    let c = requires.require(&mut bpl, Logic64Op::Xor, a, b);
    assert_eq!(c, a ^ b);

    let trace = generate_trace(requires);
    // 1 real + 1 trailing carrier = 2 rows → next pow2 = 2.
    assert_eq!(trace.height(), 2);

    let row0 = &trace.values[0..NUM_MAIN_COLS];
    for (i, byte) in a.to_le_bytes().iter().enumerate() {
        assert_eq!(row0[A_BYTES_RANGE.start + i], Felt::from(*byte));
    }
    for (i, byte) in b.to_le_bytes().iter().enumerate() {
        assert_eq!(row0[B_LIMBS_RANGE.start + i], Felt::from(*byte));
    }
    assert_eq!(row0[COL_OP_OR_K], Felt::from(Logic64Op::Xor.tag()));
    assert_eq!(row0[COL_IS_LOGIC], Felt::from(1u8));
    assert_eq!(row0[COL_IS_ROL], Felt::ZERO);

    let row1 = &trace.values[NUM_MAIN_COLS..2 * NUM_MAIN_COLS];
    for (i, byte) in c.to_le_bytes().iter().enumerate() {
        assert_eq!(row1[A_BYTES_RANGE.start + i], Felt::from(*byte));
    }
    for i in 0..8 {
        assert_eq!(row1[B_LIMBS_RANGE.start + i], Felt::ZERO);
    }
    assert_eq!(row1[COL_OP_OR_K], Felt::ZERO);
    assert_eq!(row1[COL_IS_LOGIC], Felt::ZERO);
    assert_eq!(row1[COL_IS_ROL], Felt::ZERO);
}

#[test]
fn unchained_logics_split_across_lanes() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    // Two LOGIC triples whose c's don't match the next a — no chaining
    // possible. Each is its own 2-row chain (real + trailing carrier); the
    // least-loaded greedy puts one in each lane.
    requires.require(&mut bpl, Logic64Op::Xor, 0xaa, 0xbb);
    requires.require(&mut bpl, Logic64Op::Xor, 0x22, 0x33);

    let trace = generate_trace(requires);
    // Two 2-row chains, one per lane → height 2 (not 4).
    assert_eq!(trace.height(), 2);

    let is_logic =
        |r: usize, lane: usize| trace.values[r * NUM_MAIN_COLS + lane_base(lane) + COL_IS_LOGIC];
    // Lane 0: real then trailing carrier.
    assert_eq!(is_logic(0, 0), Felt::from(1u8), "lane0 row0 real");
    assert_eq!(is_logic(1, 0), Felt::ZERO, "lane0 row1 carrier");
    // Lane 1: real then trailing carrier.
    assert_eq!(is_logic(0, 1), Felt::from(1u8), "lane1 row0 real");
    assert_eq!(is_logic(1, 1), Felt::ZERO, "lane1 row1 carrier");
}

#[test]
fn chained_logics_skip_intermediate_carriers() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    let c1 = requires.require(&mut bpl, Logic64Op::Xor, 0xaa, 0xbb);
    let c2 = requires.require(&mut bpl, Logic64Op::Xor, c1, 0xcc); // chain: a == previous c
    let _c3 = requires.require(&mut bpl, Logic64Op::AndNot, c2, 0xdd); // chain again

    let trace = generate_trace(requires);
    // 3 chained reals + 1 trailing carrier = 4 rows.
    assert_eq!(trace.height(), 4);

    let is_logic = |r: usize| trace.values[r * NUM_MAIN_COLS + COL_IS_LOGIC];
    assert_eq!(is_logic(0), Felt::from(1u8), "row 0 real");
    assert_eq!(is_logic(1), Felt::from(1u8), "row 1 chained real");
    assert_eq!(is_logic(2), Felt::from(1u8), "row 2 chained real");
    assert_eq!(is_logic(3), Felt::ZERO, "row 3 trailing carrier");

    // Row 1's a_bytes equal row 0's c bytes (the chain link).
    let row1_a =
        &trace.values[NUM_MAIN_COLS + A_BYTES_RANGE.start..NUM_MAIN_COLS + A_BYTES_RANGE.end];
    for (i, byte) in c1.to_le_bytes().iter().enumerate() {
        assert_eq!(row1_a[i], Felt::from(*byte));
    }
}

#[test]
fn three_logics_balance_across_lanes() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    requires.require(&mut bpl, Logic64Op::AndNot, 1, 2);
    requires.require(&mut bpl, Logic64Op::Xor, 3, 4);
    requires.require(&mut bpl, Logic64Op::AndNot, 5, 6);
    // Three unchained 2-row chains. Least-loaded greedy: lane 0 takes
    // chains 0 and 2 (4 rows), lane 1 takes chain 1 (2 rows). Height = 4.
    let trace = generate_trace(requires);
    assert_eq!(trace.height(), 4);

    let is_logic =
        |r: usize, lane: usize| trace.values[r * NUM_MAIN_COLS + lane_base(lane) + COL_IS_LOGIC];
    // Lane 0: two chains back to back (real, carrier, real, carrier).
    assert_eq!(is_logic(0, 0), Felt::from(1u8));
    assert_eq!(is_logic(1, 0), Felt::ZERO);
    assert_eq!(is_logic(2, 0), Felt::from(1u8));
    assert_eq!(is_logic(3, 0), Felt::ZERO);
    // Lane 1: one chain (real, carrier) then zero padding for rows 2–3.
    assert_eq!(is_logic(0, 1), Felt::from(1u8));
    assert_eq!(is_logic(1, 1), Felt::ZERO);
    for r in 2..4 {
        for c in 0..LANE_WIDTH {
            assert_eq!(
                trace.values[r * NUM_MAIN_COLS + lane_base(1) + c],
                Felt::ZERO,
                "lane1 row {r} padding",
            );
        }
    }
}

#[test]
fn require_rol_after_chained_logic_emits_rol_directly() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    // Establish chain so ROL input matches previous LOGIC's c.
    let c = requires.require(&mut bpl, Logic64Op::Xor, 0x1234_5678_9abc_def0, 0);
    assert_eq!(c, 0x1234_5678_9abc_def0);
    // ROL(c, 32 = 2^5).
    let b = requires.require_rol(&mut bpl, c, 32);
    assert_eq!(b, c.rotate_left(5));

    let trace = generate_trace(requires);
    // 1 LOGIC + 1 ROL + 0 trailing carrier (last_real_c = None after ROL) = 2 rows.
    assert_eq!(trace.height(), 2);

    let row0 = &trace.values[0..NUM_MAIN_COLS];
    let row1 = &trace.values[NUM_MAIN_COLS..2 * NUM_MAIN_COLS];

    // Row 0: LOGIC.
    assert_eq!(row0[COL_IS_LOGIC], Felt::from(1u8));
    assert_eq!(row0[COL_IS_ROL], Felt::ZERO);

    // Row 1: ROL.
    assert_eq!(row1[COL_IS_LOGIC], Felt::ZERO);
    assert_eq!(row1[COL_IS_ROL], Felt::from(1u8));
    assert_eq!(row1[COL_OP_OR_K], Felt::new(32).unwrap());
    // Row 1's a_bytes equal c's bytes (chain).
    for (i, byte) in c.to_le_bytes().iter().enumerate() {
        assert_eq!(row1[A_BYTES_RANGE.start + i], Felt::from(*byte));
    }

    // Row 1's b_limbs decompose (lo+2^32)·k and (hi+2^32)·k (each as 4 16-bit limbs).
    // The +2^32 offset ensures the product escapes the aliasable range.
    let [c_lo, c_hi] = split_u64_u32(c);
    let lo_offset_k = (c_lo + (1u64 << 32)) * 32;
    let hi_offset_k = (c_hi + (1u64 << 32)) * 32;
    for i in 0..4 {
        let limb = ((lo_offset_k >> (16 * i)) & 0xffff) as u16;
        assert_eq!(row1[B_LIMBS_RANGE.start + i], Felt::from(limb));
    }
    for i in 0..4 {
        let limb = ((hi_offset_k >> (16 * i)) & 0xffff) as u16;
        assert_eq!(row1[B_LIMBS_RANGE.start + 4 + i], Felt::from(limb));
    }
}

#[test]
#[should_panic(expected = "has no prior LOGIC producer")]
fn require_rol_without_chain_panics() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    // No prior LOGIC produces this value, so at trace-gen the ROL can't
    // claim a producer — build_chains panics.
    requires.require_rol(&mut bpl, 0xdead_beef, 16);
    generate_trace(requires);
}

#[test]
#[should_panic(expected = "has no prior LOGIC producer")]
fn require_rol_with_unmatched_a_panics() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    // Produces 0x42; the ROL below wants 0x99, which no LOGIC produces,
    // so build_chains can't claim a producer for it.
    let _c = requires.require(&mut bpl, Logic64Op::Xor, 0x42, 0);
    requires.require_rol(&mut bpl, 0x99, 32);
    generate_trace(requires);
}

#[test]
#[should_panic(expected = "k must be a power of two")]
fn require_rol_rejects_non_power_of_two_k() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    let c = requires.require(&mut bpl, Logic64Op::Xor, 0x42, 0);
    requires.require_rol(&mut bpl, c, 6); // 6 = 2·3, not a power of 2.
}

#[test]
#[should_panic(expected = "k must be a power of two < 2^31")]
fn require_rol_rejects_k_at_2_pow_31() {
    // The +2^32 offset trick keeps `(half + 2^32)·k < p` only for
    // k ≤ 2^30; k = 2^31 leaves room for an unsound limb decomposition
    // when `half = 2^32 − 1`. See `Bitwise64Requires::require_rol`.
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    let c = requires.require(&mut bpl, Logic64Op::Xor, 0x42, 0);
    requires.require_rol(&mut bpl, c, 1u64 << 31);
}

#[test]
fn require_rol_after_unchained_logic_inserts_carrier() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    // First LOGIC.
    let c1 = requires.require(&mut bpl, Logic64Op::Xor, 0xaa, 0xbb);
    // Second LOGIC, unchained — a Carrier{c1} is inserted before it.
    let c2 = requires.require(&mut bpl, Logic64Op::Xor, c1, 0); // chain to c1, c2 = c1.
    assert_eq!(c2, c1);
    // Now ROL on c2 chains naturally.
    let _b = requires.require_rol(&mut bpl, c2, 8);

    let trace = generate_trace(requires);
    // Real LOGIC, Real LOGIC, ROL = 3 rows (no trailing carrier after ROL) → pow2 = 4.
    assert_eq!(trace.height(), 4);

    let is_logic = |r: usize| trace.values[r * NUM_MAIN_COLS + COL_IS_LOGIC];
    let is_rol = |r: usize| trace.values[r * NUM_MAIN_COLS + COL_IS_ROL];
    assert_eq!(is_logic(0), Felt::from(1u8), "row 0 LOGIC");
    assert_eq!(is_logic(1), Felt::from(1u8), "row 1 LOGIC chained");
    assert_eq!(is_rol(2), Felt::from(1u8), "row 2 ROL");
    assert_eq!(is_logic(3), Felt::ZERO, "row 3 padding");
    assert_eq!(is_rol(3), Felt::ZERO, "row 3 padding");
}

#[test]
fn require_rol_recycles_non_tail_carrier() {
    // A LOGIC, then an unrelated LOGIC, then a ROL on the FIRST LOGIC's
    // c. The first LOGIC's Carrier is no longer at the tail — but
    // require_rol can still recycle it (no "next slot vacant" check
    // needed for ROL). In the lazy `last_real_c`-only design this would
    // have required a no-op `require(Xor, c1, 0)` to re-establish the
    // chain.
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    let c1 = requires.require(&mut bpl, Logic64Op::Xor, 0xaa, 0xbb);
    // Pick (a2, b2) so that a2 != c1 (else the second require would
    // chain-extend and the c1 carrier would be tail-recycled away).
    let c2 = requires.require(&mut bpl, Logic64Op::Xor, 0x33, 0x44);
    assert_ne!(c1, c2, "test values must produce distinct carrier values");
    // Now ROL on c1 — its carrier is at slot 1, two slots back.
    let b = requires.require_rol(&mut bpl, c1, 8);
    assert_eq!(b, c1.rotate_left(3));

    let trace = generate_trace(requires);
    // Two chains: A = [Real_1, Rol(c1)] (recycled non-tail carrier), B =
    // [Real_2, Carrier(c2)]. Greedy puts A in lane 0, B in lane 1 → height 2.
    assert_eq!(trace.height(), 2);
    let is_logic =
        |r: usize, lane: usize| trace.values[r * NUM_MAIN_COLS + lane_base(lane) + COL_IS_LOGIC];
    let is_rol =
        |r: usize, lane: usize| trace.values[r * NUM_MAIN_COLS + lane_base(lane) + COL_IS_ROL];
    // Lane 0: chain A — LOGIC then its ROL cap (recycled c1 carrier).
    assert_eq!(is_logic(0, 0), Felt::from(1u8), "lane0 row0 LOGIC (Real_1)");
    assert_eq!(is_rol(1, 0), Felt::from(1u8), "lane0 row1 ROL on c1");
    // Lane 1: chain B — LOGIC then trailing carrier.
    assert_eq!(is_logic(0, 1), Felt::from(1u8), "lane1 row0 LOGIC (Real_2)");
    assert_eq!(is_rol(1, 1), Felt::ZERO, "lane1 row1 carrier for c2");
    assert_eq!(is_logic(1, 1), Felt::ZERO, "lane1 row1 carrier for c2");
}

#[test]
fn air_quotient_degree_matches_constraint_plan() {
    // The 18 fractions are partitioned ≤ 2 per column (col 0 a single fraction,
    // via a single-insert batch so the gated σ-close stays at degree 3), so
    // every closing constraint is degree ≤ 3 → log_quotient_degree 1. The
    // base-trace constraints all sit at deg ≤ 3 too.
    assert_eq!(crate::tests::log_quotient_degree(&Bitwise64Air), 1);
}

#[test]
fn build_aux_trace_starts_at_zero() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    requires.require(&mut bpl, Logic64Op::Xor, 0xaabb, 0xccdd);
    let (_main, aux, _sigma) = build_aux(requires);
    // Only col 0 (the running sum) carries the σ/n cyclic boundary
    // `aux[0] = 0`. Cols 1, 2 are per-row fraction values whose row-0
    // value is whatever the per-row fractions evaluate to — not pinned.
    assert_eq!(aux.values[AUX_PROVIDE], QuadFelt::ZERO);
}

#[test]
fn build_aux_trace_shape_matches_aux_cols() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    requires.require(&mut bpl, Logic64Op::Xor, 0xaabb, 0xccdd);
    let (main, aux, _sigma) = build_aux(requires);
    assert_eq!(aux.height(), main.height());
    assert_eq!(aux.width(), NUM_AUX_COLS);
}

#[test]
fn lanes_partition_chains_and_shrink_height() {
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    // Eight independent single-logic chains (2 rows each = 16 logical rows).
    // The values are chosen so no result feeds a later input (no chaining).
    for i in 0..8u64 {
        requires.require(&mut bpl, Logic64Op::Xor, 0x100 + i, 0x200 + i);
    }
    let active = requires.active_rows();
    let populated = requires.populated_rows();
    assert_eq!(active, 16, "8 chains × 2 rows");
    // Whole-chain greedy over equal-size chains balances exactly.
    assert_eq!(populated, active / NUM_LANES);

    let trace = generate_trace(requires);
    assert_eq!(trace.width(), NUM_MAIN_COLS);
    assert_eq!(trace.height(), populated.next_power_of_two().max(2));
    // Both lane bands carry real LOGIC work on row 0.
    for lane in 0..NUM_LANES {
        assert_eq!(
            trace.values[lane_base(lane) + COL_IS_LOGIC],
            Felt::from(1u8),
            "lane {lane} row0 should be a real LOGIC row",
        );
    }
}

#[test]
fn rol_offset_limbs_escape_aliasable_range() {
    // Verify that the +2^32 offset ensures (lo+2^32)·k and (hi+2^32)·k
    // are always ≥ 2^32, escaping the aliasable range [0, 2^32-2].
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    let c = requires.require(&mut bpl, Logic64Op::Xor, 0x1234_5678_9abc_def0, 0);
    requires.require_rol(&mut bpl, c, 32);

    let trace = generate_trace(requires);
    let row1 = &trace.values[NUM_MAIN_COLS..2 * NUM_MAIN_COLS];

    // Compute expected offset products.
    let k = 32u64;
    let [c_lo, c_hi] = split_u64_u32(c);
    let lo_offset_k = (c_lo + (1u64 << 32)) * k;
    let hi_offset_k = (c_hi + (1u64 << 32)) * k;

    // Both must be ≥ 2^32 (outside the aliasable range).
    assert!(lo_offset_k >= 1u64 << 32, "lo_offset_k = {lo_offset_k:#x}");
    assert!(hi_offset_k >= 1u64 << 32, "hi_offset_k = {hi_offset_k:#x}");

    // Verify the trace limbs match the expected offset computation.
    for i in 0..4 {
        let expected_limb = ((lo_offset_k >> (16 * i)) & 0xffff) as u16;
        assert_eq!(row1[B_LIMBS_RANGE.start + i], Felt::from(expected_limb));
    }
    for i in 0..4 {
        let expected_limb = ((hi_offset_k >> (16 * i)) & 0xffff) as u16;
        assert_eq!(row1[B_LIMBS_RANGE.start + 4 + i], Felt::from(expected_limb));
    }
}

#[test]
fn num_public_values_matches_shared_root() {
    // 0.26 hands every AIR the same `air_inputs` slice — the 4-felt
    // transcript root. Each chiplet declares that shared count even when it
    // reads none of it (bitwise64 ignores the root entirely).
    assert_eq!(Bitwise64Air.num_public_values(), crate::logup::NUM_PUBLIC_VALUES);
}

#[test]
fn xorrol_op_pin_accepts_honest_fused_pair() {
    // A fused θ-apply+ρ pair: a LOGIC(Xor a, b) row capped by an
    // is_xorrol_cap ROL row, which drives the XorRol64 provide. The honest
    // op tag is Xor, so the op-pin constraint passes (completeness).
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    let a = 0x1122_3344_5566_7788u64;
    let b = 0xaabb_ccdd_eeff_0011u64;
    requires.require_xorrol(&mut bpl, a, b, 1u64 << 3);

    let main = generate_trace(requires);
    // One chain → lane 0: row 0 is the fused LOGIC row, row 1 its cap.
    let base = lane_base(0);
    assert_eq!(main.values[base + COL_IS_LOGIC], Felt::from(1u8));
    assert_eq!(main.values[base + COL_OP_OR_K], Felt::from(Logic64Op::Xor.tag()));
    assert_eq!(main.values[NUM_MAIN_COLS + base + COL_IS_XORROL_CAP], Felt::from(1u8));

    crate::tests::check_local(Bitwise64Air, &main);
}

#[test]
#[should_panic(expected = "constraint")]
fn xorrol_andnot_substitution_rejected() {
    // The op-substitution forgery: relabel the fused LOGIC row's op tag
    // Xor → AndNot. The XorRol64 tuple carries no op, so absent the op-pin
    // constraint the provide would ship rol((¬a)∧b, k) under the XOR label
    // and a consumer would accept a non-XOR permutation. The
    // `is_logic · cap_next · (1 − op_or_k)` constraint rejects it locally.
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();
    requires.require_xorrol(&mut bpl, 0x1122_3344_5566_7788, 0xaabb_ccdd_eeff_0011, 1u64 << 3);

    let mut main = generate_trace(requires);
    let base = lane_base(0);
    // Row 0 is the fused LOGIC row (row 1 caps it); swap Xor (1) for AndNot (0).
    main.values[base + COL_OP_OR_K] = Felt::from(BytePairOp::AndNot.tag());

    crate::tests::check_local(Bitwise64Air, &main);
}
