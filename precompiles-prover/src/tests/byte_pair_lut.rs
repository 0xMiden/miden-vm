use std::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt, batch_multiplicative_inverse},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::{BaseAir, LiftedAir};

use crate::{
    logup::{Challenges, lookup_challenges_from_slice},
    primitives::byte_pair_lut::{
        BytePairLutAir, BytePairLutRequires, BytePairOp, COL_MULT_ANDNOT, COL_MULT_RANGE16,
        COL_MULT_XOR, NUM_AUX_COLS, NUM_MAIN_COLS, NUM_PREPROCESSED_COLS, PRE_A, PRE_B,
        PRE_C_ANDNOT, PRE_C_XOR, TRACE_HEIGHT, generate_trace, preprocessed_table,
    },
    relations::BusId,
};

fn test_alpha_beta() -> [QuadFelt; 2] {
    [QuadFelt::from(Felt::from(7u8)), QuadFelt::from(Felt::from(11u8))]
}

fn test_challenges() -> Challenges<QuadFelt> {
    lookup_challenges_from_slice(&test_alpha_beta())
}

#[test]
fn andnot_uses_keccak_chi_convention() {
    assert_eq!(BytePairOp::AndNot.apply(0xf0, 0xcc), (!0xf0u8) & 0xcc);
    assert_eq!(BytePairOp::Xor.apply(0xab, 0xcd), 0xab ^ 0xcd);
}

#[test]
fn op_tags_match_relation_encoding() {
    assert_eq!(BytePairOp::AndNot.tag(), 0);
    assert_eq!(BytePairOp::Xor.tag(), 1);
}

#[test]
fn require_increments_multiplicity() {
    let mut requires = BytePairLutRequires::new();
    let r = requires.require(BytePairOp::Xor, 0xab, 0xcd);
    assert_eq!(r, 0xab ^ 0xcd);
    assert_eq!(requires.multiplicity(BytePairOp::Xor, 0xab, 0xcd), 1);

    requires.require(BytePairOp::Xor, 0xab, 0xcd);
    assert_eq!(requires.multiplicity(BytePairOp::Xor, 0xab, 0xcd), 2);
    assert_eq!(requires.multiplicity(BytePairOp::AndNot, 0xab, 0xcd), 0);
}

#[test]
fn require_range16_increments_dedicated_multiplicity() {
    let mut requires = BytePairLutRequires::new();
    // w = 0xABCD → low byte 0xCD, high byte 0xAB.
    requires.require_range16(0xabcd);
    assert_eq!(requires.multiplicity_range16(0xabcd), 1);
    // Compute-op multiplicities on the same row stay zero.
    assert_eq!(requires.multiplicity(BytePairOp::Xor, 0xcd, 0xab), 0);
    assert_eq!(requires.multiplicity(BytePairOp::AndNot, 0xcd, 0xab), 0);

    requires.require_range16(0xabcd);
    assert_eq!(requires.multiplicity_range16(0xabcd), 2);
}

/// Row index for `(a, b)` in the fixed lex-order trace.
fn row_idx(a: u8, b: u8) -> usize {
    ((a as usize) << 8) | (b as usize)
}

fn row(trace: &RowMajorMatrix<Felt>, idx: usize) -> &[Felt] {
    &trace.values[idx * NUM_MAIN_COLS..(idx + 1) * NUM_MAIN_COLS]
}

/// Row from the preprocessed data table (`a, b, c_andnot, c_xor`).
fn pre_row(table: &RowMajorMatrix<Felt>, idx: usize) -> &[Felt] {
    &table.values[idx * NUM_PREPROCESSED_COLS..(idx + 1) * NUM_PREPROCESSED_COLS]
}

#[test]
fn empty_requires_enumerates_all_pairs_with_zero_mults() {
    let trace = generate_trace(BytePairLutRequires::new());
    assert_eq!(trace.height(), TRACE_HEIGHT);
    assert_eq!(trace.width(), NUM_MAIN_COLS);

    let table = preprocessed_table();
    assert_eq!(table.height(), TRACE_HEIGHT);
    assert_eq!(table.width(), NUM_PREPROCESSED_COLS);

    // Spot-check a handful of rows: the preprocessed table lex-enumerates
    // (a, b) with the correct results; the witness mults are all zero.
    for (a, b) in [(0u8, 0u8), (1, 2), (5, 3), (0xab, 0xcd), (255, 255)] {
        let p = pre_row(&table, row_idx(a, b));
        assert_eq!(p[PRE_A], Felt::from(a));
        assert_eq!(p[PRE_B], Felt::from(b));
        assert_eq!(p[PRE_C_ANDNOT], Felt::from((!a) & b));
        assert_eq!(p[PRE_C_XOR], Felt::from(a ^ b));

        let r = row(&trace, row_idx(a, b));
        assert_eq!(r[COL_MULT_ANDNOT], Felt::ZERO);
        assert_eq!(r[COL_MULT_XOR], Felt::ZERO);
        assert_eq!(r[COL_MULT_RANGE16], Felt::ZERO);
    }
}

#[test]
fn preprocessed_table_is_correct_for_all_pairs() {
    // Soundness rests entirely on the fixed preprocessed table: every
    // `(a, b)` row must carry the correct bytewise results. Check all
    // `2^16` rows exhaustively (a malicious prover cannot deviate from this
    // table — it is verifier-committed, not witness).
    let table = preprocessed_table();
    assert_eq!(table.height(), TRACE_HEIGHT);
    for a in 0u16..256 {
        for b in 0u16..256 {
            let (a, b) = (a as u8, b as u8);
            let p = pre_row(&table, row_idx(a, b));
            assert_eq!(p[PRE_A], Felt::from(a));
            assert_eq!(p[PRE_B], Felt::from(b));
            assert_eq!(p[PRE_C_ANDNOT], Felt::from((!a) & b));
            assert_eq!(p[PRE_C_XOR], Felt::from(a ^ b));
        }
    }
}

#[test]
fn trace_height_is_fixed_at_2_pow_16() {
    // Multiplicities don't affect height: every `(a, b)` gets a row
    // whether anyone required it or not.
    let mut requires = BytePairLutRequires::new();
    requires.require(BytePairOp::Xor, 0x10, 0x20);
    requires.require(BytePairOp::AndNot, 0x10, 0x20);
    assert_eq!(generate_trace(requires).height(), TRACE_HEIGHT);
    assert_eq!(generate_trace(BytePairLutRequires::new()).height(), TRACE_HEIGHT);
}

#[test]
fn trace_row_carries_results_and_multiplicities_at_lex_index() {
    let mut requires = BytePairLutRequires::new();
    requires.require(BytePairOp::Xor, 0x05, 0x03);
    requires.require(BytePairOp::Xor, 0x05, 0x03);
    requires.require(BytePairOp::AndNot, 0x05, 0x03);
    requires.require(BytePairOp::AndNot, 0x01, 0x02);
    // Range16 require on w = 0x0301 → (a, b) = (0x01, 0x03).
    requires.require_range16(0x0301);

    let trace = generate_trace(requires);
    let table = preprocessed_table();

    // Preprocessed data is the fixed table (independent of requires); the
    // witness multiplicities track the requires.
    // (a=0x01, b=0x02): one AndNot require.
    let p = pre_row(&table, row_idx(0x01, 0x02));
    assert_eq!(p[PRE_C_ANDNOT], Felt::from(0x02u8));
    assert_eq!(p[PRE_C_XOR], Felt::from(0x03u8));
    let r = row(&trace, row_idx(0x01, 0x02));
    assert_eq!(r[COL_MULT_ANDNOT], Felt::from(1u8));
    assert_eq!(r[COL_MULT_XOR], Felt::ZERO);
    assert_eq!(r[COL_MULT_RANGE16], Felt::ZERO);

    // (a=0x01, b=0x03): Range16-only row.
    let p = pre_row(&table, row_idx(0x01, 0x03));
    assert_eq!(p[PRE_C_ANDNOT], Felt::from((!1u8) & 3));
    assert_eq!(p[PRE_C_XOR], Felt::from(1u8 ^ 3));
    let r = row(&trace, row_idx(0x01, 0x03));
    assert_eq!(r[COL_MULT_ANDNOT], Felt::ZERO);
    assert_eq!(r[COL_MULT_XOR], Felt::ZERO);
    assert_eq!(r[COL_MULT_RANGE16], Felt::from(1u8));

    // (a=0x05, b=0x03): one AndNot + two Xor requires.
    let p = pre_row(&table, row_idx(0x05, 0x03));
    assert_eq!(p[PRE_C_ANDNOT], Felt::from(0x02u8));
    assert_eq!(p[PRE_C_XOR], Felt::from(0x06u8));
    let r = row(&trace, row_idx(0x05, 0x03));
    assert_eq!(r[COL_MULT_ANDNOT], Felt::from(1u8));
    assert_eq!(r[COL_MULT_XOR], Felt::from(2u8));
    assert_eq!(r[COL_MULT_RANGE16], Felt::ZERO);

    // An untouched neighbour: zero mults, correct data.
    let p = pre_row(&table, row_idx(0x05, 0x04));
    assert_eq!(p[PRE_C_XOR], Felt::from(0x05u8 ^ 0x04u8));
    let r = row(&trace, row_idx(0x05, 0x04));
    assert_eq!(r[COL_MULT_ANDNOT], Felt::ZERO);
    assert_eq!(r[COL_MULT_XOR], Felt::ZERO);
    assert_eq!(r[COL_MULT_RANGE16], Felt::ZERO);
}

#[test]
fn air_quotient_degree_matches_constraint_plan() {
    // Column 0 batches the 3 self-provide fractions, so its denominator
    // product `D₀` is degree 3 and the running-sum close `D₀·(acc' − acc) −
    // N₀` is degree 4 ungated. The natural last-row σ-closing gates it with
    // the degree-1 `is_transition` / `is_last_row` selector → degree 5 →
    // log_quotient_degree = log2_ceil(5 − 1) = 2. Reading the operands from
    // preprocessed vs. witness columns doesn't change the degree.
    assert_eq!(crate::tests::log_quotient_degree(&BytePairLutAir), 2);
}

/// Prover-driven aux-trace build. Returns `(aux, sigma)`; `aux_values`
/// is always `[sigma]` for BPL.
fn build_aux(
    requires: BytePairLutRequires,
) -> (RowMajorMatrix<Felt>, RowMajorMatrix<QuadFelt>, QuadFelt) {
    let main = generate_trace(requires);
    let flat = test_alpha_beta();
    let (aux, aux_values) = BytePairLutAir.build_aux_trace(&main, &[], &[], &flat);
    assert_eq!(aux_values.len(), 1, "BPL exposes exactly one aux value (σ)");
    (main, aux, aux_values[0])
}

#[test]
fn build_aux_trace_matches_main_height() {
    let mut requires = BytePairLutRequires::new();
    requires.require(BytePairOp::Xor, 0x05, 0x03);
    requires.require(BytePairOp::AndNot, 0x10, 0x20);
    requires.require_range16(0x4321);

    let (main, aux, _sigma) = build_aux(requires);
    let height = main.height();

    assert_eq!(aux.height(), height);
    assert_eq!(aux.width(), NUM_AUX_COLS);
}

#[test]
fn build_aux_trace_starts_at_zero() {
    let mut requires = BytePairLutRequires::new();
    requires.require(BytePairOp::Xor, 0x05, 0x03);
    requires.require(BytePairOp::AndNot, 0x10, 0x20);

    let (_main, aux, _sigma) = build_aux(requires);
    assert_eq!(aux.values[0], QuadFelt::ZERO);
}

#[test]
fn populate_aux_trace_exposed_residue_matches_full_sum() {
    // σ should equal the chiplet's full residue —
    // independently computed as −Σ enc⁻¹ over every individual lookup.
    let bp_calls = [
        (BytePairOp::Xor, 0x05u8, 0x03u8),
        (BytePairOp::Xor, 0x05, 0x03),
        (BytePairOp::AndNot, 0x05, 0x03),
        (BytePairOp::AndNot, 0x10, 0x20),
    ];
    let r16_calls: &[u16] = &[0x0301, 0x0301, 0x2010];

    let mut requires = BytePairLutRequires::new();
    for &(op, a, b) in &bp_calls {
        requires.require(op, a, b);
    }
    for &w in r16_calls {
        requires.require_range16(w);
    }

    let challenges = test_challenges();
    let (_main, _aux, sigma) = build_aux(requires);

    // One encoding per call; each contributes −1/enc to σ.
    let mut encs: Vec<QuadFelt> = Vec::new();
    for &(op, a, b) in &bp_calls {
        let c = op.apply(a, b);
        encs.push(challenges.encode(
            BusId::BytePairLut as usize,
            [Felt::from(op.tag()), Felt::from(a), Felt::from(b), Felt::from(c)],
        ));
    }
    for &w in r16_calls {
        let lo = (w & 0xff) as u8;
        let hi = (w >> 8) as u8;
        let w_felt = Felt::from(lo) + Felt::from(256u16) * Felt::from(hi);
        encs.push(challenges.encode(BusId::Range16 as usize, [w_felt]));
    }
    let invs = batch_multiplicative_inverse(&encs);
    let expected_residue: QuadFelt = -invs.iter().copied().sum::<QuadFelt>();

    assert_eq!(sigma, expected_residue);
}

#[test]
fn num_public_values_matches_shared_root() {
    // 0.26 hands every AIR the same `air_inputs` slice — the 4-felt
    // transcript root. The BPL table reads none of it but declares the
    // shared count. (The old σ/n `inv_n` public input is gone.)
    assert_eq!(BytePairLutAir.num_public_values(), crate::logup::NUM_PUBLIC_VALUES);
}
