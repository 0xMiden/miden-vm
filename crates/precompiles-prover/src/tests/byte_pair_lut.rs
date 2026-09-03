use std::vec::Vec;

use miden_air::lookup::debug::{ValidateLayout, ValidateLookupAir};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt, batch_multiplicative_inverse},
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::{BaseAir, LiftedAir};
use miden_precompiles_air::primitives::byte_pair_lut::eidos::{
    self as eidos_lookup, Relation as EidosRelation, Rotation,
};

use crate::{
    logup::{
        Challenges, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, lookup_challenges_from_slice,
    },
    primitives::byte_pair_lut::{
        BytePairLutAir, BytePairLutMsg, BytePairLutRequires, BytePairOp, NUM_AUX_COLS,
        NUM_MAIN_COLS, NUM_PREPROCESSED_COLS, PRE_A, PRE_B, PRE_WRAP7, PRE_WRAP12, PRE_XOR,
        TRACE_HEIGHT, generate_trace, preprocessed_table,
    },
    relations::BusId,
};

const COL_MULT_CANONICAL_XOR: usize = EidosRelation::CanonicalXor.index();
const COL_MULT_RANGE16: usize = NUM_MAIN_COLS - 1;

fn test_alpha_beta() -> [QuadFelt; 2] {
    [QuadFelt::from(Felt::from(7u8)), QuadFelt::from(Felt::from(11u8))]
}

fn test_challenges() -> Challenges<QuadFelt> {
    lookup_challenges_from_slice(&test_alpha_beta())
}

#[test]
fn logic_operations_use_expected_conventions() {
    assert_eq!(BytePairOp::And.apply(0xf0, 0xcc), 0xf0 & 0xcc);
    assert_eq!(BytePairOp::AndNot.apply(0xf0, 0xcc), (!0xf0u8) & 0xcc);
    assert_eq!(BytePairOp::Xor.apply(0xab, 0xcd), 0xab ^ 0xcd);
}

#[test]
fn logic_operations_encode_the_same_canonical_relation() {
    let challenges = test_challenges();

    for (a, b) in [(0u8, 0u8), (1, 2), (5, 3), (0xab, 0xcd), (255, 255)] {
        let a_felt = Felt::from(a);
        let b_felt = Felt::from(b);
        let expected =
            BytePairLutMsg::from_and(a_felt, b_felt, Felt::from(a & b)).encode(&challenges);
        let xor = BytePairLutMsg::from_xor(a_felt, b_felt, Felt::from(a ^ b)).encode(&challenges);
        let andnot =
            BytePairLutMsg::from_andnot(a_felt, b_felt, Felt::from((!a) & b)).encode(&challenges);

        assert_eq!(xor, expected, "XOR mapping differed for ({a}, {b})");
        assert_eq!(andnot, expected, "ANDNOT mapping differed for ({a}, {b})");
    }
}

#[test]
fn logic_requires_share_one_multiplicity() {
    let mut requires = BytePairLutRequires::new();
    assert_eq!(requires.require(BytePairOp::And, 0xab, 0xcd), 0xab & 0xcd);
    assert_eq!(requires.multiplicity_canonical_xor(0xab, 0xcd), 1);

    assert_eq!(requires.require(BytePairOp::Xor, 0xab, 0xcd), 0xab ^ 0xcd);
    assert_eq!(requires.multiplicity_canonical_xor(0xab, 0xcd), 2);

    assert_eq!(requires.require(BytePairOp::AndNot, 0xab, 0xcd), (!0xabu8) & 0xcd);
    assert_eq!(requires.multiplicity_canonical_xor(0xab, 0xcd), 3);
}

#[test]
fn rotation_requires_share_the_canonical_relation_where_normalization_allows() {
    let mut requires = BytePairLutRequires::new();
    let a = 0x35;
    let b = 0xa7;

    for rotation in [Rotation::Rot12, Rotation::Rot7] {
        for byte in 0..4 {
            assert_eq!(
                requires.require_eidos_rotation(rotation, byte, a, b),
                eidos_lookup::contribution(rotation, byte, a, b),
            );
        }
    }

    assert_eq!(requires.multiplicity_canonical_xor(a, b), 3);
    for relation in [
        EidosRelation::Rot12Pos1,
        EidosRelation::Rot7Pos0,
        EidosRelation::Rot7Pos2,
        EidosRelation::Rot12Pos3,
        EidosRelation::Rot7Pos3,
    ] {
        assert_eq!(requires.multiplicity_relation(relation, a, b), 1);
    }

    let trace = generate_trace(requires);
    let row = row(&trace, row_idx(a, b));
    assert_eq!(
        &row[..COL_MULT_RANGE16],
        &[Felt::from_u8(3), Felt::ONE, Felt::ONE, Felt::ONE, Felt::ONE, Felt::ONE],
    );
    assert_eq!(row[COL_MULT_RANGE16], Felt::ZERO);
}

#[test]
fn require_range16_increments_only_its_relation() {
    let mut requires = BytePairLutRequires::new();
    // Range16 uses w = a + 256*b, so 0xabcd maps to (a, b) = (0xcd, 0xab).
    requires.require_range16(0xabcd);
    assert_eq!(requires.multiplicity_range16(0xabcd), 1);
    assert_eq!(requires.multiplicity_canonical_xor(0xcd, 0xab), 0);
    for relation in [
        EidosRelation::Rot12Pos1,
        EidosRelation::Rot7Pos0,
        EidosRelation::Rot7Pos2,
        EidosRelation::Rot12Pos3,
        EidosRelation::Rot7Pos3,
    ] {
        assert_eq!(requires.multiplicity_relation(relation, 0xcd, 0xab), 0);
    }

    requires.require_range16(0xabcd);
    assert_eq!(requires.multiplicity_range16(0xabcd), 2);
}

/// Row index for `(a, b)` in the fixed lexicographic trace.
fn row_idx(a: u8, b: u8) -> usize {
    ((a as usize) << 8) | (b as usize)
}

fn row(trace: &RowMajorMatrix<Felt>, idx: usize) -> &[Felt] {
    &trace.values[idx * NUM_MAIN_COLS..(idx + 1) * NUM_MAIN_COLS]
}

fn pre_row(table: &RowMajorMatrix<Felt>, idx: usize) -> &[Felt] {
    &table.values[idx * NUM_PREPROCESSED_COLS..(idx + 1) * NUM_PREPROCESSED_COLS]
}

#[test]
fn empty_requires_enumerates_all_pairs_with_zero_multiplicities() {
    let trace = generate_trace(BytePairLutRequires::new());
    assert_eq!(trace.height(), TRACE_HEIGHT);
    assert_eq!(trace.width(), NUM_MAIN_COLS);
    assert!(trace.values.iter().all(|value| *value == Felt::ZERO));

    let table = preprocessed_table();
    assert_eq!(table.height(), TRACE_HEIGHT);
    assert_eq!(table.width(), NUM_PREPROCESSED_COLS);
}

#[test]
fn preprocessed_table_and_derived_rotations_are_correct_for_all_pairs() {
    // The verifier commits this table, so exhaustively pin every deterministic output and every
    // affine output reconstructed from it by the provider AIR.
    let table = preprocessed_table();
    assert_eq!(table.height(), TRACE_HEIGHT);

    for a in 0u16..256 {
        for b in 0u16..256 {
            let (a, b) = (a as u8, b as u8);
            let p = pre_row(&table, row_idx(a, b));
            assert_eq!(p[PRE_A], Felt::from(a));
            assert_eq!(p[PRE_B], Felt::from(b));
            assert_eq!(p[PRE_XOR], Felt::from(a ^ b));
            assert_eq!(
                p[PRE_WRAP12],
                Felt::from(eidos_lookup::contribution(Rotation::Rot12, 1, a, b)),
            );
            assert_eq!(
                p[PRE_WRAP7],
                Felt::from(eidos_lookup::contribution(Rotation::Rot7, 0, a, b)),
            );

            let x = Felt::from(a ^ b);
            let derived_rot12 = [
                Felt::from(1u32 << 20) * x,
                p[PRE_WRAP12],
                Felt::from(1u8 << 4) * x,
                Felt::from(1u32 << 12) * x,
            ];
            let derived_rot7 = [
                p[PRE_WRAP7],
                Felt::from(1u8 << 1) * x,
                Felt::from(1u16 << 9) * x,
                Felt::from(1u32 << 17) * x,
            ];
            for byte in 0..4 {
                assert_eq!(
                    derived_rot12[byte],
                    Felt::from(eidos_lookup::contribution(Rotation::Rot12, byte, a, b)),
                );
                assert_eq!(
                    derived_rot7[byte],
                    Felt::from(eidos_lookup::contribution(Rotation::Rot7, byte, a, b)),
                );
            }
        }
    }
}

#[test]
fn trace_height_is_fixed_at_two_to_the_sixteenth() {
    let mut requires = BytePairLutRequires::new();
    requires.require(BytePairOp::Xor, 0x10, 0x20);
    requires.require(BytePairOp::AndNot, 0x10, 0x20);
    assert_eq!(generate_trace(requires).height(), TRACE_HEIGHT);
    assert_eq!(generate_trace(BytePairLutRequires::new()).height(), TRACE_HEIGHT);
}

#[test]
fn trace_rows_carry_the_aggregated_relation_multiplicities() {
    let mut requires = BytePairLutRequires::new();
    requires.require(BytePairOp::Xor, 0x05, 0x03);
    requires.require(BytePairOp::Xor, 0x05, 0x03);
    requires.require(BytePairOp::AndNot, 0x05, 0x03);
    requires.require(BytePairOp::AndNot, 0x01, 0x02);
    requires.require_eidos_rotation(Rotation::Rot12, 2, 0x05, 0x03);
    requires.require_eidos_rotation(Rotation::Rot7, 3, 0x05, 0x03);
    requires.require_range16(0x0301);

    let trace = generate_trace(requires);

    let one_logic = row(&trace, row_idx(0x01, 0x02));
    assert_eq!(one_logic[COL_MULT_CANONICAL_XOR], Felt::ONE);
    assert!(one_logic[1..].iter().all(|value| *value == Felt::ZERO));

    let range_only = row(&trace, row_idx(0x01, 0x03));
    assert_eq!(range_only[COL_MULT_RANGE16], Felt::ONE);
    assert!(range_only[..COL_MULT_RANGE16].iter().all(|value| *value == Felt::ZERO),);

    let shared = row(&trace, row_idx(0x05, 0x03));
    assert_eq!(shared[COL_MULT_CANONICAL_XOR], Felt::from(4u8));
    assert_eq!(shared[EidosRelation::Rot7Pos3.index()], Felt::ONE);
    assert_eq!(shared[EidosRelation::Rot12Pos1.index()], Felt::ZERO);
    assert_eq!(shared[EidosRelation::Rot7Pos0.index()], Felt::ZERO);
    assert_eq!(shared[EidosRelation::Rot7Pos2.index()], Felt::ZERO);
    assert_eq!(shared[EidosRelation::Rot12Pos3.index()], Felt::ZERO);
    assert_eq!(shared[COL_MULT_RANGE16], Felt::ZERO);

    assert!(row(&trace, row_idx(0x05, 0x04)).iter().all(|value| *value == Felt::ZERO),);
}

#[test]
fn lookup_degree_annotations_match_the_unified_table_layout() {
    assert_eq!((NUM_MAIN_COLS, NUM_PREPROCESSED_COLS, NUM_AUX_COLS), (7, 5, 4));
    BytePairLutAir
        .validate(ValidateLayout {
            preprocessed_width: NUM_PREPROCESSED_COLS,
            trace_width: NUM_MAIN_COLS,
            num_public_values: NUM_PUBLIC_VALUES,
            num_periodic_columns: 0,
            permutation_width: NUM_AUX_COLS,
            num_permutation_challenges: NUM_RANDOMNESS,
            num_permutation_values: 1,
        })
        .unwrap_or_else(|error| panic!("byte-pair lookup validation failed: {error}"));
    assert_eq!(crate::tests::log_quotient_degree(&BytePairLutAir), 1);
}

/// Build the prover-driven aux trace and return its centered LogUp residue.
fn build_aux(
    requires: BytePairLutRequires,
) -> (RowMajorMatrix<Felt>, RowMajorMatrix<QuadFelt>, QuadFelt) {
    let main = generate_trace(requires);
    let flat = test_alpha_beta();
    let (aux, aux_values) = BytePairLutAir.build_aux_trace(&main, &[], &[], &flat);
    assert_eq!(aux_values.len(), 1, "byte-pair table exposes one centered residue");
    (main, aux, aux_values[0])
}

#[test]
fn build_aux_trace_has_the_declared_shape_and_zero_initial_state() {
    let mut requires = BytePairLutRequires::new();
    requires.require(BytePairOp::Xor, 0x05, 0x03);
    requires.require(BytePairOp::AndNot, 0x10, 0x20);
    requires.require_eidos_rotation(Rotation::Rot12, 1, 0xab, 0xcd);
    requires.require_range16(0x4321);

    let (main, aux, _residue) = build_aux(requires);
    assert_eq!(aux.height(), main.height());
    assert_eq!(aux.width(), NUM_AUX_COLS);
    assert_eq!(aux.values[0], QuadFelt::ZERO);
}

#[test]
fn committed_logup_value_is_the_centered_full_sum() {
    let logic_calls = [
        (BytePairOp::Xor, 0x05u8, 0x03u8),
        (BytePairOp::Xor, 0x05, 0x03),
        (BytePairOp::AndNot, 0x05, 0x03),
        (BytePairOp::AndNot, 0x10, 0x20),
    ];
    let range_calls: &[u16] = &[0x0301, 0x0301, 0x2010];
    let rotation_calls = [
        (Rotation::Rot12, 0, 0x35u8, 0xa7u8),
        (Rotation::Rot12, 1, 0x35, 0xa7),
        (Rotation::Rot12, 2, 0x35, 0xa7),
        (Rotation::Rot12, 3, 0x35, 0xa7),
        (Rotation::Rot7, 0, 0x35, 0xa7),
        (Rotation::Rot7, 1, 0x35, 0xa7),
        (Rotation::Rot7, 2, 0x35, 0xa7),
        (Rotation::Rot7, 3, 0x35, 0xa7),
    ];

    let mut requires = BytePairLutRequires::new();
    for &(op, a, b) in &logic_calls {
        requires.require(op, a, b);
    }
    for &w in range_calls {
        requires.require_range16(w);
    }
    for &(rotation, byte, a, b) in &rotation_calls {
        requires.require_eidos_rotation(rotation, byte, a, b);
    }

    let challenges = test_challenges();
    let (_main, _aux, residue) = build_aux(requires);

    let mut encodings: Vec<QuadFelt> = logic_calls
        .iter()
        .map(|&(_op, a, b)| {
            challenges.encode(
                BusId::BytePairLut as usize,
                [Felt::from(a), Felt::from(b), Felt::from(a ^ b)],
            )
        })
        .collect();
    encodings.extend(
        range_calls
            .iter()
            .map(|&w| challenges.encode(BusId::Range16 as usize, [Felt::from(w)])),
    );
    encodings.extend(rotation_calls.iter().map(|&(rotation, byte, a, b)| {
        let relation = EidosRelation::for_rotation(rotation, byte);
        let value = eidos_lookup::normalize(
            byte,
            Felt::from(eidos_lookup::contribution(rotation, byte, a, b)),
        );
        challenges.encode(relation.bus() as usize, [Felt::from(a), Felt::from(b), value])
    }));

    let inverses = batch_multiplicative_inverse(&encodings);
    let expected_sum: QuadFelt = -inverses.iter().copied().sum::<QuadFelt>();
    assert_eq!(QuadFelt::from_usize(TRACE_HEIGHT) * residue, expected_sum);
}

#[test]
fn num_public_values_matches_shared_root() {
    assert_eq!(BytePairLutAir.num_public_values(), NUM_PUBLIC_VALUES);
}
