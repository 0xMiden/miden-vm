use alloc::collections::BTreeMap;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};

use super::{
    layout::*,
    lookup::{
        AEAD_HIGH_OUTPUT_COLUMN, AEAD_INPUT_COLUMN, AEAD_LOW_OUTPUT_COLUMN,
        BLAKEG_LOOKUP_COLUMN_SHAPE, BlakeGCompressionLookupAir, BlakeGCompressionMode,
        COMPRESSION_LINK_COLUMN, LookupPlan, NARROW_BATCH_COLUMNS, NarrowLookup, NarrowLookupKind,
        SingletonLookupKind, lookup_plan,
    },
    periodic::{P_IS_AB, P_IS_CD, P_IS_FOOTER, get_periodic_column_values},
    trace::{BlakeGRow, TraceMode, generate_trace_block},
};
use crate::lookup::{Challenges, build_lookup_fractions};

fn count_narrow(plan: &[NarrowLookup], kind: NarrowLookupKind, sign: i8) -> usize {
    plan.iter().filter(|lookup| lookup.kind == kind && lookup.sign == sign).count()
}

fn signed_narrow_total(kind: NarrowLookupKind) -> i64 {
    (0..BLOCK_PERIOD)
        .flat_map(|row| lookup_plan(row, BlakeGCompressionMode::Compression).narrow)
        .filter(|lookup| lookup.kind == kind)
        .map(|lookup| lookup.sign as i64)
        .sum()
}

fn test_block() -> [u32; 16] {
    [
        0x0000_0001,
        0x0000_0002,
        0x0000_0003,
        0x0000_0004,
        0x8000_0005,
        0x0000_0006,
        0x0000_0007,
        0x0000_0008,
        0x0000_0009,
        0x8000_000a,
        0x8000_000b,
        0x0000_000c,
        0x0000_000d,
        0x0000_000e,
        0x0000_000f,
        0x0000_0010,
    ]
}

fn test_h() -> [u32; 8] {
    [
        0x0000_0021,
        0x8000_0001,
        0x8000_0022,
        0x0000_0043,
        0x0000_0023,
        0x0000_0065,
        0x0000_0024,
        0x0000_0087,
    ]
}

fn add_payload(map: &mut BTreeMap<[u64; 3], i64>, payload: [u64; 3], sign: i64) {
    *map.entry(payload).or_default() += sign;
}

fn packed_b(row: &BlakeGRow, g: usize) -> u64 {
    row[g_bd_rot_slot_col(g, 0, 0)]
        + (row[g_bd_rot_slot_col(g, 1, 0)] << 8)
        + (row[g_bd_rot_slot_col(g, 2, 0)] << 16)
        + (row[g_bd_rot_slot_col(g, 3, 0)] << 24)
}

fn felt_trace_matrix(mode: TraceMode) -> RowMajorMatrix<Felt> {
    let trace = generate_trace_block(test_block(), test_h(), mode);
    let values = trace
        .rows
        .iter()
        .flat_map(|row| row.iter().map(|&value| Felt::new_unchecked(value)))
        .collect();
    RowMajorMatrix::new(values, NUM_COLS)
}

fn lookup_challenges() -> Challenges<QuadFelt> {
    Challenges::new(QuadFelt::from_u32(7), QuadFelt::from_u32(11), 16, 39)
}

fn expected_column_counts(row: usize, mode: BlakeGCompressionMode) -> [usize; AUX_COLS] {
    let mut counts = [0; AUX_COLS];
    let plan = lookup_plan(row, mode);

    for slot in 0..plan.narrow.len() {
        counts[slot / 2] += 1;
    }

    for singleton in plan.singletons {
        counts[LookupPlan::singleton_aux_column(singleton.kind)] += 1;
    }

    counts
}

fn assert_lookup_fraction_counts(mode: BlakeGCompressionMode, trace_mode: TraceMode) {
    let air = BlakeGCompressionLookupAir;
    let trace = felt_trace_matrix(trace_mode);
    let periodic = get_periodic_column_values();
    let fractions = build_lookup_fractions(&air, &trace, None, &periodic, &lookup_challenges());

    assert_eq!(fractions.shape(), BLAKEG_LOOKUP_COLUMN_SHAPE);
    assert_eq!(fractions.counts().len(), BLOCK_PERIOD * AUX_COLS);

    for row in 0..BLOCK_PERIOD {
        let expected = expected_column_counts(row, mode);
        let actual = &fractions.counts()[row * AUX_COLS..(row + 1) * AUX_COLS];
        assert_eq!(actual, expected, "row {row}");
    }
}

#[test]
fn lookup_plans_match_layout_pressure_helpers() {
    for row in 0..BLOCK_PERIOD {
        let compression = lookup_plan(row, BlakeGCompressionMode::Compression);
        assert_eq!(compression.narrow.len(), narrow_lookups_at(row), "row {row}");
        assert_eq!(compression.singletons.len(), common_singletons_at(row), "row {row}");
        assert!(compression.narrow_aux_columns() <= NARROW_BATCH_COLUMNS, "row {row}");
        assert!(aux_cols_at(row, false) <= AUX_COLS, "row {row}");

        let aead = lookup_plan(row, BlakeGCompressionMode::AeadXof);
        assert_eq!(aead.narrow.len(), narrow_lookups_at(row), "row {row}");
        assert_eq!(
            aead.singletons.len(),
            common_singletons_at(row) + aead_singletons_at(row),
            "row {row}",
        );
        assert!(aead.narrow_aux_columns() <= NARROW_BATCH_COLUMNS, "row {row}");
        assert!(aux_cols_at(row, true) <= AUX_COLS, "row {row}");
    }
}

#[test]
fn lookup_plans_fit_fixed_aux_columns() {
    assert_eq!(BLAKEG_LOOKUP_COLUMN_SHAPE.len(), AUX_COLS);
    assert_eq!(NARROW_BATCH_COLUMNS, 20);
    assert_eq!(COMPRESSION_LINK_COLUMN, 20);
    assert_eq!(AEAD_INPUT_COLUMN, 21);
    assert_eq!(AEAD_LOW_OUTPUT_COLUMN, 22);
    assert_eq!(AEAD_HIGH_OUTPUT_COLUMN, 23);

    for mode in [BlakeGCompressionMode::Compression, BlakeGCompressionMode::AeadXof] {
        let narrow_peak = (0..BLOCK_PERIOD)
            .map(|row| lookup_plan(row, mode).narrow_aux_columns())
            .max()
            .unwrap();
        assert_eq!(narrow_peak, NARROW_BATCH_COLUMNS);
    }
}

#[test]
fn lookup_plans_follow_periodic_row_families() {
    let columns = get_periodic_column_values();

    for row in 0..BLOCK_PERIOD {
        let plan = lookup_plan(row, BlakeGCompressionMode::Compression);
        let is_ab = columns[P_IS_AB][row].as_canonical_u64() == 1;
        let is_cd = columns[P_IS_CD][row].as_canonical_u64() == 1;
        let is_footer = columns[P_IS_FOOTER][row].as_canonical_u64() == 1;

        assert_eq!(is_ab, count_narrow(&plan.narrow, NarrowLookupKind::Rot12, -1) > 0);
        assert_eq!(is_cd, count_narrow(&plan.narrow, NarrowLookupKind::Rot7, -1) > 0);
        assert_eq!(is_footer, count_narrow(&plan.narrow, NarrowLookupKind::RangeCheck, -1) > 0);
    }
}

#[test]
fn first_ab_row_carries_all_initial_input_pair_removals() {
    let first = lookup_plan(0, BlakeGCompressionMode::Compression);
    assert_eq!(count_narrow(&first.narrow, NarrowLookupKind::InputPair, -1), 4);
    assert_eq!(count_narrow(&first.narrow, NarrowLookupKind::And8, -1), 16);
    assert_eq!(count_narrow(&first.narrow, NarrowLookupKind::Rot12, -1), 16);
    assert_eq!(count_narrow(&first.narrow, NarrowLookupKind::MessageWord, 1), 4);

    let later_ab = lookup_plan(FUSED_G_ROWS_PER_ROUND, BlakeGCompressionMode::Compression);
    assert_eq!(count_narrow(&later_ab.narrow, NarrowLookupKind::InputPair, -1), 0);
}

#[test]
fn footer_rows_carry_net_hin_and_message_group() {
    let footer = lookup_plan(FOOTER_START + 2, BlakeGCompressionMode::Compression);

    assert_eq!(count_narrow(&footer.narrow, NarrowLookupKind::And8, -1), 17);
    assert_eq!(count_narrow(&footer.narrow, NarrowLookupKind::InputPair, 1), 1);
    assert_eq!(count_narrow(&footer.narrow, NarrowLookupKind::MessageWord, -7), 4);
    assert_eq!(count_narrow(&footer.narrow, NarrowLookupKind::RangeCheck, -1), 8);
    assert!(footer.singletons.is_empty());
}

#[test]
fn message_word_relation_balances_over_one_block() {
    assert_eq!(signed_narrow_total(NarrowLookupKind::MessageWord), 0);
}

#[test]
fn input_pair_relation_balances_without_interface_row() {
    assert_eq!(signed_narrow_total(NarrowLookupKind::InputPair), 0);
}

#[test]
fn message_word_payloads_balance_over_generated_block() {
    let trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    let mut balance = BTreeMap::new();

    for row in 0..FUSED_G_ROWS {
        for g in 0..NUM_G {
            let base = g_msg_slot_col(g, 0);
            add_payload(
                &mut balance,
                [trace.rows[row][base], trace.rows[row][base + 1], trace.rows[row][base + 2]],
                1,
            );
        }
    }

    for footer in 0..FOOTER_ROWS {
        let row = &trace.rows[FOOTER_START + footer];
        for word_slot in 0..F_MSG_WORD_SLOTS {
            let base = footer_msg_word_slot_col(word_slot, 0);
            add_payload(&mut balance, [row[base], row[base + 1], row[base + 2]], -7);
        }
    }

    assert!(balance.values().all(|&count| count == 0));
}

#[test]
fn input_pair_payloads_balance_over_generated_block() {
    let trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);
    let mut balance = BTreeMap::new();
    let first_row = &trace.rows[0];

    add_payload(&mut balance, [0, first_row[G_A_BASE_COL], first_row[G_A_BASE_COL + 1]], -1);
    add_payload(&mut balance, [1, first_row[G_A_BASE_COL + 2], first_row[G_A_BASE_COL + 3]], -1);
    add_payload(&mut balance, [2, packed_b(first_row, 0), packed_b(first_row, 1)], -1);
    add_payload(&mut balance, [3, packed_b(first_row, 2), packed_b(first_row, 3)], -1);

    for footer in 0..FOOTER_ROWS {
        let row = &trace.rows[FOOTER_START + footer];
        add_payload(
            &mut balance,
            [
                row[F_HIN_SLOT_BASE_COL],
                row[F_HIN_SLOT_BASE_COL + 1],
                row[F_HIN_SLOT_BASE_COL + 2],
            ],
            1,
        );
    }

    assert!(balance.values().all(|&count| count == 0));
}

#[test]
fn final_footer_singletons_are_mode_specific() {
    let compression = lookup_plan(FOOTER_START + 3, BlakeGCompressionMode::Compression);
    assert_eq!(compression.singletons.len(), 1);
    assert_eq!(compression.singletons[0].kind, SingletonLookupKind::CompressionLink);
    assert_eq!(compression.singletons[0].sign, -1);

    let aead = lookup_plan(FOOTER_START + 3, BlakeGCompressionMode::AeadXof);
    assert_eq!(aead.singletons.len(), 3);
    assert_eq!(aead.singletons[0].kind, SingletonLookupKind::AeadInput);
    assert_eq!(aead.singletons[0].sign, -1);
    assert_eq!(LookupPlan::singleton_aux_column(aead.singletons[0].kind), AEAD_INPUT_COLUMN,);
    assert_eq!(aead.singletons[1].kind, SingletonLookupKind::AeadLowOutputPair);
    assert_eq!(aead.singletons[1].sign, -1);
    assert_eq!(
        LookupPlan::singleton_aux_column(aead.singletons[1].kind),
        AEAD_LOW_OUTPUT_COLUMN,
    );
    assert_eq!(aead.singletons[2].kind, SingletonLookupKind::AeadHighOutputPair);
    assert_eq!(aead.singletons[2].sign, -1);
    assert_eq!(
        LookupPlan::singleton_aux_column(aead.singletons[2].kind),
        AEAD_HIGH_OUTPUT_COLUMN,
    );
}

#[test]
fn batch_two_aux_columns_pair_adjacent_narrow_lookups() {
    let plan = lookup_plan(0, BlakeGCompressionMode::Compression);
    assert_eq!(plan.narrow.len(), 40);

    for slot in 0..plan.narrow.len() {
        assert_eq!(super::lookup::LookupPlan::narrow_aux_column(slot), slot / 2);
    }
    assert_eq!(plan.narrow_aux_columns(), 20);
}

#[test]
fn lookup_air_emits_expected_compression_fraction_counts() {
    assert_lookup_fraction_counts(BlakeGCompressionMode::Compression, TraceMode::Compression);
}

#[test]
fn lookup_air_emits_expected_aead_fraction_counts() {
    assert_lookup_fraction_counts(BlakeGCompressionMode::AeadXof, TraceMode::AeadXof { clk: 19 });
}
