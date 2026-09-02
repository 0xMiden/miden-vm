use alloc::{collections::BTreeMap, vec::Vec};

use miden_core::{
    Felt,
    field::{Field, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};

use super::{
    algebra::{cv_storage_coefficient, universal_cv_word},
    layout::*,
    lookup::{
        EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, EidosCompressionLookupAir, EidosCompressionMode,
        FOOTER_INPUT_COLUMN, FOOTER_OUTPUT_COLUMN, NARROW_BATCH_COLUMNS, NarrowLookup,
        NarrowLookupKind, OverlayRelationKind, lookup_plan,
    },
    model::low_output,
    periodic::{P_IS_AB, P_IS_CD, P_IS_FOOTER, get_periodic_column_values},
    schedule::fused_step_at,
    trace::{EidosCompressionRow, TraceMode, generate_trace_block_with_cycle_id},
};
#[cfg(feature = "std")]
use crate::lookup::debug::{ValidateLayout, ValidateLookupAir};
use crate::{
    constraints::{
        and8_lookup::columns::eidos_compression_rotation_contribution,
        lookup::messages::{
            AeadEidosCompressionInputMsg, HasherCompressionLinkMsg, eidos_compression_rot7_bus,
            eidos_compression_rot12_bus,
        },
    },
    logup::BusId,
    lookup::{
        Challenges, LookupFractions, LookupMessage, accumulate, accumulate_slow,
        build_lookup_fractions,
    },
};

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

fn other_test_block() -> [u32; 16] {
    core::array::from_fn(|idx| 0x1000_0000 + idx as u32 * 17)
}

fn other_test_h() -> [u32; 8] {
    core::array::from_fn(|idx| 0x2000_0000 + idx as u32 * 19)
}

fn count_narrow(plan: &[NarrowLookup], kind: NarrowLookupKind, sign: i8) -> usize {
    plan.iter().filter(|lookup| lookup.kind == kind && lookup.sign == sign).count()
}

fn signed_narrow_total(kind: NarrowLookupKind) -> i64 {
    (0..BLOCK_PERIOD)
        .flat_map(|row| lookup_plan(row, EidosCompressionMode::Compression).narrow)
        .filter(|lookup| lookup.kind == kind)
        .map(|lookup| lookup.sign as i64)
        .sum()
}

fn felt_trace_matrix(mode: TraceMode) -> RowMajorMatrix<Felt> {
    felt_trace_matrix_with_cycle_id(0, mode)
}

fn felt_trace_matrix_with_cycle_id(
    compression_cycle_id: u64,
    mode: TraceMode,
) -> RowMajorMatrix<Felt> {
    let trace =
        generate_trace_block_with_cycle_id(test_block(), test_h(), compression_cycle_id, mode);
    felt_matrix_from_rows(&trace.rows)
}

fn felt_matrix_from_rows(rows: &[EidosCompressionRow]) -> RowMajorMatrix<Felt> {
    let values = rows
        .iter()
        .flat_map(|row| row.iter().map(|&value| Felt::new_unchecked(value)))
        .collect();
    RowMajorMatrix::new(values, NUM_COLS)
}

fn lookup_challenges() -> Challenges<QuadFelt> {
    Challenges::new(QuadFelt::from_u32(7), QuadFelt::from_u32(11), 16, BusId::COUNT)
}

fn lookup_fractions(trace: &RowMajorMatrix<Felt>) -> LookupFractions<Felt, QuadFelt> {
    build_lookup_fractions(
        &EidosCompressionLookupAir,
        trace,
        None,
        &get_periodic_column_values(),
        &lookup_challenges(),
    )
}

fn lookup_sigma(trace: &RowMajorMatrix<Felt>) -> QuadFelt {
    accumulate_slow(&lookup_fractions(trace)).1
}

fn fractions_at(
    fractions: &LookupFractions<Felt, QuadFelt>,
    row: usize,
    column: usize,
) -> &[(Felt, QuadFelt)] {
    let count_idx = row * fractions.num_columns() + column;
    let start = fractions.counts()[..count_idx].iter().sum::<usize>();
    let end = start + fractions.counts()[count_idx];
    &fractions.fractions()[start..end]
}

fn expected_column_counts(row: usize, mode: EidosCompressionMode) -> [usize; AUX_COLS] {
    let mut counts = [0; AUX_COLS];
    match row_kind(row) {
        RowKind::Ab | RowKind::Cd | RowKind::AbDiag | RowKind::CdDiag => {
            counts[..NARROW_BATCH_COLUMNS].fill(2);
            if row == 0 {
                counts[FOOTER_INPUT_COLUMN] = 1;
            }
        },
        RowKind::Footer(footer) => {
            counts[..9].fill(2);
            counts[11..13].fill(2);
            counts[13] = 1;
            counts[14] = 2;
            counts[16..18].fill(2);
            if footer == FOOTER_ROWS - 1 {
                counts[FOOTER_INPUT_COLUMN] = 2;
            }
            if mode == EidosCompressionMode::AeadXof {
                counts[FOOTER_OUTPUT_COLUMN] = 2;
            }
        },
    }
    counts
}

fn assert_lookup_fraction_counts(mode: EidosCompressionMode, trace_mode: TraceMode) {
    let fractions = lookup_fractions(&felt_trace_matrix(trace_mode));
    assert_eq!(fractions.shape(), EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE);
    assert_eq!(fractions.counts().len(), BLOCK_PERIOD * AUX_COLS);

    for row in 0..BLOCK_PERIOD {
        let expected = expected_column_counts(row, mode);
        let actual = &fractions.counts()[row * AUX_COLS..(row + 1) * AUX_COLS];
        assert_eq!(actual, expected, "row {row}");
    }
}

fn full_cv_fields(row: &EidosCompressionRow) -> [Felt; 9] {
    core::array::from_fn(|idx| {
        if idx == 0 {
            Felt::new_unchecked(row[F_COMPRESSION_CYCLE_ID_COL])
        } else {
            universal_cv_word(|col| Felt::new_unchecked(row[col]), idx - 1)
        }
    })
}

fn set_full_cv_words(row: &mut EidosCompressionRow, words: [u32; 8]) {
    for idx in (NUM_G..8).chain(0..NUM_G) {
        let word = words[idx];
        let at = |col| Felt::new_unchecked(row[col]);
        let target = Felt::from_u32(word);
        let base = super::algebra::cv_word_base(&at, idx);
        let offset = super::algebra::cv_storage_offset::<Felt>(idx);
        let coefficient = cv_storage_coefficient::<Felt>(idx);
        row[F_CV_STORAGE_COLS[idx]] =
            ((target - base + offset) * coefficient.inverse()).as_canonical_u64();
    }
}

fn pack_pair(lo: u32, hi: u32) -> Felt {
    Felt::from_u32(lo) + Felt::from_u64(1 << 32) * Felt::from_u32(hi)
}

fn add_to_raw_cell(cell: &mut u64, delta: Felt) {
    *cell = (Felt::new_unchecked(*cell) + delta).as_canonical_u64();
}

fn compression_link_fields(block: [u32; 16], h: [u32; 8], final_v: [u32; 16]) -> [Felt; 16] {
    let low = low_output(final_v);
    core::array::from_fn(|idx| match idx {
        0..=7 => pack_pair(block[2 * idx], block[2 * idx + 1]),
        8..=11 => {
            let pair = idx - 8;
            pack_pair(h[2 * pair], h[2 * pair + 1])
        },
        12..=15 => {
            let pair = idx - 12;
            pack_pair(low[2 * pair], low[2 * pair + 1] & 0x7fff_ffff)
        },
        _ => unreachable!(),
    })
}

fn aead_input_fields(block: [u32; 16], h: [u32; 8], clk: u64) -> [Felt; 16] {
    core::array::from_fn(|idx| match idx {
        0..=7 => pack_pair(block[2 * idx], block[2 * idx + 1]),
        8..=11 => {
            let pair = idx - 8;
            pack_pair(h[2 * pair], h[2 * pair + 1])
        },
        12 => Felt::new_unchecked(clk),
        13..=15 => Felt::ZERO,
        _ => unreachable!(),
    })
}

#[test]
fn lookup_plan_and_column_liveness_match_the_20_column_design() {
    assert_eq!(EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE, [2; 20]);
    assert_eq!(NARROW_BATCH_COLUMNS, 18);
    assert_eq!(FOOTER_INPUT_COLUMN, 18);
    assert_eq!(FOOTER_OUTPUT_COLUMN, 19);

    let first = lookup_plan(0, EidosCompressionMode::Compression);
    assert_eq!(first.narrow.len(), 36);
    assert_eq!(first.narrow_aux_columns(), 18);
    assert_eq!(first.overlay_relations.len(), 1);
    assert_eq!(first.overlay_relations[0].kind, OverlayRelationKind::FullCv);
    assert_eq!(first.overlay_relations[0].sign, -1);

    let later = lookup_plan(1, EidosCompressionMode::Compression);
    assert_eq!(later.narrow.len(), 36);
    assert!(later.overlay_relations.is_empty());

    let footer0 = lookup_plan(FOOTER_START, EidosCompressionMode::Compression);
    assert_eq!(footer0.narrow.len(), 29);
    assert!(footer0.overlay_relations.is_empty());

    let footer3 = lookup_plan(BLOCK_PERIOD - 1, EidosCompressionMode::Compression);
    assert_eq!(footer3.narrow.len(), 29);
    assert_eq!(footer3.overlay_relations.len(), 2);
    assert_eq!(footer3.overlay_relations[0].kind, OverlayRelationKind::FullCv);
    assert_eq!(footer3.overlay_relations[0].sign, 1);
    assert_eq!(footer3.overlay_relations[1].kind, OverlayRelationKind::CompressionLink);
}

#[test]
fn lookup_plans_follow_periodic_row_families() {
    let columns = get_periodic_column_values();

    for (row, &is_ab_value) in columns[P_IS_AB].iter().enumerate() {
        let plan = lookup_plan(row, EidosCompressionMode::Compression);
        let is_ab = is_ab_value.as_canonical_u64() == 1;
        let is_cd = columns[P_IS_CD][row].as_canonical_u64() == 1;
        let is_footer = columns[P_IS_FOOTER][row].as_canonical_u64() == 1;

        assert_eq!(is_ab, count_narrow(&plan.narrow, NarrowLookupKind::Rot12, -1) > 0);
        assert_eq!(is_cd, count_narrow(&plan.narrow, NarrowLookupKind::Rot7, -1) > 0);
        assert_eq!(is_footer, count_narrow(&plan.narrow, NarrowLookupKind::RangeCheck, -1) > 0);
    }
}

#[test]
fn internal_relations_balance_over_one_cycle() {
    assert_eq!(signed_narrow_total(NarrowLookupKind::MessageWord), 0);

    let full_cv_total: i64 = (0..BLOCK_PERIOD)
        .flat_map(|row| lookup_plan(row, EidosCompressionMode::Compression).overlay_relations)
        .filter(|lookup| lookup.kind == OverlayRelationKind::FullCv)
        .map(|lookup| lookup.sign as i64)
        .sum();
    assert_eq!(full_cv_total, 0);
}

#[test]
fn lookup_air_emits_expected_compression_fraction_counts() {
    assert_lookup_fraction_counts(EidosCompressionMode::Compression, TraceMode::Compression);
}

#[test]
fn lookup_air_emits_expected_aead_fraction_counts() {
    assert_lookup_fraction_counts(EidosCompressionMode::AeadXof, TraceMode::AeadXof { clk: 19 });
}

#[test]
#[cfg(feature = "std")]
fn lookup_degree_annotations_match_air_expressions() {
    let layout = ValidateLayout {
        preprocessed_width: 0,
        trace_width: NUM_COLS,
        num_public_values: 0,
        num_periodic_columns: get_periodic_column_values().len(),
        permutation_width: EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len(),
        num_permutation_challenges: 2,
        num_permutation_values: 1,
    };

    ValidateLookupAir::validate(&EidosCompressionLookupAir, layout)
        .unwrap_or_else(|err| panic!("EidosCompression lookup validation failed: {err}"));
}

#[test]
fn compact_messages_and_derived_rotation_encode_the_original_relations() {
    let cycle_id = 7;
    let challenges = lookup_challenges();
    let trace = generate_trace_block_with_cycle_id(
        test_block(),
        test_h(),
        cycle_id,
        TraceMode::Compression,
    );
    let fractions = lookup_fractions(&felt_matrix_from_rows(&trace.rows));

    for row in 0..FUSED_G_ROWS {
        let step = fused_step_at(row).expect("row is fused");
        for g in 0..NUM_G {
            let expected = challenges.encode(
                BusId::EidosCompressionMessageWord as usize,
                [
                    Felt::from_usize(step.message_indices[g]),
                    Felt::new_unchecked(trace.rows[row][g_msg_word_col(g)]),
                    Felt::new_unchecked(cycle_id),
                ],
            );
            assert!(fractions_at(&fractions, row, 16 + g / 2).contains(&(Felt::ONE, expected)));
        }

        let lhs =
            trace.rows[row][g_bd_rot_slot_col(MISSING_ROTATION_G, MISSING_ROTATION_BYTE, 0)] as u8;
        let rhs =
            trace.rows[row][g_bd_rot_slot_col(MISSING_ROTATION_G, MISSING_ROTATION_BYTE, 1)] as u8;
        let result = eidos_compression_rotation_contribution(
            MISSING_ROTATION_BYTE,
            lhs,
            rhs,
            step.second_rotation,
        );
        let bus = match step.second_rotation {
            12 => eidos_compression_rot12_bus(MISSING_ROTATION_BYTE),
            7 => eidos_compression_rot7_bus(MISSING_ROTATION_BYTE),
            _ => unreachable!(),
        };
        let expected = challenges
            .encode(bus as usize, [Felt::from_u8(lhs), Felt::from_u8(rhs), Felt::from_u32(result)]);
        assert!(fractions_at(&fractions, row, 31 / 2).contains(&(-Felt::ONE, expected)));
    }

    for footer in 0..FOOTER_ROWS {
        let row = FOOTER_START + footer;
        for g in 0..NUM_G {
            let expected = challenges.encode(
                BusId::EidosCompressionMessageWord as usize,
                [
                    Felt::from_usize(footer_message_word_index(footer, g)),
                    Felt::new_unchecked(trace.rows[row][footer_msg_word_col(g)]),
                    Felt::new_unchecked(cycle_id),
                ],
            );
            assert!(
                fractions_at(&fractions, row, 16 + g / 2).contains(&(-Felt::from_u8(7), expected)),
            );
        }
    }
}

#[test]
fn atomic_full_cv_encoding_is_identical_on_first_fused_and_footer_three() {
    let cycle_id = 7;
    let challenges = lookup_challenges();
    let trace = generate_trace_block_with_cycle_id(
        test_block(),
        test_h(),
        cycle_id,
        TraceMode::Compression,
    );
    let fractions = lookup_fractions(&felt_matrix_from_rows(&trace.rows));
    let expected =
        challenges.encode(BusId::EidosCompressionInputCv as usize, full_cv_fields(&trace.rows[0]));

    let first = fractions_at(&fractions, 0, FOOTER_INPUT_COLUMN);
    assert_eq!(first, &[(-Felt::ONE, expected)]);

    let footer_row = BLOCK_PERIOD - 1;
    assert_eq!(full_cv_fields(&trace.rows[footer_row]), full_cv_fields(&trace.rows[0]));
    assert!(
        fractions_at(&fractions, footer_row, FOOTER_INPUT_COLUMN).contains(&(Felt::ONE, expected)),
    );
}

#[test]
fn footer_input_encoding_matches_each_domain_standard_message() {
    let challenges = lookup_challenges();

    let compression = generate_trace_block_with_cycle_id(
        test_block(),
        test_h(),
        0,
        TraceMode::CompressionWithMultiplicity { multiplicity: 3 },
    );
    let compression_fractions = lookup_fractions(&felt_matrix_from_rows(&compression.rows));
    let compression_fields = compression_link_fields(test_block(), test_h(), compression.final_v);
    let expected_compression = HasherCompressionLinkMsg {
        block: core::array::from_fn(|idx| compression_fields[idx]),
        cv_in: core::array::from_fn(|idx| compression_fields[8 + idx]),
        cv_out: core::array::from_fn(|idx| compression_fields[12 + idx]),
    }
    .encode(&challenges);
    assert!(
        fractions_at(&compression_fractions, BLOCK_PERIOD - 1, FOOTER_INPUT_COLUMN)
            .contains(&(-Felt::from_u8(3), expected_compression)),
    );

    let clk = 19;
    let aead =
        generate_trace_block_with_cycle_id(test_block(), test_h(), 0, TraceMode::AeadXof { clk });
    let aead_fractions = lookup_fractions(&felt_matrix_from_rows(&aead.rows));
    let aead_fields = aead_input_fields(test_block(), test_h(), clk);
    let expected_aead = AeadEidosCompressionInputMsg {
        clk: Felt::new_unchecked(clk),
        state: core::array::from_fn(|idx| aead_fields[idx]),
    }
    .encode(&challenges);
    assert!(
        fractions_at(&aead_fractions, BLOCK_PERIOD - 1, FOOTER_INPUT_COLUMN)
            .contains(&(-Felt::ONE, expected_aead)),
    );
    assert_ne!(expected_compression, expected_aead, "bus domains must remain separated");
}

#[test]
fn full_cv_relation_binds_all_eight_raw_words_on_both_emission_rows() {
    let honest = generate_trace_block_with_cycle_id(
        test_block(),
        test_h(),
        0,
        TraceMode::CompressionWithMultiplicity { multiplicity: 0 },
    );
    let honest_sigma = lookup_sigma(&felt_matrix_from_rows(&honest.rows));

    // Zero compression multiplicity disables the external-input fraction. On footer 3 these
    // correction cells are also outside every active narrow slot, so each footer mutation below
    // is detected by the atomic CV relation alone.
    for &row in &[0, BLOCK_PERIOD - 1] {
        for &col in &F_CV_STORAGE_COLS {
            let mut rows = honest.rows;
            rows[row][col] += 1;
            assert_ne!(
                lookup_sigma(&felt_matrix_from_rows(&rows)),
                honest_sigma,
                "full-CV relation omitted row {row}, storage column {col}",
            );
        }
    }
}

#[test]
fn first_row_message_and_valid_carry_mutations_change_lookup_sum() {
    let honest =
        generate_trace_block_with_cycle_id(test_block(), test_h(), 0, TraceMode::Compression);
    let honest_sigma = lookup_sigma(&felt_matrix_from_rows(&honest.rows));

    let mut rows = honest.rows;
    rows[0][g_msg_word_col(0)] += 1;
    assert_ne!(lookup_sigma(&felt_matrix_from_rows(&rows)), honest_sigma);

    for g in 0..NUM_G {
        let mut rows = honest.rows;
        let k3 = rows[0][g_k3_col(g)];
        let alternate = (k3 + 1) % 3;
        rows[0][g_k3_col(g)] = alternate;
        assert_ne!(
            lookup_sigma(&felt_matrix_from_rows(&rows)),
            honest_sigma,
            "atomic CV relation did not anchor reconstructed a[{g}]",
        );
    }
}

#[test]
fn derived_rotation_lookup_binds_the_omitted_next_b_transition() {
    let honest =
        generate_trace_block_with_cycle_id(test_block(), test_h(), 0, TraceMode::Compression);
    let honest_fractions = lookup_fractions(&felt_matrix_from_rows(&honest.rows));
    let honest_sigma = lookup_sigma(&felt_matrix_from_rows(&honest.rows));
    let derived_column = 31 / 2;

    for row in 0..FUSED_G_ROWS - 1 {
        let step = fused_step_at(row).expect("row is fused");
        let next_step = fused_step_at(row + 1).expect("next row is fused");
        let affected_word = step.lane_map[MISSING_ROTATION_G][1];
        let affected_next_g = next_step
            .lane_map
            .iter()
            .position(|lane| lane[1] == affected_word)
            .expect("the affected word remains in a B lane");
        let mut rows = honest.rows;

        add_to_raw_cell(&mut rows[row + 1][g_bd_rot_slot_col(affected_next_g, 0, 0)], Felt::ONE);
        add_to_raw_cell(&mut rows[row + 1][g_msg_word_col(affected_next_g)], -Felt::ONE);
        let mutated = lookup_fractions(&felt_matrix_from_rows(&rows));
        assert_ne!(
            fractions_at(&mutated, row, derived_column),
            fractions_at(&honest_fractions, row, derived_column),
            "the derived tuple did not read the affected next-row B input on row {row}",
        );
        assert_ne!(lookup_sigma(&felt_matrix_from_rows(&rows)), honest_sigma);

        // A second mutation with the opposite byte weight restores the total used by the derived
        // tuple. The main AIR's unaffected lane transition is responsible for rejecting this case.
        let anchored_next_g = (affected_next_g + 1) % NUM_G;
        add_to_raw_cell(&mut rows[row + 1][g_bd_rot_slot_col(anchored_next_g, 0, 0)], -Felt::ONE);
        add_to_raw_cell(&mut rows[row + 1][g_msg_word_col(anchored_next_g)], Felt::ONE);
        let compensated = lookup_fractions(&felt_matrix_from_rows(&rows));
        assert_eq!(
            fractions_at(&compensated, row, derived_column),
            fractions_at(&honest_fractions, row, derived_column),
        );
    }
}

#[test]
fn derived_rotation_cannot_cancel_a_mutated_stored_contribution() {
    let honest =
        generate_trace_block_with_cycle_id(test_block(), test_h(), 0, TraceMode::Compression);
    let honest_fractions = lookup_fractions(&felt_matrix_from_rows(&honest.rows));
    let honest_sigma = lookup_sigma(&felt_matrix_from_rows(&honest.rows));
    let mut rows = honest.rows;

    // Raising both terms by one leaves `next_B_sum - stored_result_sum` unchanged. The omitted
    // tuple therefore stays honest, while the independently looked-up stored tuple must change.
    add_to_raw_cell(&mut rows[0][g_bd_rot_slot_col(0, 0, 2)], Felt::ONE);
    add_to_raw_cell(&mut rows[1][g_bd_rot_slot_col(0, 0, 0)], Felt::ONE);
    add_to_raw_cell(&mut rows[1][g_msg_word_col(0)], -Felt::ONE);
    let mutated = lookup_fractions(&felt_matrix_from_rows(&rows));
    assert_eq!(fractions_at(&mutated, 0, 31 / 2), fractions_at(&honest_fractions, 0, 31 / 2));
    assert_ne!(fractions_at(&mutated, 0, 16 / 2), fractions_at(&honest_fractions, 0, 16 / 2));
    assert_ne!(lookup_sigma(&felt_matrix_from_rows(&rows)), honest_sigma);
}

#[test]
fn derived_rotation_lookup_binds_both_uncommitted_tuple_inputs() {
    let honest =
        generate_trace_block_with_cycle_id(test_block(), test_h(), 0, TraceMode::Compression);
    let honest_fractions = lookup_fractions(&felt_matrix_from_rows(&honest.rows));

    for field in 0..2 {
        let mut rows = honest.rows;
        add_to_raw_cell(
            &mut rows[0][g_bd_rot_slot_col(MISSING_ROTATION_G, MISSING_ROTATION_BYTE, field)],
            Felt::ONE,
        );
        let mutated = lookup_fractions(&felt_matrix_from_rows(&rows));
        assert_ne!(
            fractions_at(&mutated, 0, 31 / 2),
            fractions_at(&honest_fractions, 0, 31 / 2),
            "missing tuple field {field} was not bound",
        );
    }
}

#[test]
fn derived_rotation_rejects_a_compensated_last_fused_footer_mutation() {
    let honest =
        generate_trace_block_with_cycle_id(test_block(), test_h(), 0, TraceMode::Compression);
    let honest_fractions = lookup_fractions(&felt_matrix_from_rows(&honest.rows));
    let honest_sigma = lookup_sigma(&felt_matrix_from_rows(&honest.rows));
    let mut rows = honest.rows;
    let affected_idx = F_FUTURE_W_WORD_INDICES
        .iter()
        .position(|&word_idx| word_idx == 4)
        .expect("footer 0 carries final B word four");

    add_to_raw_cell(&mut rows[FOOTER_START][footer_future_w_col(0, affected_idx)], Felt::ONE);
    let coefficient = cv_storage_coefficient::<Felt>(7);
    add_to_raw_cell(&mut rows[FOOTER_START][F_B_SUM_CORRECTION_COL], coefficient.inverse());

    let mutated = lookup_fractions(&felt_matrix_from_rows(&rows));
    assert_ne!(
        fractions_at(&mutated, FUSED_G_ROWS - 1, 31 / 2),
        fractions_at(&honest_fractions, FUSED_G_ROWS - 1, 31 / 2),
    );
    assert_ne!(lookup_sigma(&felt_matrix_from_rows(&rows)), honest_sigma);
}

#[test]
fn external_input_binds_every_footer_three_payload_field() {
    for mode in [TraceMode::Compression, TraceMode::AeadXof { clk: 19 }] {
        let honest = generate_trace_block_with_cycle_id(test_block(), test_h(), 0, mode);
        let honest_sigma = lookup_sigma(&felt_matrix_from_rows(&honest.rows));
        let row = BLOCK_PERIOD - 1;

        let mut columns = Vec::new();
        columns.extend((0..6).map(|idx| footer_r_col(FOOTER_ROWS - 1, idx)));
        columns.extend((0..4).map(footer_msg_word_col));
        columns.extend(F_CV_STORAGE_COLS);
        match mode {
            TraceMode::Compression => {
                columns.extend((0..4).map(footer_interface_tail_col));
            },
            TraceMode::AeadXof { .. } => columns.push(F_INTERFACE_TAIL0_COL),
            TraceMode::CompressionWithMultiplicity { .. } => unreachable!(),
        }

        columns.sort_unstable();
        columns.dedup();
        for col in columns {
            let mut rows = honest.rows;
            rows[row][col] += 1;
            assert_ne!(
                lookup_sigma(&felt_matrix_from_rows(&rows)),
                honest_sigma,
                "external input omitted mode {mode:?}, column {col}",
            );
        }
    }
}

#[test]
fn aead_output_batch_binds_both_pairs_on_every_footer() {
    let periodic = get_periodic_column_values();
    let challenges = lookup_challenges();
    let honest = generate_trace_block_with_cycle_id(
        test_block(),
        test_h(),
        0,
        TraceMode::AeadXof { clk: 19 },
    );
    let honest_matrix = felt_matrix_from_rows(&honest.rows);
    let honest_fractions = build_lookup_fractions(
        &EidosCompressionLookupAir,
        &honest_matrix,
        None,
        &periodic,
        &challenges,
    );

    for footer in 0..FOOTER_ROWS {
        let row = FOOTER_START + footer;
        for slot in [
            F_HIGH_EVEN_SLOT_BASE,
            F_HIGH_ODD_SLOT_BASE,
            F_OUTPUT_EVEN_SLOT_BASE,
            F_OUTPUT_ODD_SLOT_BASE,
        ] {
            let mut rows = honest.rows;
            rows[row][footer_xor_slot_col(slot, 0)] += 1;
            let mutated = lookup_fractions(&felt_matrix_from_rows(&rows));
            assert_ne!(
                fractions_at(&mutated, row, FOOTER_OUTPUT_COLUMN),
                fractions_at(&honest_fractions, row, FOOTER_OUTPUT_COLUMN),
                "AEAD output slot {slot} was not bound on footer {footer}",
            );
        }
    }
}

#[test]
fn cycle_tag_rejects_two_cycle_atomic_cv_swap() {
    let h_a = test_h();
    let h_b = other_test_h();
    let mut tagged: BTreeMap<[u64; 9], i64> = BTreeMap::new();
    let mut anonymous: BTreeMap<[u64; 8], i64> = BTreeMap::new();

    for (cycle_id, consumed, advertised) in [(0u64, h_b, h_a), (1, h_a, h_b)] {
        let consumed_tagged =
            core::array::from_fn(|idx| if idx == 0 { cycle_id } else { consumed[idx - 1] as u64 });
        let advertised_tagged =
            core::array::from_fn(
                |idx| {
                    if idx == 0 { cycle_id } else { advertised[idx - 1] as u64 }
                },
            );
        *tagged.entry(consumed_tagged).or_default() -= 1;
        *tagged.entry(advertised_tagged).or_default() += 1;
        *anonymous.entry(consumed.map(u64::from)).or_default() -= 1;
        *anonymous.entry(advertised.map(u64::from)).or_default() += 1;
    }

    assert!(anonymous.values().all(|&count| count == 0));
    assert!(tagged.values().any(|&count| count != 0));
}

#[test]
fn actual_lookup_rejects_two_cycle_atomic_cv_swap() {
    let h_a = test_h();
    let h_b = other_test_h();
    let trace_a = generate_trace_block_with_cycle_id(
        test_block(),
        h_a,
        0,
        TraceMode::CompressionWithMultiplicity { multiplicity: 0 },
    );
    let trace_b = generate_trace_block_with_cycle_id(
        other_test_block(),
        h_b,
        1,
        TraceMode::CompressionWithMultiplicity { multiplicity: 0 },
    );
    let mut rows = Vec::from(trace_a.rows);
    rows.extend(trace_b.rows);
    let honest_sigma = lookup_sigma(&felt_matrix_from_rows(&rows));

    set_full_cv_words(&mut rows[BLOCK_PERIOD - 1], h_b);
    set_full_cv_words(&mut rows[2 * BLOCK_PERIOD - 1], h_a);

    assert_ne!(lookup_sigma(&felt_matrix_from_rows(&rows)), honest_sigma);
}

#[test]
fn cycle_tag_rejects_two_cycle_message_swap() {
    let trace_a =
        generate_trace_block_with_cycle_id(test_block(), test_h(), 0, TraceMode::Compression);
    let trace_b = generate_trace_block_with_cycle_id(
        other_test_block(),
        other_test_h(),
        1,
        TraceMode::Compression,
    );
    let mut tagged: BTreeMap<[u64; 3], i64> = BTreeMap::new();
    let mut anonymous: BTreeMap<[u64; 2], i64> = BTreeMap::new();

    for (cycle_id, consumed, advertised) in [(0u64, &trace_b, &trace_a), (1, &trace_a, &trace_b)] {
        for row in 0..FUSED_G_ROWS {
            let step = fused_step_at(row).expect("row is fused");
            for g in 0..NUM_G {
                let payload =
                    [step.message_indices[g] as u64, consumed.rows[row][g_msg_word_col(g)]];
                *tagged.entry([payload[0], payload[1], cycle_id]).or_default() += 1;
                *anonymous.entry(payload).or_default() += 1;
            }
        }
        for footer in 0..FOOTER_ROWS {
            let row = &advertised.rows[FOOTER_START + footer];
            for word_slot in 0..F_MSG_WORD_SLOTS {
                let payload = [
                    footer_message_word_index(footer, word_slot) as u64,
                    row[footer_msg_word_col(word_slot)],
                ];
                *tagged.entry([payload[0], payload[1], cycle_id]).or_default() -= 7;
                *anonymous.entry(payload).or_default() -= 7;
            }
        }
    }

    assert!(anonymous.values().all(|&count| count == 0));
    assert!(tagged.values().any(|&count| count != 0));
}

#[test]
fn actual_lookup_rejects_each_two_cycle_message_swap() {
    let h_a = test_h();
    let h_b = other_test_h();
    let trace_a = generate_trace_block_with_cycle_id(
        test_block(),
        h_a,
        0,
        TraceMode::CompressionWithMultiplicity { multiplicity: 0 },
    );
    let trace_b = generate_trace_block_with_cycle_id(
        other_test_block(),
        h_b,
        1,
        TraceMode::CompressionWithMultiplicity { multiplicity: 0 },
    );
    let honest_rows: Vec<_> = trace_a.rows.into_iter().chain(trace_b.rows).collect();
    let honest_sigma = lookup_sigma(&felt_matrix_from_rows(&honest_rows));

    // Swap one footer-advertised word at a time while leaving each cycle tag in place. Swapping
    // the corresponding range limbs keeps the anonymous range-check multiset balanced. Footer 3
    // overlaps the linear full-CV expression, so restore its correction coordinates to keep the
    // atomic CV relation unchanged and isolate the message-word tag.
    for word_idx in 0..16 {
        let footer = word_idx / F_MSG_WORD_SLOTS;
        let word_slot = word_idx % F_MSG_WORD_SLOTS;
        let row = FOOTER_START + footer;
        let mut rows = honest_rows.clone();
        let (first_cycle, second_cycle) = rows.split_at_mut(BLOCK_PERIOD);

        for col in [
            footer_msg_word_col(word_slot),
            footer_range_slot_col(2 * word_slot, 0),
            footer_range_slot_col(2 * word_slot + 1, 0),
        ] {
            core::mem::swap(&mut first_cycle[row][col], &mut second_cycle[row][col]);
        }

        if footer == FOOTER_ROWS - 1 {
            set_full_cv_words(&mut first_cycle[BLOCK_PERIOD - 1], h_a);
            set_full_cv_words(&mut second_cycle[BLOCK_PERIOD - 1], h_b);
        }

        assert_ne!(
            lookup_sigma(&felt_matrix_from_rows(&rows)),
            honest_sigma,
            "cycle-tagged message word {word_idx} accepted a two-cycle swap",
        );
    }
}

#[test]
fn honest_aux_accumulation_matches_reference_and_inactive_columns_are_zero() {
    for (mode, is_aead) in [(TraceMode::Compression, false), (TraceMode::AeadXof { clk: 19 }, true)]
    {
        let fractions = lookup_fractions(&felt_trace_matrix(mode));
        let (fast_aux, fast_sum) = accumulate(&fractions);
        let (slow_aux, slow_sum) = accumulate_slow(&fractions);
        for (col, slow_column) in slow_aux.iter().enumerate() {
            for (row, &expected) in slow_column.iter().enumerate() {
                assert_eq!(fast_aux.values[row * AUX_COLS + col], expected);
            }
        }
        assert_eq!(fast_sum, slow_sum);

        for row in 0..BLOCK_PERIOD {
            if row != 0 && row != BLOCK_PERIOD - 1 {
                assert_eq!(fast_aux.values[row * AUX_COLS + FOOTER_INPUT_COLUMN], QuadFelt::ZERO);
            }
            if !(is_aead && row >= FOOTER_START) {
                assert_eq!(fast_aux.values[row * AUX_COLS + FOOTER_OUTPUT_COLUMN], QuadFelt::ZERO);
            }
        }
    }
}
