use miden_core::{Felt, field::PrimeField64};

use super::{
    algebra::{cv_storage_coefficient, missing_rotation_result, universal_cv_word},
    layout::*,
    model::{execute_fused_rounds, initial_working_state, low_output, xof_lanes},
    schedule::fused_step_at,
    trace::{
        CV_STORAGE_COEFFICIENT_INVERSES, EidosCompressionFeltRow, EidosCompressionRow, TraceMode,
        generate_felt_trace_block, generate_trace_block, generate_trace_block_with_cycle_id,
        retag_felt_trace_block_cycle_id, write_felt_trace_block,
    },
    views::{FooterOverlayRow, FusedGRow, LookupSlot},
};
use crate::constraints::and8_lookup::columns::eidos_compression_rotation_contribution;

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

fn assert_slot(slot: LookupSlot<'_, u64>, expected: [u64; 3]) {
    assert_eq!(*slot.field0, expected[0]);
    assert_eq!(*slot.field1, expected[1]);
    assert_eq!(*slot.field2, expected[2]);
}

fn cv_word(row: &EidosCompressionRow, idx: usize) -> u64 {
    universal_cv_word(|col| Felt::new_unchecked(row[col]), idx).as_canonical_u64()
}

#[test]
fn cv_storage_coefficient_inverses_are_exact() {
    for (idx, inverse) in CV_STORAGE_COEFFICIENT_INVERSES.into_iter().enumerate() {
        assert_eq!(cv_storage_coefficient::<Felt>(idx) * inverse, Felt::ONE);
    }
}

#[test]
fn trace_writer_final_state_matches_execution_model() {
    let trace = generate_trace_block(test_block(), test_h(), TraceMode::Compression);

    assert_eq!(trace.final_v, execute_fused_rounds(test_block(), test_h()));
}

#[test]
fn felt_trace_writer_matches_raw_trace() {
    let raw = generate_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 99 });
    let felt = generate_felt_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 99 });

    assert_eq!(felt.final_v, raw.final_v);
    for row in 0..BLOCK_PERIOD {
        for col in 0..NUM_COLS {
            assert_eq!(felt.rows[row][col].as_canonical_u64(), raw.rows[row][col]);
        }
    }
}

#[test]
fn felt_trace_writer_fills_one_block_prefix() {
    let sentinel = Felt::new_unchecked(7);
    let mut rows = vec![sentinel; NUM_COLS * (BLOCK_PERIOD + 1)];
    let (rows, _) = rows.as_chunks_mut::<NUM_COLS>();
    let rows: &mut [EidosCompressionFeltRow] = rows;

    let final_v = write_felt_trace_block(rows, test_block(), test_h(), 0, TraceMode::Compression);
    let expected = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

    assert_eq!(final_v, expected.final_v);
    assert_eq!(&rows[..BLOCK_PERIOD], &expected.rows);
    assert!(rows[BLOCK_PERIOD].iter().all(|&cell| cell == sentinel));
}

#[test]
fn trace_writer_materializes_compression_cycle_id_on_internal_bus_rows() {
    let cycle_id = 7;
    let trace = generate_trace_block_with_cycle_id(
        test_block(),
        test_h(),
        cycle_id,
        TraceMode::Compression,
    );

    for row in 0..BLOCK_PERIOD {
        let row = &trace.rows[row];
        assert_eq!(row[F_COMPRESSION_CYCLE_ID_COL], cycle_id);
    }
    for footer in 0..FOOTER_ROWS {
        let row = &trace.rows[FOOTER_START + footer];
        for (idx, &word) in test_h().iter().enumerate().take(2 * footer + 2) {
            assert_eq!(cv_word(row, idx), word as u64);
        }
    }
}

#[test]
fn trace_writer_accepts_largest_canonical_cycle_id() {
    let max_cycle_id = Felt::ORDER_U64 - 1;
    let trace = generate_trace_block_with_cycle_id(
        test_block(),
        test_h(),
        max_cycle_id,
        TraceMode::Compression,
    );

    assert_eq!(
        trace.rows[FOOTER_START + FOOTER_ROWS - 1][F_COMPRESSION_CYCLE_ID_COL],
        max_cycle_id,
    );
}

#[test]
#[should_panic(expected = "compression-cycle ID must be a canonical field element")]
fn trace_writer_rejects_noncanonical_cycle_id() {
    let invalid_cycle_id = Felt::ORDER_U64;
    let _ = generate_trace_block_with_cycle_id(
        test_block(),
        test_h(),
        invalid_cycle_id,
        TraceMode::Compression,
    );
}

#[test]
#[should_panic(expected = "trace metadata must be a canonical field element")]
fn trace_writer_rejects_noncanonical_multiplicity() {
    let _ = generate_trace_block(
        test_block(),
        test_h(),
        TraceMode::CompressionWithMultiplicity { multiplicity: Felt::ORDER_U64 },
    );
}

#[test]
#[should_panic(expected = "packed Eidos compression input must be a canonical field element")]
fn trace_writer_rejects_noncanonical_packed_input() {
    let mut block = test_block();
    block[0] = 1;
    block[1] = u32::MAX;
    let _ = generate_trace_block(block, test_h(), TraceMode::Compression);
}

#[test]
fn fused_g_rows_materialize_expected_slots() {
    let block = test_block();
    let mut v = initial_working_state(test_h());
    let trace = generate_trace_block(block, test_h(), TraceMode::Compression);

    for row_idx in 0..FUSED_G_ROWS {
        let step = fused_step_at(row_idx).unwrap();
        let row = FusedGRow::new(&trace.rows[row_idx]);

        for g in 0..NUM_G {
            let [ai, bi, ci, di] = step.lane_map[g];
            let a = v[ai];
            let b = v[bi];
            let c = v[ci];
            let d = v[di];
            let msg = block[step.message_indices[g]];

            let sum3 = a as u64 + b as u64 + msg as u64;
            let a_new = sum3 as u32;
            let k3 = sum3 >> 32;
            let d_new = (d ^ a_new).rotate_right(step.first_rotation);

            let sum2 = c as u64 + d_new as u64;
            let c_new = sum2 as u32;
            let k2 = sum2 >> 32;
            let b_new = (b ^ c_new).rotate_right(step.second_rotation);

            assert_eq!(*row.k3(g), k3);
            assert_eq!(*row.k2(g), k2);
            assert_eq!(*row.msg_word(g), msg as u64);
            assert_eq!(*row.compression_cycle_id(), 0);

            let d_bytes = d.to_le_bytes();
            let a_new_bytes = a_new.to_le_bytes();
            let b_bytes = b.to_le_bytes();
            let c_new_bytes = c_new.to_le_bytes();
            for byte in 0..BYTES_PER_WORD {
                assert_slot(
                    row.ac_byte_slot(g, byte),
                    [
                        d_bytes[byte] as u64,
                        a_new_bytes[byte] as u64,
                        (d_bytes[byte] & a_new_bytes[byte]) as u64,
                    ],
                );
                let expected_result = eidos_compression_rotation_contribution(
                    byte,
                    b_bytes[byte],
                    c_new_bytes[byte],
                    step.second_rotation,
                ) as u64;
                if g_bd_rot_result_col(g, byte).is_some() {
                    assert_slot(
                        row.bd_rot_slot(g, byte),
                        [b_bytes[byte] as u64, c_new_bytes[byte] as u64, expected_result],
                    );
                } else {
                    let inputs = row.bd_rot_inputs(g, byte);
                    assert_eq!(*inputs.field0, b_bytes[byte] as u64);
                    assert_eq!(*inputs.field1, c_new_bytes[byte] as u64);
                    let next = &trace.rows[row_idx + 1];
                    let derived = missing_rotation_result(
                        |col| Felt::new_unchecked(trace.rows[row_idx][col]),
                        |col| Felt::new_unchecked(next[col]),
                    );
                    assert_eq!(derived.as_canonical_u64(), expected_result);
                }
            }

            let actual_a_new = packed_slot_bytes(&row, g, true, 1);
            let actual_b = packed_slot_bytes(&row, g, false, 0);
            let actual_c_new = packed_slot_bytes(&row, g, false, 1);
            let actual_d = packed_slot_bytes(&row, g, true, 0);
            let actual_d_new = (actual_d ^ actual_a_new).rotate_right(step.first_rotation);
            let actual_k3 = *row.k3(g);
            let reconstructed_a =
                actual_a_new as u64 + (actual_k3 << 32) - actual_b as u64 - *row.msg_word(g);
            let reconstructed_c = actual_c_new as u64 + (*row.k2(g) << 32) - actual_d_new as u64;
            assert_eq!(reconstructed_a, a as u64);
            assert_eq!(reconstructed_c, c as u64);

            v[ai] = a_new;
            v[di] = d_new;
            v[ci] = c_new;
            v[bi] = b_new;
        }
    }

    assert_eq!(v, trace.final_v);
}

fn packed_slot_bytes(row: &FusedGRow<'_, u64>, g: usize, ac_slot: bool, field: usize) -> u32 {
    let bytes = core::array::from_fn(|byte| {
        if ac_slot {
            let slot = row.ac_byte_slot(g, byte);
            match field {
                0 => *slot.field0 as u8,
                1 => *slot.field1 as u8,
                2 => *slot.field2 as u8,
                _ => unreachable!("lookup-slot field must be in 0..3"),
            }
        } else {
            let slot = row.bd_rot_inputs(g, byte);
            match field {
                0 => *slot.field0 as u8,
                1 => *slot.field1 as u8,
                _ => unreachable!("rotation-input field must be zero or one"),
            }
        }
    });
    u32::from_le_bytes(bytes)
}

#[test]
fn footer_overlay_rows_materialize_expected_surface() {
    let block = test_block();
    let h = test_h();
    let clk = 12345;
    let trace = generate_trace_block(block, h, TraceMode::AeadXof { clk });
    let low = low_output(trace.final_v);
    let xof = xof_lanes(trace.final_v, h);
    let r_values: [u64; 8] = core::array::from_fn(|i| pack_pair(block[2 * i], block[2 * i + 1]));
    for footer in 0..FOOTER_ROWS {
        let row = FooterOverlayRow::new(&trace.rows[FOOTER_START + footer], footer);
        let even = 2 * footer;
        let odd = even + 1;

        assert_footer_xor_slots(&row, footer, h, trace.final_v, low, xof);
        assert_slot(
            row.top_bit_slot(),
            [
                low[odd].to_le_bytes()[3] as u64,
                F_TOP_BIT_MASK as u64,
                (low[odd].to_le_bytes()[3] & F_TOP_BIT_MASK) as u64,
            ],
        );
        for word_slot in 0..F_MSG_WORD_SLOTS {
            let msg_idx = footer_message_word_index(footer, word_slot);
            assert_eq!(*row.msg_word(word_slot), block[msg_idx] as u64);
        }
        for limb in 0..F_RANGE_SLOTS {
            let msg_idx = footer_range_limb_word_index(footer, limb);
            let word = block[msg_idx];
            let value = if footer_range_limb_is_high(limb) {
                word >> 16
            } else {
                word & 0xffff
            };
            assert_slot(row.range_slot(limb), [value as u64, 0, 0]);
        }

        for (idx, &r_value) in r_values.iter().enumerate().take(2 * footer) {
            assert_eq!(*row.carried_r(idx), r_value);
        }
        for pair in 0..2 {
            let lo = *row.msg_word(2 * pair) as u32;
            let hi = *row.msg_word(2 * pair + 1) as u32;
            assert_eq!(pack_pair(lo, hi), r_values[2 * footer + pair]);
        }
        for (idx, &word) in h.iter().enumerate().take(2 * footer + 2) {
            assert_eq!(cv_word(&trace.rows[FOOTER_START + footer], idx), word as u64);
        }

        assert_future_w_queue(&row, footer, trace.final_v);
        assert_eq!(*row.compression_multiplicity(), 0);
        assert_eq!(*row.mode(), 1);
        assert_eq!(*row.interface_tail(0), clk);
        for idx in 1..4 {
            assert_eq!(*row.interface_tail(idx), 0);
        }
    }
}

#[test]
fn compression_footer_rows_carry_request_multiplicity() {
    let trace = generate_trace_block(
        test_block(),
        test_h(),
        TraceMode::CompressionWithMultiplicity { multiplicity: 3 },
    );

    let low = low_output(trace.final_v);
    let d_values: [u64; 4] =
        core::array::from_fn(|i| pack_pair(low[2 * i], low[2 * i + 1] & 0x7fff_ffff));
    for footer in 0..FOOTER_ROWS {
        let row = FooterOverlayRow::new(&trace.rows[FOOTER_START + footer], footer);
        assert_eq!(*row.compression_multiplicity(), 3);
        assert_eq!(*row.mode(), 0);
        for (idx, &value) in d_values.iter().enumerate() {
            assert_eq!(*row.interface_tail(idx), value);
        }
    }
}

#[test]
fn padding_retag_preserves_full_cv_coordinates() {
    let h = test_h();
    let mut trace = generate_felt_trace_block(test_block(), h, TraceMode::Compression);

    retag_felt_trace_block_cycle_id(&mut trace.rows, 17);

    for row in 0..FUSED_G_ROWS {
        assert_eq!(trace.rows[row][F_COMPRESSION_CYCLE_ID_COL], Felt::from_u8(17));
    }
    for footer in 0..FOOTER_ROWS {
        let row = &trace.rows[FOOTER_START + footer];
        assert_eq!(row[F_COMPRESSION_CYCLE_ID_COL], Felt::from_u8(17));
        for (idx, &word) in h.iter().enumerate().take(2 * footer + 2) {
            let actual = universal_cv_word(|col| row[col], idx);
            assert_eq!(actual, Felt::from_u32(word), "footer {footer}, CV word {idx}");
        }
    }
}

fn assert_footer_xor_slots(
    row: &FooterOverlayRow<'_, u64>,
    footer: usize,
    h: [u32; 8],
    v: [u32; 16],
    low: [u32; 8],
    xof: [u32; 16],
) {
    let even = 2 * footer;
    let odd = even + 1;
    let words = [
        (v[8 + even], h[even], xof[8 + even], F_HIGH_EVEN_SLOT_BASE),
        (v[8 + odd], h[odd], xof[8 + odd], F_HIGH_ODD_SLOT_BASE),
        (v[even], v[8 + even], low[even], F_OUTPUT_EVEN_SLOT_BASE),
        (v[odd], v[8 + odd], low[odd], F_OUTPUT_ODD_SLOT_BASE),
    ];

    for (lhs, rhs, _xor, slot_base) in words {
        let lhs_bytes = lhs.to_le_bytes();
        let rhs_bytes = rhs.to_le_bytes();
        for byte in 0..BYTES_PER_WORD {
            assert_slot(
                row.xor_slot(slot_base + byte),
                [
                    lhs_bytes[byte] as u64,
                    rhs_bytes[byte] as u64,
                    (lhs_bytes[byte] & rhs_bytes[byte]) as u64,
                ],
            );
        }
    }
}

fn assert_future_w_queue(row: &FooterOverlayRow<'_, u64>, footer: usize, v: [u32; 16]) {
    let future_w: &[usize] = match footer {
        0 => &[2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15],
        1 => &[4, 5, 12, 13, 6, 7, 14, 15],
        2 => &[6, 7, 14, 15],
        3 => &[],
        _ => unreachable!(),
    };

    for (idx, &word_idx) in future_w.iter().enumerate() {
        assert_eq!(*row.future_w(idx), v[word_idx] as u64);
    }
}

fn pack_pair(lo: u32, hi: u32) -> u64 {
    lo as u64 + ((hi as u64) << 32)
}
