use miden_core::Felt;

use super::{
    layout::*,
    model::{execute_fused_rounds, initial_working_state, low_output, xof_lanes},
    schedule::fused_step_at,
    trace::{
        BlakeGFeltRow, TraceMode, generate_felt_trace_block, generate_trace_block,
        rot_contribution, write_felt_trace_block,
    },
    views::{FooterOverlayRow, FusedGRow, LookupSlot},
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

fn assert_slot(slot: LookupSlot<'_, u64>, expected: [u64; 3]) {
    assert_eq!(*slot.field0, expected[0]);
    assert_eq!(*slot.field1, expected[1]);
    assert_eq!(*slot.field2, expected[2]);
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
    let mut rows = [sentinel; NUM_COLS * (BLOCK_PERIOD + 1)];
    let (rows, _) = rows.as_chunks_mut::<NUM_COLS>();
    let rows: &mut [BlakeGFeltRow] = rows;

    let final_v = write_felt_trace_block(rows, test_block(), test_h(), TraceMode::Compression);
    let expected = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

    assert_eq!(final_v, expected.final_v);
    assert_eq!(&rows[..BLOCK_PERIOD], &expected.rows);
    assert!(rows[BLOCK_PERIOD].iter().all(|&cell| cell == sentinel));
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

            assert_eq!(*row.a(g), a as u64);
            assert_eq!(*row.c(g), c as u64);
            assert_eq!(*row.k3_bit0(g), k3 & 1);
            assert_eq!(*row.k3_bit1(g), k3 >> 1);
            assert_eq!(*row.k2(g), k2);
            assert_slot(row.msg_slot(g), [step.message_indices[g] as u64, msg as u64, 0]);

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
                assert_slot(
                    row.bd_rot_slot(g, byte),
                    [
                        b_bytes[byte] as u64,
                        c_new_bytes[byte] as u64,
                        rot_contribution(
                            byte,
                            b_bytes[byte],
                            c_new_bytes[byte],
                            step.second_rotation,
                        ) as u64,
                    ],
                );
            }

            v[ai] = a_new;
            v[di] = d_new;
            v[ci] = c_new;
            v[bi] = b_new;
        }
    }

    assert_eq!(v, trace.final_v);
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
    let c_values: [u64; 4] = core::array::from_fn(|i| pack_pair(h[2 * i], h[2 * i + 1]));
    let d_values: [u64; 4] =
        core::array::from_fn(|i| pack_pair(low[2 * i], low[2 * i + 1] & 0x7fff_ffff));

    for footer in 0..FOOTER_ROWS {
        let row = FooterOverlayRow::new(&trace.rows[FOOTER_START + footer]);
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
        assert_slot(row.hin_slot(), [footer as u64, h[even] as u64, h[odd] as u64]);

        for word_slot in 0..F_MSG_WORD_SLOTS {
            let msg_idx = footer_message_word_index(footer, word_slot);
            assert_slot(row.msg_word_slot(word_slot), [msg_idx as u64, block[msg_idx] as u64, 0]);
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

        for idx in 0..8 {
            let expected = if idx <= 2 * footer + 1 { r_values[idx] } else { 0 };
            assert_eq!(*row.r(idx), expected);
        }
        for idx in 0..4 {
            let expected_c = if idx <= footer { c_values[idx] } else { 0 };
            let expected_d = if idx <= footer { d_values[idx] } else { 0 };
            assert_eq!(*row.c(idx), expected_c);
            assert_eq!(*row.d(idx), expected_d);
        }

        assert_future_w_queue(&row, footer, trace.final_v);
        assert_eq!(*row.compression_multiplicity(), 0);
        assert_eq!(*row.mode(), 1);
        assert_eq!(*row.clk(), clk);
    }
}

#[test]
fn compression_footer_rows_carry_request_multiplicity() {
    let trace = generate_trace_block(
        test_block(),
        test_h(),
        TraceMode::CompressionWithMultiplicity { multiplicity: 3 },
    );

    for footer in 0..FOOTER_ROWS {
        let row = FooterOverlayRow::new(&trace.rows[FOOTER_START + footer]);
        assert_eq!(*row.compression_multiplicity(), 3);
        assert_eq!(*row.mode(), 0);
        assert_eq!(*row.clk(), 0);
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

    for idx in 0..F_FUTURE_W_COLS {
        let expected = future_w.get(idx).map(|&word_idx| v[word_idx] as u64).unwrap_or(0);
        assert_eq!(*row.future_w(idx), expected);
    }
}

fn pack_pair(lo: u32, hi: u32) -> u64 {
    lo as u64 + ((hi as u64) << 32)
}
