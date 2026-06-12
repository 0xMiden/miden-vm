//! Tests for operation flags.

use alloc::vec::Vec;

use miden_core::{
    Felt, ONE, ZERO,
    operations::{Operation, opcodes},
};
use proptest::prelude::*;

use super::{
    DEGREE_4_OPCODE_ENDS, DEGREE_4_OPCODE_STARTS, DEGREE_5_OPCODE_ENDS, DEGREE_5_OPCODE_STARTS,
    DEGREE_6_OPCODE_ENDS, DEGREE_6_OPCODE_STARTS, DEGREE_7_OPCODE_ENDS, DEGREE_7_OPCODE_STARTS,
    NUM_DEGREE_4_OPS, NUM_DEGREE_5_OPS, NUM_DEGREE_6_OPS, NUM_DEGREE_7_OPS, OpFlags,
    generate_test_row, get_op_bits, get_op_index,
};
// HELPER
// ================================================================================================

// Valid interpolation slots that do not currently map to an `Operation`.
const UNUSED_DEGREE_7_UNARY_ROUTE_OPCODE: u8 = 6;
const UNUSED_DEGREE_7_LEFT_SHIFT_ROUTE_OPCODE: u8 = 47;
const UNUSED_DEGREE_5_ROUTE_OPCODE: u8 = 95;

/// Creates OpFlags from an opcode using a generated test row.
fn op_flags_for_opcode(opcode: usize) -> OpFlags<Felt> {
    let row = generate_test_row(opcode);
    let row_next = generate_test_row(0); // next row defaults to NOOP
    OpFlags::new(&row.decoder, &row.stack, &row_next.decoder)
}

fn naive_flag(bits: &[Felt; 7], opcode: u8) -> Felt {
    let mut acc = ONE;
    for (i, bit) in bits.iter().enumerate() {
        if (opcode >> i) & 1 == 1 {
            acc *= *bit;
        } else {
            acc *= ONE - *bit;
        }
    }
    acc
}

fn naive_op_flags(bits: [Felt; 7]) -> ([Felt; 64], [Felt; 8], [Felt; 16], [Felt; 8]) {
    let mut deg7 = [ZERO; 64];
    let mut deg6 = [ZERO; 8];
    let mut deg5 = [ZERO; 16];
    let mut deg4 = [ZERO; 8];

    for (opcode, slot) in deg7
        .iter_mut()
        .enumerate()
        .take(DEGREE_7_OPCODE_ENDS - DEGREE_7_OPCODE_STARTS + 1)
    {
        *slot = naive_flag(&bits, opcode as u8);
    }

    for opcode in (DEGREE_6_OPCODE_STARTS..=DEGREE_6_OPCODE_ENDS).step_by(2) {
        let idx = get_op_index(opcode as u8);
        deg6[idx] = naive_flag(&bits, opcode as u8);
    }

    for opcode in DEGREE_5_OPCODE_STARTS..=DEGREE_5_OPCODE_ENDS {
        let idx = get_op_index(opcode as u8);
        deg5[idx] = naive_flag(&bits, opcode as u8);
    }

    for opcode in (DEGREE_4_OPCODE_STARTS..=DEGREE_4_OPCODE_ENDS).step_by(4) {
        let idx = get_op_index(opcode as u8);
        deg4[idx] = naive_flag(&bits, opcode as u8);
    }

    (deg7, deg6, deg5, deg4)
}

fn naive_composites(
    bits: [Felt; 7],
    deg6: &[Felt; 8],
    deg5: &[Felt; 16],
    deg4: &[Felt; 8],
    is_loop_end: Felt,
) -> (Felt, Felt, Felt) {
    let bit_2 = bits[2];
    let bit_3 = bits[3];
    let bit_4 = bits[4];
    let bit_5 = bits[5];
    let bit_6 = bits[6];

    let not_4 = ONE - bit_4;
    let not_5 = ONE - bit_5;
    let not_6 = ONE - bit_6;

    let prefix_010 = not_6 * bit_5 * not_4;
    let prefix_011 = not_6 * bit_5 * bit_4;
    let add3_madd_prefix = bit_6 * not_5 * not_4 * bit_3 * bit_2;

    // Under do-while semantics, LOOP (deg5[5]) does not shift the stack — only SPLIT (deg5[4])
    // contributes here.
    let split_flag = deg5[4];
    let shift_left_on_end = deg4[4] * is_loop_end;

    let right_shift_flag = prefix_011 + deg5[11] + deg6[4];
    let left_shift_flag =
        prefix_010 + add3_madd_prefix + split_flag + deg5[8] + deg4[5] + shift_left_on_end;

    let control_flow = deg5[4] + deg5[5] + deg5[6] + deg5[7] // SPAN/JOIN/SPLIT/LOOP
        + deg4[4] + deg4[5] + deg4[6] + deg4[7] // END/REPEAT/RESPAN/HALT
        + deg5[8] + deg5[12] // DYN/DYNCALL
        + deg4[2] + deg4[3]; // SYSCALL/CALL

    (left_shift_flag, right_shift_flag, control_flow)
}

fn valid_opcodes() -> Vec<usize> {
    let mut opcodes = Vec::new();
    opcodes.extend(DEGREE_7_OPCODE_STARTS..=DEGREE_7_OPCODE_ENDS);
    opcodes.extend((DEGREE_6_OPCODE_STARTS..=DEGREE_6_OPCODE_ENDS).step_by(2));
    opcodes.extend(DEGREE_5_OPCODE_STARTS..=DEGREE_5_OPCODE_ENDS);
    opcodes.extend((DEGREE_4_OPCODE_STARTS..=DEGREE_4_OPCODE_ENDS).step_by(4));
    opcodes
}

fn routes_for_opcode(opcode: u8, is_loop_end: bool) -> ([bool; 16], [bool; 16], [bool; 16]) {
    let mut no_shift = [false; 16];
    let mut left_shift = [false; 16];
    let mut right_shift = [false; 16];

    let set = |flags: &mut [bool; 16], range: core::ops::Range<usize>| {
        for idx in range {
            flags[idx] = true;
        }
    };

    match opcode {
        opcodes::NOOP
        | opcodes::U32ASSERT2
        | opcodes::MPVERIFY
        | opcodes::SPAN
        | opcodes::JOIN
        | opcodes::LOOP
        | opcodes::EMIT
        | opcodes::RESPAN
        | opcodes::HALT
        | opcodes::CALL
        | opcodes::SYSCALL
        | opcodes::EVALCIRCUIT => set(&mut no_shift, 0..16),
        opcodes::END if !is_loop_end => set(&mut no_shift, 0..16),
        opcodes::END => set(&mut left_shift, 1..16),

        opcodes::EQZ
        | opcodes::NEG
        | opcodes::INV
        | opcodes::INCR
        | opcodes::NOT
        | UNUSED_DEGREE_7_UNARY_ROUTE_OPCODE
        | opcodes::MLOAD => set(&mut no_shift, 1..16),
        opcodes::SWAP => set(&mut no_shift, 2..16),

        opcodes::MOVUP2 => {
            set(&mut right_shift, 0..2);
            set(&mut no_shift, 3..16);
        },
        opcodes::MOVUP3 => {
            set(&mut right_shift, 0..3);
            set(&mut no_shift, 4..16);
        },
        opcodes::MOVUP4 => {
            set(&mut right_shift, 0..4);
            set(&mut no_shift, 5..16);
        },
        opcodes::MOVUP5 => {
            set(&mut right_shift, 0..5);
            set(&mut no_shift, 6..16);
        },
        opcodes::MOVUP6 => {
            set(&mut right_shift, 0..6);
            set(&mut no_shift, 7..16);
        },
        opcodes::MOVUP7 => {
            set(&mut right_shift, 0..7);
            set(&mut no_shift, 8..16);
        },
        opcodes::MOVUP8 => {
            set(&mut right_shift, 0..8);
            set(&mut no_shift, 9..16);
        },

        opcodes::MOVDN2 => {
            set(&mut left_shift, 1..3);
            set(&mut no_shift, 3..16);
        },
        opcodes::MOVDN3 => {
            set(&mut left_shift, 1..4);
            set(&mut no_shift, 4..16);
        },
        opcodes::MOVDN4 => {
            set(&mut left_shift, 1..5);
            set(&mut no_shift, 5..16);
        },
        opcodes::MOVDN5 => {
            set(&mut left_shift, 1..6);
            set(&mut no_shift, 6..16);
        },
        opcodes::MOVDN6 => {
            set(&mut left_shift, 1..7);
            set(&mut no_shift, 7..16);
        },
        opcodes::MOVDN7 => {
            set(&mut left_shift, 1..8);
            set(&mut no_shift, 8..16);
        },
        opcodes::MOVDN8 => {
            set(&mut left_shift, 1..9);
            set(&mut no_shift, 9..16);
        },

        opcodes::CALLER
        | opcodes::ADVPOPW
        | opcodes::EXPACC
        | opcodes::EXT2MUL
        | opcodes::MRUPDATE => set(&mut no_shift, 4..16),
        opcodes::SWAPW => set(&mut no_shift, 8..16),
        opcodes::SWAPW2 => {
            set(&mut no_shift, 4..8);
            set(&mut no_shift, 12..16);
        },
        opcodes::SWAPW3 => set(&mut no_shift, 4..12),
        opcodes::SWAPDW => {},

        opcodes::ASSERT
        | opcodes::DROP
        | opcodes::MSTORE
        | opcodes::MSTOREW
        | UNUSED_DEGREE_7_LEFT_SHIFT_ROUTE_OPCODE
        | opcodes::SPLIT
        | opcodes::REPEAT
        | opcodes::DYN
        | opcodes::DYNCALL => {
            set(&mut left_shift, 1..16);
        },
        opcodes::EQ
        | opcodes::ADD
        | opcodes::MUL
        | opcodes::AND
        | opcodes::OR
        | opcodes::U32AND
        | opcodes::U32XOR => set(&mut left_shift, 2..16),
        opcodes::CSWAP | opcodes::U32ADD3 | opcodes::U32MADD => set(&mut left_shift, 3..16),
        opcodes::MLOADW => set(&mut left_shift, 5..16),
        opcodes::CSWAPW => set(&mut left_shift, 9..16),

        opcodes::PAD
        | opcodes::DUP0
        | opcodes::DUP1
        | opcodes::DUP2
        | opcodes::DUP3
        | opcodes::DUP4
        | opcodes::DUP5
        | opcodes::DUP6
        | opcodes::DUP7
        | opcodes::DUP9
        | opcodes::DUP11
        | opcodes::DUP13
        | opcodes::DUP15
        | opcodes::ADVPOP
        | opcodes::SDEPTH
        | opcodes::CLK
        | opcodes::PUSH => set(&mut right_shift, 0..16),
        opcodes::U32SPLIT => set(&mut right_shift, 1..16),

        opcodes::U32ADD | opcodes::U32SUB | opcodes::U32MUL | opcodes::U32DIV => {
            set(&mut no_shift, 2..16);
        },
        opcodes::HPERM | opcodes::LOGPRECOMPILE => set(&mut no_shift, 12..16),
        opcodes::MSTREAM | opcodes::PIPE => {
            set(&mut no_shift, 8..12);
            set(&mut no_shift, 13..16);
        },
        opcodes::FRIE2F4
        | opcodes::HORNERBASE
        | opcodes::HORNEREXT
        | opcodes::CRYPTOSTREAM
        | UNUSED_DEGREE_5_ROUTE_OPCODE => {},

        _ => panic!("missing route table entry for opcode {opcode}"),
    }

    (no_shift, left_shift, right_shift)
}

fn aggregate_shifts_for_opcode(opcode: u8, is_loop_end: bool) -> (bool, bool) {
    let left_shift = matches!(
        opcode,
        opcodes::ASSERT
            | opcodes::EQ
            | opcodes::ADD
            | opcodes::MUL
            | opcodes::AND
            | opcodes::OR
            | opcodes::U32AND
            | opcodes::U32XOR
            | opcodes::FRIE2F4
            | opcodes::DROP
            | opcodes::CSWAP
            | opcodes::CSWAPW
            | opcodes::MLOADW
            | opcodes::MSTORE
            | opcodes::MSTOREW
            | UNUSED_DEGREE_7_LEFT_SHIFT_ROUTE_OPCODE
            | opcodes::U32ADD3
            | opcodes::U32MADD
            | opcodes::SPLIT
            | opcodes::REPEAT
            | opcodes::DYN
    ) || (opcode == opcodes::END && is_loop_end);

    let right_shift = matches!(
        opcode,
        opcodes::PAD
            | opcodes::DUP0
            | opcodes::DUP1
            | opcodes::DUP2
            | opcodes::DUP3
            | opcodes::DUP4
            | opcodes::DUP5
            | opcodes::DUP6
            | opcodes::DUP7
            | opcodes::DUP9
            | opcodes::DUP11
            | opcodes::DUP13
            | opcodes::DUP15
            | opcodes::ADVPOP
            | opcodes::SDEPTH
            | opcodes::CLK
            | opcodes::PUSH
            | opcodes::U32SPLIT
    );

    (left_shift, right_shift)
}

// BASIC INDEX TESTS
// ================================================================================================

#[test]
fn test_get_op_index_degree7() {
    // Degree 7 operations have opcodes 0-63, index maps directly
    assert_eq!(get_op_index(opcodes::NOOP), 0);
    assert_eq!(get_op_index(opcodes::SWAP), opcodes::SWAP as usize);
    assert_eq!(get_op_index(opcodes::PAD), opcodes::PAD as usize);
}

#[test]
fn test_get_op_index_degree6() {
    // Degree 6 operations have opcodes 64-79, but only even opcodes are used
    assert_eq!(get_op_index(opcodes::U32ADD), 0);
    assert_eq!(get_op_index(opcodes::U32SUB), 1);
    assert_eq!(get_op_index(opcodes::U32MUL), 2);
    assert_eq!(get_op_index(opcodes::U32DIV), 3);
    assert_eq!(get_op_index(opcodes::U32SPLIT), 4);
    assert_eq!(get_op_index(opcodes::U32ASSERT2), 5);
    assert_eq!(get_op_index(opcodes::U32ADD3), 6);
    assert_eq!(get_op_index(opcodes::U32MADD), 7);
}

#[test]
fn test_get_op_index_degree5() {
    // Degree 5 operations have opcodes 80-95
    assert_eq!(get_op_index(opcodes::HPERM), 0);
    assert_eq!(get_op_index(opcodes::MPVERIFY), 1);
    assert_eq!(get_op_index(opcodes::SPLIT), 4);
    assert_eq!(get_op_index(opcodes::LOOP), 5);
    assert_eq!(get_op_index(opcodes::SPAN), 6);
    assert_eq!(get_op_index(opcodes::JOIN), 7);
    assert_eq!(get_op_index(opcodes::PUSH), 11);
}

#[test]
fn test_get_op_index_degree4() {
    // Degree 4 operations have opcodes 96-127, only every 4th opcode is used
    assert_eq!(get_op_index(opcodes::MRUPDATE), 0);
    assert_eq!(get_op_index(opcodes::CRYPTOSTREAM), 1);
    assert_eq!(get_op_index(opcodes::SYSCALL), 2);
    assert_eq!(get_op_index(opcodes::CALL), 3);
    assert_eq!(get_op_index(opcodes::END), 4);
    assert_eq!(get_op_index(opcodes::REPEAT), 5);
    assert_eq!(get_op_index(opcodes::RESPAN), 6);
    assert_eq!(get_op_index(opcodes::HALT), 7);
}

#[test]
fn test_array_sizes() {
    assert_eq!(NUM_DEGREE_7_OPS, 64);
    assert_eq!(NUM_DEGREE_6_OPS, 8);
    assert_eq!(NUM_DEGREE_5_OPS, 16);
    assert_eq!(NUM_DEGREE_4_OPS, 8);
}

// DEGREE 7 OPERATION FLAG TESTS
// ================================================================================================

/// Tests that for each degree 7 opcode, exactly one flag is set to ONE.
#[test]
fn degree_7_op_flags() {
    for opcode in DEGREE_7_OPCODE_STARTS..=DEGREE_7_OPCODE_ENDS {
        let op_flags = op_flags_for_opcode(opcode);

        // Expected index in the degree 7 flags array
        let expected_idx = get_op_index(opcode as u8);

        // Check degree 7 flags: exactly one should be ONE
        for (i, &flag) in op_flags.degree7_op_flags.iter().enumerate() {
            if i == expected_idx {
                assert_eq!(flag, ONE, "Degree 7 flag {i} should be ONE for opcode {opcode}");
            } else {
                assert_eq!(flag, ZERO, "Degree 7 flag {i} should be ZERO for opcode {opcode}");
            }
        }

        // All other degree flags should be ZERO
        for (i, &flag) in op_flags.degree6_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 6 flag {i} should be ZERO for degree 7 opcode {opcode}");
        }
        for (i, &flag) in op_flags.degree5_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 5 flag {i} should be ZERO for degree 7 opcode {opcode}");
        }
        for (i, &flag) in op_flags.degree4_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 4 flag {i} should be ZERO for degree 7 opcode {opcode}");
        }
    }
}

// DEGREE 6 OPERATION FLAG TESTS
// ================================================================================================

/// Tests that for each degree 6 opcode, exactly one flag is set to ONE.
#[test]
fn degree_6_op_flags() {
    // Degree 6 uses even opcodes only (64, 66, 68, ...)
    for opcode in (DEGREE_6_OPCODE_STARTS..=DEGREE_6_OPCODE_ENDS).step_by(2) {
        let op_flags = op_flags_for_opcode(opcode);

        let expected_idx = get_op_index(opcode as u8);

        // Check degree 6 flags
        for (i, &flag) in op_flags.degree6_op_flags.iter().enumerate() {
            if i == expected_idx {
                assert_eq!(flag, ONE, "Degree 6 flag {i} should be ONE for opcode {opcode}");
            } else {
                assert_eq!(flag, ZERO, "Degree 6 flag {i} should be ZERO for opcode {opcode}");
            }
        }

        // All other degree flags should be ZERO
        for (i, &flag) in op_flags.degree7_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 7 flag {i} should be ZERO for degree 6 opcode {opcode}");
        }
        for (i, &flag) in op_flags.degree5_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 5 flag {i} should be ZERO for degree 6 opcode {opcode}");
        }
        for (i, &flag) in op_flags.degree4_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 4 flag {i} should be ZERO for degree 6 opcode {opcode}");
        }
    }
}

// DEGREE 5 OPERATION FLAG TESTS
// ================================================================================================

/// Tests that for each degree 5 opcode, exactly one flag is set to ONE.
#[test]
fn degree_5_op_flags() {
    for opcode in DEGREE_5_OPCODE_STARTS..=DEGREE_5_OPCODE_ENDS {
        let op_flags = op_flags_for_opcode(opcode);

        let expected_idx = get_op_index(opcode as u8);

        // Check degree 5 flags
        for (i, &flag) in op_flags.degree5_op_flags.iter().enumerate() {
            if i == expected_idx {
                assert_eq!(flag, ONE, "Degree 5 flag {i} should be ONE for opcode {opcode}");
            } else {
                assert_eq!(flag, ZERO, "Degree 5 flag {i} should be ZERO for opcode {opcode}");
            }
        }

        // All other degree flags should be ZERO
        for (i, &flag) in op_flags.degree7_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 7 flag {i} should be ZERO for degree 5 opcode {opcode}");
        }
        for (i, &flag) in op_flags.degree6_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 6 flag {i} should be ZERO for degree 5 opcode {opcode}");
        }
        for (i, &flag) in op_flags.degree4_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 4 flag {i} should be ZERO for degree 5 opcode {opcode}");
        }
    }
}

// NAIVE VS OPTIMIZED COMPOSITE FLAGS
// ================================================================================================

/// Compares optimized op flags and composite flags against naive bit-product computation.
#[test]
fn optimized_flags_match_naive() {
    for opcode in valid_opcodes() {
        let bits = get_op_bits(opcode);
        let (deg7, deg6, deg5, deg4) = naive_op_flags(bits);
        let op_flags = op_flags_for_opcode(opcode);

        for (i, &flag) in op_flags.degree7_op_flags.iter().enumerate() {
            assert_eq!(flag, deg7[i], "degree7 flag mismatch at index {i}");
        }
        for (i, &flag) in op_flags.degree6_op_flags.iter().enumerate() {
            assert_eq!(flag, deg6[i], "degree6 flag mismatch at index {i}");
        }
        for (i, &flag) in op_flags.degree5_op_flags.iter().enumerate() {
            assert_eq!(flag, deg5[i], "degree5 flag mismatch at index {i}");
        }
        for (i, &flag) in op_flags.degree4_op_flags.iter().enumerate() {
            assert_eq!(flag, deg4[i], "degree4 flag mismatch at index {i}");
        }

        let (left_shift_flag, right_shift_flag, control_flow) =
            naive_composites(bits, &deg6, &deg5, &deg4, ZERO);

        assert_eq!(op_flags.left_shift(), left_shift_flag, "left_shift flag mismatch");
        assert_eq!(op_flags.right_shift(), right_shift_flag, "right_shift flag mismatch");
        assert_eq!(op_flags.control_flow(), control_flow, "control_flow flag mismatch");
    }
}

/// Checks the full per-depth stack route table for every valid opcode.
#[test]
fn composite_stack_routes_match_expected_table() {
    for opcode in valid_opcodes() {
        assert_stack_routes(opcode as u8, false);
    }

    assert_stack_routes(opcodes::END, true);
}

fn assert_stack_routes(opcode: u8, is_loop_end: bool) {
    let mut row = generate_test_row(opcode.into());
    if opcode == opcodes::END && is_loop_end {
        row.decoder.hasher_state[5] = ONE;
    }
    let row_next = generate_test_row(0);
    let op_flags: OpFlags<Felt> = OpFlags::new(&row.decoder, &row.stack, &row_next.decoder);
    let (no_shift, left_shift, right_shift) = routes_for_opcode(opcode, is_loop_end);
    let (left_shift_flag, right_shift_flag) = aggregate_shifts_for_opcode(opcode, is_loop_end);

    assert_eq!(
        op_flags.left_shift(),
        if left_shift_flag { ONE } else { ZERO },
        "left_shift aggregate mismatch for opcode {opcode}"
    );
    assert_eq!(
        op_flags.right_shift(),
        if right_shift_flag { ONE } else { ZERO },
        "right_shift aggregate mismatch for opcode {opcode}"
    );

    for idx in 0..16 {
        assert_eq!(
            op_flags.no_shift_at(idx),
            if no_shift[idx] { ONE } else { ZERO },
            "no_shift_at({idx}) mismatch for opcode {opcode}"
        );
        assert_eq!(
            op_flags.left_shift_at(idx),
            if left_shift[idx] { ONE } else { ZERO },
            "left_shift_at({idx}) mismatch for opcode {opcode}"
        );
        assert_eq!(
            op_flags.right_shift_at(idx),
            if right_shift[idx] { ONE } else { ZERO },
            "right_shift_at({idx}) mismatch for opcode {opcode}"
        );
    }
}

// DEGREE 4 OPERATION FLAG TESTS
// ================================================================================================

/// Tests that for each degree 4 opcode, exactly one flag is set to ONE.
#[test]
fn degree_4_op_flags() {
    // Degree 4 uses every 4th opcode (96, 100, 104, ...)
    for opcode in (DEGREE_4_OPCODE_STARTS..=DEGREE_4_OPCODE_ENDS).step_by(4) {
        let op_flags = op_flags_for_opcode(opcode);

        let expected_idx = get_op_index(opcode as u8);

        // Check degree 4 flags
        for (i, &flag) in op_flags.degree4_op_flags.iter().enumerate() {
            if i == expected_idx {
                assert_eq!(flag, ONE, "Degree 4 flag {i} should be ONE for opcode {opcode}");
            } else {
                assert_eq!(flag, ZERO, "Degree 4 flag {i} should be ZERO for opcode {opcode}");
            }
        }

        // All other degree flags should be ZERO
        for (i, &flag) in op_flags.degree7_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 7 flag {i} should be ZERO for degree 4 opcode {opcode}");
        }
        for (i, &flag) in op_flags.degree6_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 6 flag {i} should be ZERO for degree 4 opcode {opcode}");
        }
        for (i, &flag) in op_flags.degree5_op_flags.iter().enumerate() {
            assert_eq!(flag, ZERO, "Degree 5 flag {i} should be ZERO for degree 4 opcode {opcode}");
        }
    }
}

// COMPOSITE FLAG TESTS
// ================================================================================================

/// Tests no_shift composite flags for operations that don't shift the stack.
#[test]
fn composite_no_shift_flags() {
    // Operations where all 16 positions remain unchanged
    let no_shift_opcodes: [u8; 7] = [
        opcodes::MPVERIFY,
        opcodes::SPAN,
        opcodes::HALT,
        opcodes::EMIT,
        opcodes::CALL,
        opcodes::SYSCALL,
        opcodes::EVALCIRCUIT,
    ];

    for opcode in no_shift_opcodes {
        let op_flags = op_flags_for_opcode(opcode.into());

        // All positions should have no_shift = ONE
        for i in 0..16 {
            assert_eq!(
                op_flags.no_shift_at(i),
                ONE,
                "no_shift_at({i}) should be ONE for opcode {opcode:?}"
            );
        }

        // No shifts
        assert_eq!(op_flags.right_shift(), ZERO);
        assert_eq!(op_flags.left_shift(), ZERO);
    }
}

/// Tests composite flags for INCR (no shift from position 1 onwards).
#[test]
fn composite_incr_flags() {
    let op_flags = op_flags_for_opcode(opcodes::INCR.into());

    // Position 0 changes, positions 1-15 don't
    assert_eq!(op_flags.no_shift_at(0), ZERO);
    for i in 1..16 {
        assert_eq!(op_flags.no_shift_at(i), ONE, "no_shift_at({i}) should be ONE for INCR");
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests composite flags for SWAP (no shift from position 2 onwards).
#[test]
fn composite_swap_flags() {
    let op_flags = op_flags_for_opcode(opcodes::SWAP.into());

    assert_eq!(op_flags.no_shift_at(0), ZERO);
    assert_eq!(op_flags.no_shift_at(1), ZERO);
    for i in 2..16 {
        assert_eq!(op_flags.no_shift_at(i), ONE, "no_shift_at({i}) should be ONE for SWAP");
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests HPERM flags (top three words are overwritten, the tail is preserved).
#[test]
fn composite_hperm_flags() {
    let op_flags = op_flags_for_opcode(opcodes::HPERM.into());

    for i in 0..12 {
        assert_eq!(op_flags.no_shift_at(i), ZERO, "no_shift_at({i}) should be ZERO for HPERM");
    }
    for i in 12..16 {
        assert_eq!(op_flags.no_shift_at(i), ONE, "no_shift_at({i}) should be ONE for HPERM");
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests composite flags for LOGPRECOMPILE (hasher output rewrites positions 0..12, no shift from
/// position 12 onwards).
#[test]
fn composite_log_precompile_flags() {
    let op_flags = op_flags_for_opcode(opcodes::LOGPRECOMPILE.into());

    for i in 0..12 {
        assert_eq!(
            op_flags.no_shift_at(i),
            ZERO,
            "no_shift_at({i}) should be ZERO for LOGPRECOMPILE"
        );
    }
    for i in 12..16 {
        assert_eq!(
            op_flags.no_shift_at(i),
            ONE,
            "no_shift_at({i}) should be ONE for LOGPRECOMPILE"
        );
    }

    for i in 0..16 {
        assert_eq!(
            op_flags.left_shift_at(i),
            ZERO,
            "left_shift_at({i}) should be ZERO for LOGPRECOMPILE"
        );
        assert_eq!(
            op_flags.right_shift_at(i),
            ZERO,
            "right_shift_at({i}) should be ZERO for LOGPRECOMPILE"
        );
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests composite shift flags for LOOP operation. Under do-while semantics LOOP reads no stack
/// input, so it is classified as no-shift at every depth.
#[test]
fn composite_loop_no_shift() {
    let op_flags = op_flags_for_opcode(opcodes::LOOP.into());

    for i in 0..16 {
        assert_eq!(op_flags.left_shift_at(i), ZERO, "left_shift_at({i}) should be ZERO for LOOP");
        assert_eq!(op_flags.no_shift_at(i), ONE, "no_shift_at({i}) should be ONE for LOOP");
    }

    assert_eq!(op_flags.left_shift(), ZERO);
    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.control_flow(), ONE);
}

/// Tests left shift composite flags for AND operation (shifts from position 2).
#[test]
fn composite_and_left_shift() {
    let op_flags = op_flags_for_opcode(opcodes::AND.into());

    // AND shifts left from position 2
    assert_eq!(op_flags.left_shift_at(0), ZERO);
    assert_eq!(op_flags.left_shift_at(1), ZERO);
    for i in 2..16 {
        assert_eq!(op_flags.left_shift_at(i), ONE, "left_shift_at({i}) should be ONE for AND");
    }

    assert_eq!(op_flags.left_shift(), ONE);
    assert_eq!(op_flags.right_shift(), ZERO);
}

/// Tests right shift flags for DUP1.
#[test]
fn composite_dup1_right_shift() {
    let op_flags = op_flags_for_opcode(opcodes::DUP1.into());

    // DUP1 shifts the entire stack right
    for i in 0..=15 {
        assert_eq!(op_flags.right_shift_at(i), ONE, "right_shift_at({i}) should be ONE for DUP1");
    }
    for i in 0..16 {
        assert_eq!(op_flags.no_shift_at(i), ZERO);
    }

    assert_eq!(op_flags.right_shift(), ONE);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests right shift flags for PUSH.
#[test]
fn composite_push_right_shift() {
    let op_flags = op_flags_for_opcode(opcodes::PUSH.into());

    // PUSH shifts the entire stack right
    for i in 0..=15 {
        assert_eq!(op_flags.right_shift_at(i), ONE, "right_shift_at({i}) should be ONE for PUSH");
    }

    assert_eq!(op_flags.right_shift(), ONE);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests END operation with and without loop flag.
#[test]
fn composite_end_flags() {
    // END without loop flag: no shift
    let op_flags = op_flags_for_opcode(opcodes::END.into());

    for i in 0..16 {
        assert_eq!(
            op_flags.no_shift_at(i),
            ONE,
            "no_shift_at({i}) should be ONE for END (no loop)"
        );
    }
    assert_eq!(op_flags.left_shift(), ZERO);
    assert_eq!(op_flags.control_flow(), ONE);

    // END with loop flag: left shift (need to modify the row)
    let mut row = generate_test_row(opcodes::END.into());
    row.decoder.hasher_state[5] = ONE; // is_loop flag
    let row_next = generate_test_row(0);
    let op_flags_loop: OpFlags<Felt> = OpFlags::new(&row.decoder, &row.stack, &row_next.decoder);

    for i in 0..16 {
        assert_eq!(
            op_flags_loop.no_shift_at(i),
            ZERO,
            "no_shift_at({i}) should be ZERO for END (with loop)"
        );
    }
    for i in 1..16 {
        assert_eq!(
            op_flags_loop.left_shift_at(i),
            ONE,
            "left_shift_at({i}) should be ONE for END (with loop)"
        );
    }
    assert_eq!(op_flags_loop.left_shift(), ONE);
    assert_eq!(op_flags_loop.control_flow(), ONE);
}

/// Tests SWAPW2 flags (positions 4-7 and 12-15 remain, others swap).
#[test]
fn composite_swapw2_flags() {
    let op_flags = op_flags_for_opcode(opcodes::SWAPW2.into());

    // Positions 4-7 and 12-15 should be no_shift (words that stay in place)
    for i in [0, 1, 2, 3, 8, 9, 10, 11] {
        assert_eq!(op_flags.no_shift_at(i), ZERO, "no_shift_at({i}) should be ZERO for SWAPW2");
    }
    for i in [4, 5, 6, 7, 12, 13, 14, 15] {
        assert_eq!(op_flags.no_shift_at(i), ONE, "no_shift_at({i}) should be ONE for SWAPW2");
    }

    assert_eq!(op_flags.right_shift(), ZERO);
    assert_eq!(op_flags.left_shift(), ZERO);
}

/// Tests control flow flag.
#[test]
fn control_flow_flag() {
    // Control flow operations
    let cf_opcodes: [u8; 10] = [
        opcodes::SPAN,
        opcodes::JOIN,
        opcodes::SPLIT,
        opcodes::LOOP,
        opcodes::END,
        opcodes::REPEAT,
        opcodes::RESPAN,
        opcodes::HALT,
        opcodes::CALL,
        opcodes::SYSCALL,
    ];

    for opcode in cf_opcodes {
        let op_flags = op_flags_for_opcode(opcode.into());
        assert_eq!(op_flags.control_flow(), ONE, "control_flow should be ONE for opcode {opcode}");
    }

    // Non-control flow operations
    let non_cf_ops = [
        Operation::Add,
        Operation::Mul,
        Operation::Swap,
        Operation::Dup0,
        Operation::U32add,
        Operation::HPerm,
        Operation::MpVerify(ZERO),
    ];

    for op in non_cf_ops {
        let op_flags = op_flags_for_opcode(op.op_code().into());
        assert_eq!(op_flags.control_flow(), ZERO, "control_flow should be ZERO for {op:?}");
    }
}

// PROPERTY TESTS
// ================================================================================================

proptest! {
    #[test]
    fn composite_shift_flags_are_binary_and_disjoint(opcode in prop::sample::select(valid_opcodes())) {
        let op_flags = op_flags_for_opcode(opcode);
        for idx in 0usize..16 {
            let no_shift = op_flags.no_shift_at(idx);
            let left_shift = op_flags.left_shift_at(idx);
            let right_shift = op_flags.right_shift_at(idx);

            prop_assert_eq!(no_shift * (no_shift - ONE), ZERO);
            prop_assert_eq!(left_shift * (left_shift - ONE), ZERO);
            prop_assert_eq!(right_shift * (right_shift - ONE), ZERO);

            prop_assert_eq!(no_shift * left_shift, ZERO);
            prop_assert_eq!(no_shift * right_shift, ZERO);
            prop_assert_eq!(left_shift * right_shift, ZERO);
        }
    }
}
