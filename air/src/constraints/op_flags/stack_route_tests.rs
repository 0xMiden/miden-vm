//! Stack route tests for operation flags.

use alloc::vec::Vec;

use miden_core::{Felt, ONE, ZERO, operations::opcodes};

use super::{
    DEGREE_4_OPCODE_ENDS, DEGREE_4_OPCODE_STARTS, DEGREE_5_OPCODE_ENDS, DEGREE_5_OPCODE_STARTS,
    DEGREE_6_OPCODE_ENDS, DEGREE_6_OPCODE_STARTS, DEGREE_7_OPCODE_ENDS, DEGREE_7_OPCODE_STARTS,
    OpFlags, generate_test_row,
};

// Valid interpolation slots that do not currently map to an `Operation`.
const UNUSED_DEGREE_7_UNARY_ROUTE_OPCODE: u8 = 6;
const UNUSED_DEGREE_7_LEFT_SHIFT_ROUTE_OPCODE: u8 = 47;
const UNUSED_DEGREE_5_ROUTE_OPCODE: u8 = 95;

fn valid_route_opcodes() -> Vec<usize> {
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
        opcodes::HORNERBASE | opcodes::HORNEREXT => set(&mut no_shift, 0..14),
        opcodes::FRIE2F4 | opcodes::CRYPTOSTREAM | UNUSED_DEGREE_5_ROUTE_OPCODE => {},

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

#[test]
fn composite_stack_routes_match_expected_table() {
    for opcode in valid_route_opcodes() {
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
