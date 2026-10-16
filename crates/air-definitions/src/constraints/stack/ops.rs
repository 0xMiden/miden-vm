//! Stack operation constraints.
//!
//! This module enforces ops that directly rewrite visible stack items:
//! PAD, DUP*, CLK, SWAP, MOVUP/MOVDN, SWAPW/SWAPDW, conditional swaps, and small
//! system/io stack ops (ASSERT, CALLER, SDEPTH).
//!
//! Stack shifting is enforced in the general stack constraints; here we only cover explicit
//! rewrites of stack positions for these op groups.

use miden_crypto::stark::air::AirBuilder;

use crate::{
    CoreCols, MidenAirBuilder,
    constraints::{constants::F_8, op_flags::OpFlags, utils::BoolNot},
};

// ENTRY POINT
// ================================================================================================

/// Enforces stack operation constraints for PAD/DUP/CLK/SWAP/MOV/SWAPW/CSWAP.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &CoreCols<AB::Var>,
    next: &CoreCols<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s0 = local.stack.get(0);
    let s1 = local.stack.get(1);
    let s2 = local.stack.get(2);
    let s3 = local.stack.get(3);
    let s4 = local.stack.get(4);
    let s5 = local.stack.get(5);
    let s6 = local.stack.get(6);
    let s7 = local.stack.get(7);
    let s8 = local.stack.get(8);
    let s9 = local.stack.get(9);
    let s10 = local.stack.get(10);
    let s11 = local.stack.get(11);
    let s12 = local.stack.get(12);
    let s13 = local.stack.get(13);
    let s14 = local.stack.get(14);
    let s15 = local.stack.get(15);
    let stack_depth = local.stack.b0;

    let fn_hash_0 = local.system.fn_hash[0];
    let fn_hash_1 = local.system.fn_hash[1];
    let fn_hash_2 = local.system.fn_hash[2];
    let fn_hash_3 = local.system.fn_hash[3];

    let s0_next = next.stack.get(0);
    let s1_next = next.stack.get(1);
    let s2_next = next.stack.get(2);
    let s3_next = next.stack.get(3);
    let s4_next = next.stack.get(4);
    let s5_next = next.stack.get(5);
    let s6_next = next.stack.get(6);
    let s7_next = next.stack.get(7);
    let s8_next = next.stack.get(8);
    let s9_next = next.stack.get(9);
    let s10_next = next.stack.get(10);
    let s11_next = next.stack.get(11);
    let s12_next = next.stack.get(12);
    let s13_next = next.stack.get(13);
    let s14_next = next.stack.get(14);
    let s15_next = next.stack.get(15);

    let is_pad = op_flags.pad();
    let is_dup = op_flags.dup();
    let is_dup1 = op_flags.dup1();
    let is_dup2 = op_flags.dup2();
    let is_dup3 = op_flags.dup3();
    let is_dup4 = op_flags.dup4();
    let is_dup5 = op_flags.dup5();
    let is_dup6 = op_flags.dup6();
    let is_dup7 = op_flags.dup7();
    let is_dup9 = op_flags.dup9();
    let is_dup11 = op_flags.dup11();
    let is_dup13 = op_flags.dup13();
    let is_dup15 = op_flags.dup15();

    let is_clk = op_flags.clk();

    let is_swap = op_flags.swap();
    let is_movup2 = op_flags.movup2();
    let is_movup3 = op_flags.movup3();
    let is_movup4 = op_flags.movup4();
    let is_movup5 = op_flags.movup5();
    let is_movup6 = op_flags.movup6();
    let is_movup7 = op_flags.movup7();
    let is_movup8 = op_flags.movup8();

    let is_movdn2 = op_flags.movdn2();
    let is_movdn3 = op_flags.movdn3();
    let is_movdn4 = op_flags.movdn4();
    let is_movdn5 = op_flags.movdn5();
    let is_movdn6 = op_flags.movdn6();
    let is_movdn7 = op_flags.movdn7();
    let is_movdn8 = op_flags.movdn8();

    let is_swapw = op_flags.swapw();
    let is_swapw2 = op_flags.swapw2();
    let is_swapw3 = op_flags.swapw3();
    let is_swapdw = op_flags.swapdw();
    let is_mstream_or_pipe = op_flags.mstream() + op_flags.pipe();

    let is_cswap = op_flags.cswap();
    let is_cswapw = op_flags.cswapw();
    let is_assert = op_flags.assert_op();
    let is_caller = op_flags.caller();
    let is_sdepth = op_flags.sdepth();

    let clk = local.system.clk;

    // ASSERT: top element must be 1 (shift handled by stack general).
    builder.when(is_assert).assert_one(s0);

    // CSWAP / CSWAPW: conditional swaps using s0 as the selector.
    let cswap_c = s0;
    let cswap_c_inv = cswap_c.into().not();

    // Binary constraint for the swap selector (must be 0 or 1). CSWAP and CSWAPW are
    // distinct opcodes, so at most one gate is live and the shared check is exact.
    builder.when(is_cswap.clone() + is_cswapw.clone()).assert_bool(cswap_c);

    // Each block below folds, for one next-row stack position, all ops that explicitly
    // rewrite that position into a single constraint:
    //
    //   next[i] * flag_sum = Σ_op flag_op * source_op
    //
    // Op flags are one-hot by construction: each is a product of selectors over the
    // same 7 binary op bits for a distinct opcode, so at most one term is live on any
    // row and the folded constraint enforces exactly the live op's transition.

    // Position 0: PAD (pushes 0, so it contributes only to flag_sum), DUP*, CLK, SWAP,
    // MOVUP*, SWAPW/SWAPW2/SWAPW3/SWAPDW, CSWAP, CSWAPW, CALLER, SDEPTH.
    {
        let flag_sum = is_pad
            + is_dup.clone()
            + is_dup1.clone()
            + is_dup2.clone()
            + is_dup3.clone()
            + is_dup4.clone()
            + is_dup5.clone()
            + is_dup6.clone()
            + is_dup7.clone()
            + is_dup9.clone()
            + is_dup11.clone()
            + is_dup13.clone()
            + is_dup15.clone()
            + is_clk.clone()
            + is_swap.clone()
            + is_movup2.clone()
            + is_movup3.clone()
            + is_movup4.clone()
            + is_movup5.clone()
            + is_movup6.clone()
            + is_movup7.clone()
            + is_movup8.clone()
            + is_swapw.clone()
            + is_swapw2.clone()
            + is_swapw3.clone()
            + is_swapdw.clone()
            + is_cswap.clone()
            + is_cswapw.clone()
            + is_caller.clone()
            + is_sdepth.clone();
        let expected = is_dup * s0.into()
            + is_dup1 * s1.into()
            + is_dup2 * s2.into()
            + is_dup3 * s3.into()
            + is_dup4 * s4.into()
            + is_dup5 * s5.into()
            + is_dup6 * s6.into()
            + is_dup7 * s7.into()
            + is_dup9 * s9.into()
            + is_dup11 * s11.into()
            + is_dup13 * s13.into()
            + is_dup15 * s15.into()
            + is_clk * clk.into()
            + is_swap.clone() * s1.into()
            + is_movup2 * s2.into()
            + is_movup3 * s3.into()
            + is_movup4 * s4.into()
            + is_movup5 * s5.into()
            + is_movup6 * s6.into()
            + is_movup7 * s7.into()
            + is_movup8 * s8.into()
            + is_swapw.clone() * s4.into()
            + is_swapw2.clone() * s8.into()
            + is_swapw3.clone() * s12.into()
            + is_swapdw.clone() * s8.into()
            + is_cswap.clone() * (cswap_c * s2.into() + cswap_c_inv.clone() * s1.into())
            + is_cswapw.clone() * (cswap_c * s5.into() + cswap_c_inv.clone() * s1.into())
            + is_caller.clone() * fn_hash_0.into()
            + is_sdepth * stack_depth.into();
        builder.assert_zero(s0_next * flag_sum - expected);
    }

    // Position 1: SWAP, SWAPW/SWAPW2/SWAPW3/SWAPDW, CSWAP, CSWAPW, CALLER.
    {
        let flag_sum = is_swap.clone()
            + is_swapw.clone()
            + is_swapw2.clone()
            + is_swapw3.clone()
            + is_swapdw.clone()
            + is_cswap.clone()
            + is_cswapw.clone()
            + is_caller.clone();
        let expected = is_swap * s0.into()
            + is_swapw.clone() * s5.into()
            + is_swapw2.clone() * s9.into()
            + is_swapw3.clone() * s13.into()
            + is_swapdw.clone() * s9.into()
            + is_cswap * (cswap_c * s1.into() + cswap_c_inv.clone() * s2.into())
            + is_cswapw.clone() * (cswap_c * s6.into() + cswap_c_inv.clone() * s2.into())
            + is_caller.clone() * fn_hash_1.into();
        builder.assert_zero(s1_next * flag_sum - expected);
    }

    // Position 2: MOVDN2, SWAPW/SWAPW2/SWAPW3/SWAPDW, CSWAPW, CALLER.
    {
        let flag_sum = is_movdn2.clone()
            + is_swapw.clone()
            + is_swapw2.clone()
            + is_swapw3.clone()
            + is_swapdw.clone()
            + is_cswapw.clone()
            + is_caller.clone();
        let expected = is_movdn2 * s0.into()
            + is_swapw.clone() * s6.into()
            + is_swapw2.clone() * s10.into()
            + is_swapw3.clone() * s14.into()
            + is_swapdw.clone() * s10.into()
            + is_cswapw.clone() * (cswap_c * s7.into() + cswap_c_inv.clone() * s3.into())
            + is_caller.clone() * fn_hash_2.into();
        builder.assert_zero(s2_next * flag_sum - expected);
    }

    // Position 3: MOVDN3, SWAPW/SWAPW2/SWAPW3/SWAPDW, CSWAPW, CALLER.
    {
        let flag_sum = is_movdn3.clone()
            + is_swapw.clone()
            + is_swapw2.clone()
            + is_swapw3.clone()
            + is_swapdw.clone()
            + is_cswapw.clone()
            + is_caller.clone();
        let expected = is_movdn3 * s0.into()
            + is_swapw.clone() * s7.into()
            + is_swapw2.clone() * s11.into()
            + is_swapw3.clone() * s15.into()
            + is_swapdw.clone() * s11.into()
            + is_cswapw.clone() * (cswap_c * s8.into() + cswap_c_inv.clone() * s4.into())
            + is_caller * fn_hash_3.into();
        builder.assert_zero(s3_next * flag_sum - expected);
    }

    // Position 4: MOVDN4, SWAPW, SWAPDW, CSWAPW.
    {
        let flag_sum = is_movdn4.clone() + is_swapw.clone() + is_swapdw.clone() + is_cswapw.clone();
        let expected = is_movdn4 * s0.into()
            + is_swapw.clone() * s0.into()
            + is_swapdw.clone() * s12.into()
            + is_cswapw.clone() * (cswap_c * s1.into() + cswap_c_inv.clone() * s5.into());
        builder.assert_zero(s4_next * flag_sum - expected);
    }

    // Position 5: MOVDN5, SWAPW, SWAPDW, CSWAPW.
    {
        let flag_sum = is_movdn5.clone() + is_swapw.clone() + is_swapdw.clone() + is_cswapw.clone();
        let expected = is_movdn5 * s0.into()
            + is_swapw.clone() * s1.into()
            + is_swapdw.clone() * s13.into()
            + is_cswapw.clone() * (cswap_c * s2.into() + cswap_c_inv.clone() * s6.into());
        builder.assert_zero(s5_next * flag_sum - expected);
    }

    // Position 6: MOVDN6, SWAPW, SWAPDW, CSWAPW.
    {
        let flag_sum = is_movdn6.clone() + is_swapw.clone() + is_swapdw.clone() + is_cswapw.clone();
        let expected = is_movdn6 * s0.into()
            + is_swapw.clone() * s2.into()
            + is_swapdw.clone() * s14.into()
            + is_cswapw.clone() * (cswap_c * s3.into() + cswap_c_inv.clone() * s7.into());
        builder.assert_zero(s6_next * flag_sum - expected);
    }

    // Position 7: MOVDN7, SWAPW, SWAPDW, CSWAPW.
    {
        let flag_sum = is_movdn7.clone() + is_swapw.clone() + is_swapdw.clone() + is_cswapw.clone();
        let expected = is_movdn7 * s0.into()
            + is_swapw * s3.into()
            + is_swapdw.clone() * s15.into()
            + is_cswapw * (cswap_c * s4.into() + cswap_c_inv * s8.into());
        builder.assert_zero(s7_next * flag_sum - expected);
    }

    // Position 8: MOVDN8, SWAPW2, SWAPDW.
    {
        let flag_sum = is_movdn8.clone() + is_swapw2.clone() + is_swapdw.clone();
        let expected =
            is_movdn8 * s0.into() + is_swapw2.clone() * s0.into() + is_swapdw.clone() * s0.into();
        builder.assert_zero(s8_next * flag_sum - expected);
    }

    // Position 9: SWAPW2, SWAPDW.
    {
        let flag_sum = is_swapw2.clone() + is_swapdw.clone();
        let expected = is_swapw2.clone() * s1.into() + is_swapdw.clone() * s1.into();
        builder.assert_zero(s9_next * flag_sum - expected);
    }

    // Position 10: SWAPW2, SWAPDW.
    {
        let flag_sum = is_swapw2.clone() + is_swapdw.clone();
        let expected = is_swapw2.clone() * s2.into() + is_swapdw.clone() * s2.into();
        builder.assert_zero(s10_next * flag_sum - expected);
    }

    // Position 11: SWAPW2, SWAPDW.
    {
        let flag_sum = is_swapw2.clone() + is_swapdw.clone();
        let expected = is_swapw2 * s3.into() + is_swapdw.clone() * s3.into();
        builder.assert_zero(s11_next * flag_sum - expected);
    }

    // Position 12: SWAPW3, SWAPDW, MSTREAM/PIPE (two-word memory cursor advances by 8).
    {
        let flag_sum = is_swapw3.clone() + is_swapdw.clone() + is_mstream_or_pipe.clone();
        let expected = is_swapw3.clone() * s0.into()
            + is_swapdw.clone() * s4.into()
            + is_mstream_or_pipe * (s12.into() + F_8);
        builder.assert_zero(s12_next * flag_sum - expected);
    }

    // Position 13: SWAPW3, SWAPDW.
    {
        let flag_sum = is_swapw3.clone() + is_swapdw.clone();
        let expected = is_swapw3.clone() * s1.into() + is_swapdw.clone() * s5.into();
        builder.assert_zero(s13_next * flag_sum - expected);
    }

    // Position 14: SWAPW3, SWAPDW.
    {
        let flag_sum = is_swapw3.clone() + is_swapdw.clone();
        let expected = is_swapw3.clone() * s2.into() + is_swapdw.clone() * s6.into();
        builder.assert_zero(s14_next * flag_sum - expected);
    }

    // Position 15: SWAPW3, SWAPDW.
    {
        let flag_sum = is_swapw3.clone() + is_swapdw.clone();
        let expected = is_swapw3 * s3.into() + is_swapdw * s7.into();
        builder.assert_zero(s15_next * flag_sum - expected);
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        format,
        string::{String, ToString},
        vec::Vec,
    };

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
        operations::opcodes,
    };

    use super::enforce_main;
    use crate::constraints::{
        columns::CoreCols,
        op_flags::{OpFlags, generate_test_row},
        stack::test_utils::ConstraintEvalBuilder,
    };

    fn eval_stack_ops(local: &CoreCols<Felt>, next: &CoreCols<Felt>) -> Vec<QuadFelt> {
        let mut builder = ConstraintEvalBuilder::new();
        let op_flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
        enforce_main(&mut builder, local, next, &op_flags);
        builder.evaluations
    }

    /// Distinct sentinel value for stack position `i`, so a misrouted source position is
    /// always detectable.
    fn sentinel(i: usize) -> Felt {
        Felt::new_unchecked(100 + i as u64)
    }

    fn base_setup(local: &mut CoreCols<Felt>) {
        for i in 0..16 {
            local.stack.top[i] = sentinel(i);
        }
    }

    fn setup_clk(local: &mut CoreCols<Felt>) {
        base_setup(local);
        local.system.clk = Felt::new_unchecked(555);
    }

    fn setup_caller(local: &mut CoreCols<Felt>) {
        base_setup(local);
        local.system.fn_hash = [
            Felt::new_unchecked(31),
            Felt::new_unchecked(32),
            Felt::new_unchecked(33),
            Felt::new_unchecked(34),
        ];
    }

    fn setup_sdepth(local: &mut CoreCols<Felt>) {
        base_setup(local);
        local.stack.b0 = Felt::new_unchecked(7);
    }

    fn setup_cswap_false(local: &mut CoreCols<Felt>) {
        base_setup(local);
        local.stack.top[0] = Felt::ZERO;
    }

    fn setup_cswap_true(local: &mut CoreCols<Felt>) {
        base_setup(local);
        local.stack.top[0] = Felt::ONE;
    }

    /// One test case for the position-folded stack op constraints: an opcode, how to
    /// populate the local row, and the next-row `(position, value)` pairs dictated by the
    /// op's ISA semantics (see `processor::execution::operations::stack_ops` /
    /// `sys_ops`) — independent of the folded constraint's own arithmetic in
    /// `enforce_main`.
    struct StackOpCase {
        name: String,
        opcode: u8,
        setup: fn(&mut CoreCols<Felt>),
        expected: Vec<(usize, Felt)>,
    }

    fn stack_op_cases() -> Vec<StackOpCase> {
        let s = sentinel;

        // DUP8/10/12/14 have no dedicated opcode (their opcode slots are reused by other
        // ops), so the indices below are not contiguous.
        const DUP_INDICES: [usize; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 9, 11, 13, 15];
        const DUP_OPCODES: [u8; 12] = [
            opcodes::DUP0,
            opcodes::DUP1,
            opcodes::DUP2,
            opcodes::DUP3,
            opcodes::DUP4,
            opcodes::DUP5,
            opcodes::DUP6,
            opcodes::DUP7,
            opcodes::DUP9,
            opcodes::DUP11,
            opcodes::DUP13,
            opcodes::DUP15,
        ];
        const MOVUP_OPCODES: [u8; 7] = [
            opcodes::MOVUP2,
            opcodes::MOVUP3,
            opcodes::MOVUP4,
            opcodes::MOVUP5,
            opcodes::MOVUP6,
            opcodes::MOVUP7,
            opcodes::MOVUP8,
        ];
        const MOVDN_OPCODES: [u8; 7] = [
            opcodes::MOVDN2,
            opcodes::MOVDN3,
            opcodes::MOVDN4,
            opcodes::MOVDN5,
            opcodes::MOVDN6,
            opcodes::MOVDN7,
            opcodes::MOVDN8,
        ];

        let mut cases = Vec::from([StackOpCase {
            name: "PAD".to_string(),
            opcode: opcodes::PAD,
            setup: base_setup,
            expected: Vec::from([(0, Felt::ZERO)]),
        }]);

        cases.extend(DUP_INDICES.into_iter().zip(DUP_OPCODES).map(|(i, opcode)| StackOpCase {
            name: format!("DUP{i}"),
            opcode,
            setup: base_setup,
            expected: Vec::from([(0, s(i))]),
        }));

        cases.extend([
            StackOpCase {
                name: "CLK".to_string(),
                opcode: opcodes::CLK,
                setup: setup_clk,
                expected: Vec::from([(0, Felt::new_unchecked(555))]),
            },
            StackOpCase {
                name: "SWAP".to_string(),
                opcode: opcodes::SWAP,
                setup: base_setup,
                expected: Vec::from([(0, s(1)), (1, s(0))]),
            },
        ]);

        cases.extend((2usize..=8).zip(MOVUP_OPCODES).map(|(i, opcode)| StackOpCase {
            name: format!("MOVUP{i}"),
            opcode,
            setup: base_setup,
            expected: Vec::from([(0, s(i))]),
        }));

        cases.extend((2usize..=8).zip(MOVDN_OPCODES).map(|(i, opcode)| StackOpCase {
            name: format!("MOVDN{i}"),
            opcode,
            setup: base_setup,
            expected: Vec::from([(i, s(0))]),
        }));

        cases.extend([
            StackOpCase {
                name: "SWAPW".to_string(),
                opcode: opcodes::SWAPW,
                setup: base_setup,
                expected: Vec::from([
                    (0, s(4)),
                    (1, s(5)),
                    (2, s(6)),
                    (3, s(7)),
                    (4, s(0)),
                    (5, s(1)),
                    (6, s(2)),
                    (7, s(3)),
                ]),
            },
            StackOpCase {
                name: "SWAPW2".to_string(),
                opcode: opcodes::SWAPW2,
                setup: base_setup,
                expected: Vec::from([
                    (0, s(8)),
                    (1, s(9)),
                    (2, s(10)),
                    (3, s(11)),
                    (8, s(0)),
                    (9, s(1)),
                    (10, s(2)),
                    (11, s(3)),
                ]),
            },
            StackOpCase {
                name: "SWAPW3".to_string(),
                opcode: opcodes::SWAPW3,
                setup: base_setup,
                expected: Vec::from([
                    (0, s(12)),
                    (1, s(13)),
                    (2, s(14)),
                    (3, s(15)),
                    (12, s(0)),
                    (13, s(1)),
                    (14, s(2)),
                    (15, s(3)),
                ]),
            },
            StackOpCase {
                name: "SWAPDW".to_string(),
                opcode: opcodes::SWAPDW,
                setup: base_setup,
                expected: Vec::from([
                    (0, s(8)),
                    (1, s(9)),
                    (2, s(10)),
                    (3, s(11)),
                    (4, s(12)),
                    (5, s(13)),
                    (6, s(14)),
                    (7, s(15)),
                    (8, s(0)),
                    (9, s(1)),
                    (10, s(2)),
                    (11, s(3)),
                    (12, s(4)),
                    (13, s(5)),
                    (14, s(6)),
                    (15, s(7)),
                ]),
            },
            StackOpCase {
                name: "CSWAP (selector = 0)".to_string(),
                opcode: opcodes::CSWAP,
                setup: setup_cswap_false,
                expected: Vec::from([(0, s(1)), (1, s(2))]),
            },
            StackOpCase {
                name: "CSWAP (selector = 1)".to_string(),
                opcode: opcodes::CSWAP,
                setup: setup_cswap_true,
                expected: Vec::from([(0, s(2)), (1, s(1))]),
            },
            StackOpCase {
                name: "CSWAPW (selector = 0)".to_string(),
                opcode: opcodes::CSWAPW,
                setup: setup_cswap_false,
                expected: Vec::from([
                    (0, s(1)),
                    (1, s(2)),
                    (2, s(3)),
                    (3, s(4)),
                    (4, s(5)),
                    (5, s(6)),
                    (6, s(7)),
                    (7, s(8)),
                ]),
            },
            StackOpCase {
                name: "CSWAPW (selector = 1)".to_string(),
                opcode: opcodes::CSWAPW,
                setup: setup_cswap_true,
                expected: Vec::from([
                    (0, s(5)),
                    (1, s(6)),
                    (2, s(7)),
                    (3, s(8)),
                    (4, s(1)),
                    (5, s(2)),
                    (6, s(3)),
                    (7, s(4)),
                ]),
            },
            StackOpCase {
                name: "CALLER".to_string(),
                opcode: opcodes::CALLER,
                setup: setup_caller,
                expected: Vec::from([
                    (0, Felt::new_unchecked(31)),
                    (1, Felt::new_unchecked(32)),
                    (2, Felt::new_unchecked(33)),
                    (3, Felt::new_unchecked(34)),
                ]),
            },
            StackOpCase {
                name: "SDEPTH".to_string(),
                opcode: opcodes::SDEPTH,
                setup: setup_sdepth,
                expected: Vec::from([(0, Felt::new_unchecked(7))]),
            },
            StackOpCase {
                name: "MSTREAM".to_string(),
                opcode: opcodes::MSTREAM,
                setup: base_setup,
                expected: Vec::from([(12, s(12) + Felt::new_unchecked(8))]),
            },
            StackOpCase {
                name: "PIPE".to_string(),
                opcode: opcodes::PIPE,
                setup: base_setup,
                expected: Vec::from([(12, s(12) + Felt::new_unchecked(8))]),
            },
        ]);

        cases
    }

    /// For every opcode folded into the shared per-position constraints in `enforce_main`,
    /// builds the next-stack row its ISA semantics dictate and verifies the folded
    /// constraint (a) accepts that row and (b) rejects a one-off mutation of each position
    /// the opcode is expected to rewrite.
    #[test]
    fn stack_ops_fold_accepts_and_rejects_each_written_position() {
        for case in stack_op_cases() {
            let mut local = generate_test_row(case.opcode.into());
            (case.setup)(&mut local);

            let mut next = generate_test_row(0);
            for &(pos, value) in &case.expected {
                next.stack.top[pos] = value;
            }

            let evaluations = eval_stack_ops(&local, &next);
            assert!(
                evaluations.iter().all(|value| *value == QuadFelt::ZERO),
                "{}: correct next-row rewrite should be accepted",
                case.name
            );

            for &(pos, _) in &case.expected {
                let mut mutated = next.clone();
                mutated.stack.top[pos] += Felt::ONE;

                let evaluations = eval_stack_ops(&local, &mutated);
                assert!(
                    evaluations.iter().any(|value| *value != QuadFelt::ZERO),
                    "{}: mutating written position {} should be rejected",
                    case.name,
                    pos
                );
            }
        }
    }
}
