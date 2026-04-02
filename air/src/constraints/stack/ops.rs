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
    MainTraceRow, MidenAirBuilder,
    constraints::{op_flags::OpFlags, utils::BoolNot},
};

// ENTRY POINT
// ================================================================================================

/// Enforces stack operation constraints for PAD/DUP/CLK/SWAP/MOV/SWAPW/CSWAP.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s0 = local.stack[0];
    let s1 = local.stack[1];
    let s2 = local.stack[2];
    let s3 = local.stack[3];
    let s4 = local.stack[4];
    let s5 = local.stack[5];
    let s6 = local.stack[6];
    let s7 = local.stack[7];
    let s8 = local.stack[8];
    let s9 = local.stack[9];
    let s10 = local.stack[10];
    let s11 = local.stack[11];
    let s12 = local.stack[12];
    let s13 = local.stack[13];
    let s14 = local.stack[14];
    let s15 = local.stack[15];
    let stack_depth = local.stack[16];

    let fn_hash_0 = local.system.fn_hash[0];
    let fn_hash_1 = local.system.fn_hash[1];
    let fn_hash_2 = local.system.fn_hash[2];
    let fn_hash_3 = local.system.fn_hash[3];

    let s0_next = next.stack[0];
    let s1_next = next.stack[1];
    let s2_next = next.stack[2];
    let s3_next = next.stack[3];
    let s4_next = next.stack[4];
    let s5_next = next.stack[5];
    let s6_next = next.stack[6];
    let s7_next = next.stack[7];
    let s8_next = next.stack[8];
    let s9_next = next.stack[9];
    let s10_next = next.stack[10];
    let s11_next = next.stack[11];
    let s12_next = next.stack[12];
    let s13_next = next.stack[13];
    let s14_next = next.stack[14];
    let s15_next = next.stack[15];

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

    let is_cswap = op_flags.cswap();
    let is_cswapw = op_flags.cswapw();
    let is_assert = op_flags.assert_op();
    let is_caller = op_flags.caller();
    let is_sdepth = op_flags.sdepth();

    // All constraints are gated by op flags which vanish on the last row.
    let builder = &mut builder.when_transition();

    // PAD
    builder.when(is_pad).assert_zero(s0_next);

    // DUP*
    builder.when(is_dup).assert_eq(s0_next, s0);
    builder.when(is_dup1).assert_eq(s0_next, s1);
    builder.when(is_dup2).assert_eq(s0_next, s2);
    builder.when(is_dup3).assert_eq(s0_next, s3);
    builder.when(is_dup4).assert_eq(s0_next, s4);
    builder.when(is_dup5).assert_eq(s0_next, s5);
    builder.when(is_dup6).assert_eq(s0_next, s6);
    builder.when(is_dup7).assert_eq(s0_next, s7);
    builder.when(is_dup9).assert_eq(s0_next, s9);
    builder.when(is_dup11).assert_eq(s0_next, s11);
    builder.when(is_dup13).assert_eq(s0_next, s13);
    builder.when(is_dup15).assert_eq(s0_next, s15);

    // CLK
    let clk = local.system.clk;
    builder.when(is_clk).assert_eq(s0_next, clk);

    // SWAP: exchange top two stack elements.
    {
        let builder = &mut builder.when(is_swap);
        builder.assert_eq(s0_next, s1);
        builder.assert_eq(s1_next, s0);
    }

    // MOVUP
    builder.when(is_movup2).assert_eq(s0_next, s2);
    builder.when(is_movup3).assert_eq(s0_next, s3);
    builder.when(is_movup4).assert_eq(s0_next, s4);
    builder.when(is_movup5).assert_eq(s0_next, s5);
    builder.when(is_movup6).assert_eq(s0_next, s6);
    builder.when(is_movup7).assert_eq(s0_next, s7);
    builder.when(is_movup8).assert_eq(s0_next, s8);

    // MOVDN
    builder.when(is_movdn2).assert_eq(s2_next, s0);
    builder.when(is_movdn3).assert_eq(s3_next, s0);
    builder.when(is_movdn4).assert_eq(s4_next, s0);
    builder.when(is_movdn5).assert_eq(s5_next, s0);
    builder.when(is_movdn6).assert_eq(s6_next, s0);
    builder.when(is_movdn7).assert_eq(s7_next, s0);
    builder.when(is_movdn8).assert_eq(s8_next, s0);

    // SWAPW: exchange first and second words.
    {
        let builder = &mut builder.when(is_swapw);
        builder.assert_eq(s0_next, s4);
        builder.assert_eq(s1_next, s5);
        builder.assert_eq(s2_next, s6);
        builder.assert_eq(s3_next, s7);
        builder.assert_eq(s4_next, s0);
        builder.assert_eq(s5_next, s1);
        builder.assert_eq(s6_next, s2);
        builder.assert_eq(s7_next, s3);
    }

    // SWAPW2: exchange first and third words.
    {
        let builder = &mut builder.when(is_swapw2);
        builder.assert_eq(s0_next, s8);
        builder.assert_eq(s1_next, s9);
        builder.assert_eq(s2_next, s10);
        builder.assert_eq(s3_next, s11);
        builder.assert_eq(s8_next, s0);
        builder.assert_eq(s9_next, s1);
        builder.assert_eq(s10_next, s2);
        builder.assert_eq(s11_next, s3);
    }

    // SWAPW3: exchange first and fourth words.
    {
        let builder = &mut builder.when(is_swapw3);
        builder.assert_eq(s0_next, s12);
        builder.assert_eq(s1_next, s13);
        builder.assert_eq(s2_next, s14);
        builder.assert_eq(s3_next, s15);
        builder.assert_eq(s12_next, s0);
        builder.assert_eq(s13_next, s1);
        builder.assert_eq(s14_next, s2);
        builder.assert_eq(s15_next, s3);
    }

    // SWAPDW: exchange first and second double-words.
    {
        let builder = &mut builder.when(is_swapdw);
        builder.assert_eq(s0_next, s8);
        builder.assert_eq(s1_next, s9);
        builder.assert_eq(s2_next, s10);
        builder.assert_eq(s3_next, s11);
        builder.assert_eq(s4_next, s12);
        builder.assert_eq(s5_next, s13);
        builder.assert_eq(s6_next, s14);
        builder.assert_eq(s7_next, s15);
        builder.assert_eq(s8_next, s0);
        builder.assert_eq(s9_next, s1);
        builder.assert_eq(s10_next, s2);
        builder.assert_eq(s11_next, s3);
        builder.assert_eq(s12_next, s4);
        builder.assert_eq(s13_next, s5);
        builder.assert_eq(s14_next, s6);
        builder.assert_eq(s15_next, s7);
    }

    // CSWAP / CSWAPW: conditional swaps using s0 as the selector.
    let cswap_c = s0;
    let cswap_c_inv = cswap_c.into().not();

    // Binary constraint for the cswap selector (must be 0 or 1).
    builder.when(is_cswap.clone()).assert_bool(cswap_c);

    // Conditional swap equations for the top two stack items.
    {
        let builder = &mut builder.when(is_cswap);
        builder.assert_eq(s0_next, cswap_c * s2.into() + cswap_c_inv.clone() * s1.into());
        builder.assert_eq(s1_next, cswap_c * s1.into() + cswap_c_inv.clone() * s2.into());
    }

    // Binary constraint for the cswapw selector (same selector as cswap).
    builder.when(is_cswapw.clone()).assert_bool(cswap_c);

    // Conditional swap equations for the top two words.
    {
        let builder = &mut builder.when(is_cswapw);
        builder.assert_eq(s0_next, cswap_c * s5.into() + cswap_c_inv.clone() * s1.into());
        builder.assert_eq(s1_next, cswap_c * s6.into() + cswap_c_inv.clone() * s2.into());
        builder.assert_eq(s2_next, cswap_c * s7.into() + cswap_c_inv.clone() * s3.into());
        builder.assert_eq(s3_next, cswap_c * s8.into() + cswap_c_inv.clone() * s4.into());
        builder.assert_eq(s4_next, cswap_c * s1.into() + cswap_c_inv.clone() * s5.into());
        builder.assert_eq(s5_next, cswap_c * s2.into() + cswap_c_inv.clone() * s6.into());
        builder.assert_eq(s6_next, cswap_c * s3.into() + cswap_c_inv.clone() * s7.into());
        builder.assert_eq(s7_next, cswap_c * s4.into() + cswap_c_inv * s8.into());
    }

    // ASSERT: top element must be 1 (shift handled by stack general).
    builder.when(is_assert).assert_one(s0);

    // CALLER: load fn_hash into the top 4 stack elements.
    {
        let builder = &mut builder.when(is_caller);
        builder.assert_eq(s0_next, fn_hash_0);
        builder.assert_eq(s1_next, fn_hash_1);
        builder.assert_eq(s2_next, fn_hash_2);
        builder.assert_eq(s3_next, fn_hash_3);
    }

    // SDEPTH: push current stack depth to the top.
    builder.when(is_sdepth).assert_eq(s0_next, stack_depth);
}
