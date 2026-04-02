//! Stack operation constraints.
//!
//! This module enforces ops that directly rewrite visible stack items:
//! PAD, DUP*, CLK, SWAP, MOVUP/MOVDN, SWAPW/SWAPDW, conditional swaps, and small
//! system/io stack ops (ASSERT, CALLER, SDEPTH).
//!
//! Stack shifting is enforced in the general stack constraints; here we only cover explicit
//! rewrites of stack positions for these op groups.

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use crate::{MainTraceRow, MidenAirBuilder, constraints::op_flags::OpFlags};

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
    let s0: AB::Expr = local.stack[0].clone().into();
    let s1: AB::Expr = local.stack[1].clone().into();
    let s2: AB::Expr = local.stack[2].clone().into();
    let s3: AB::Expr = local.stack[3].clone().into();
    let s4: AB::Expr = local.stack[4].clone().into();
    let s5: AB::Expr = local.stack[5].clone().into();
    let s6: AB::Expr = local.stack[6].clone().into();
    let s7: AB::Expr = local.stack[7].clone().into();
    let s8: AB::Expr = local.stack[8].clone().into();
    let s9: AB::Expr = local.stack[9].clone().into();
    let s10: AB::Expr = local.stack[10].clone().into();
    let s11: AB::Expr = local.stack[11].clone().into();
    let s12: AB::Expr = local.stack[12].clone().into();
    let s13: AB::Expr = local.stack[13].clone().into();
    let s14: AB::Expr = local.stack[14].clone().into();
    let s15: AB::Expr = local.stack[15].clone().into();
    let stack_depth: AB::Expr = local.stack[16].clone().into();

    let fn_hash_0: AB::Expr = local.fn_hash[0].clone().into();
    let fn_hash_1: AB::Expr = local.fn_hash[1].clone().into();
    let fn_hash_2: AB::Expr = local.fn_hash[2].clone().into();
    let fn_hash_3: AB::Expr = local.fn_hash[3].clone().into();

    let s0_next: AB::Expr = next.stack[0].clone().into();
    let s1_next: AB::Expr = next.stack[1].clone().into();
    let s2_next: AB::Expr = next.stack[2].clone().into();
    let s3_next: AB::Expr = next.stack[3].clone().into();
    let s4_next: AB::Expr = next.stack[4].clone().into();
    let s5_next: AB::Expr = next.stack[5].clone().into();
    let s6_next: AB::Expr = next.stack[6].clone().into();
    let s7_next: AB::Expr = next.stack[7].clone().into();
    let s8_next: AB::Expr = next.stack[8].clone().into();
    let s9_next: AB::Expr = next.stack[9].clone().into();
    let s10_next: AB::Expr = next.stack[10].clone().into();
    let s11_next: AB::Expr = next.stack[11].clone().into();
    let s12_next: AB::Expr = next.stack[12].clone().into();
    let s13_next: AB::Expr = next.stack[13].clone().into();
    let s14_next: AB::Expr = next.stack[14].clone().into();
    let s15_next: AB::Expr = next.stack[15].clone().into();

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

    // PAD
    builder.when_transition().assert_zero(is_pad * s0_next.clone());

    // DUP*
    builder.when_transition().assert_zero(is_dup * (s0_next.clone() - s0.clone()));
    builder.when_transition().assert_zero(is_dup1 * (s0_next.clone() - s1.clone()));
    builder.when_transition().assert_zero(is_dup2 * (s0_next.clone() - s2.clone()));
    builder.when_transition().assert_zero(is_dup3 * (s0_next.clone() - s3.clone()));
    builder.when_transition().assert_zero(is_dup4 * (s0_next.clone() - s4.clone()));
    builder.when_transition().assert_zero(is_dup5 * (s0_next.clone() - s5.clone()));
    builder.when_transition().assert_zero(is_dup6 * (s0_next.clone() - s6.clone()));
    builder.when_transition().assert_zero(is_dup7 * (s0_next.clone() - s7.clone()));
    builder.when_transition().assert_zero(is_dup9 * (s0_next.clone() - s9.clone()));
    builder
        .when_transition()
        .assert_zero(is_dup11 * (s0_next.clone() - s11.clone()));
    builder
        .when_transition()
        .assert_zero(is_dup13 * (s0_next.clone() - s13.clone()));
    builder
        .when_transition()
        .assert_zero(is_dup15 * (s0_next.clone() - s15.clone()));

    // CLK
    let clk: AB::Expr = local.clk.clone().into();
    builder.when_transition().assert_zero(is_clk * (s0_next.clone() - clk));

    // SWAP
    builder.when_transition().assert_zeros([
        is_swap.clone() * (s0_next.clone() - s1.clone()),
        is_swap * (s1_next.clone() - s0.clone()),
    ]);

    // MOVUP
    builder
        .when_transition()
        .assert_zero(is_movup2 * (s0_next.clone() - s2.clone()));
    builder
        .when_transition()
        .assert_zero(is_movup3 * (s0_next.clone() - s3.clone()));
    builder
        .when_transition()
        .assert_zero(is_movup4 * (s0_next.clone() - s4.clone()));
    builder
        .when_transition()
        .assert_zero(is_movup5 * (s0_next.clone() - s5.clone()));
    builder
        .when_transition()
        .assert_zero(is_movup6 * (s0_next.clone() - s6.clone()));
    builder
        .when_transition()
        .assert_zero(is_movup7 * (s0_next.clone() - s7.clone()));
    builder
        .when_transition()
        .assert_zero(is_movup8 * (s0_next.clone() - s8.clone()));

    // MOVDN
    builder
        .when_transition()
        .assert_zero(is_movdn2 * (s2_next.clone() - s0.clone()));
    builder
        .when_transition()
        .assert_zero(is_movdn3 * (s3_next.clone() - s0.clone()));
    builder
        .when_transition()
        .assert_zero(is_movdn4 * (s4_next.clone() - s0.clone()));
    builder
        .when_transition()
        .assert_zero(is_movdn5 * (s5_next.clone() - s0.clone()));
    builder
        .when_transition()
        .assert_zero(is_movdn6 * (s6_next.clone() - s0.clone()));
    builder
        .when_transition()
        .assert_zero(is_movdn7 * (s7_next.clone() - s0.clone()));
    builder
        .when_transition()
        .assert_zero(is_movdn8 * (s8_next.clone() - s0.clone()));

    // SWAPW
    builder.when_transition().assert_zeros([
        is_swapw.clone() * (s0_next.clone() - s4.clone()),
        is_swapw.clone() * (s1_next.clone() - s5.clone()),
        is_swapw.clone() * (s2_next.clone() - s6.clone()),
        is_swapw.clone() * (s3_next.clone() - s7.clone()),
        is_swapw.clone() * (s4_next.clone() - s0.clone()),
        is_swapw.clone() * (s5_next.clone() - s1.clone()),
        is_swapw.clone() * (s6_next.clone() - s2.clone()),
        is_swapw * (s7_next.clone() - s3.clone()),
    ]);

    // SWAPW2
    builder.when_transition().assert_zeros([
        is_swapw2.clone() * (s0_next.clone() - s8.clone()),
        is_swapw2.clone() * (s1_next.clone() - s9.clone()),
        is_swapw2.clone() * (s2_next.clone() - s10.clone()),
        is_swapw2.clone() * (s3_next.clone() - s11.clone()),
        is_swapw2.clone() * (s8_next.clone() - s0.clone()),
        is_swapw2.clone() * (s9_next.clone() - s1.clone()),
        is_swapw2.clone() * (s10_next.clone() - s2.clone()),
        is_swapw2 * (s11_next.clone() - s3.clone()),
    ]);

    // SWAPW3
    builder.when_transition().assert_zeros([
        is_swapw3.clone() * (s0_next.clone() - s12.clone()),
        is_swapw3.clone() * (s1_next.clone() - s13.clone()),
        is_swapw3.clone() * (s2_next.clone() - s14.clone()),
        is_swapw3.clone() * (s3_next.clone() - s15.clone()),
        is_swapw3.clone() * (s12_next.clone() - s0.clone()),
        is_swapw3.clone() * (s13_next.clone() - s1.clone()),
        is_swapw3.clone() * (s14_next.clone() - s2.clone()),
        is_swapw3 * (s15_next.clone() - s3.clone()),
    ]);

    // SWAPDW
    builder.when_transition().assert_zeros([
        is_swapdw.clone() * (s0_next.clone() - s8.clone()),
        is_swapdw.clone() * (s1_next.clone() - s9.clone()),
        is_swapdw.clone() * (s2_next.clone() - s10.clone()),
        is_swapdw.clone() * (s3_next.clone() - s11.clone()),
        is_swapdw.clone() * (s4_next.clone() - s12.clone()),
        is_swapdw.clone() * (s5_next.clone() - s13.clone()),
        is_swapdw.clone() * (s6_next.clone() - s14.clone()),
        is_swapdw.clone() * (s7_next.clone() - s15.clone()),
        is_swapdw.clone() * (s8_next.clone() - s0.clone()),
        is_swapdw.clone() * (s9_next.clone() - s1.clone()),
        is_swapdw.clone() * (s10_next.clone() - s2.clone()),
        is_swapdw.clone() * (s11_next.clone() - s3.clone()),
        is_swapdw.clone() * (s12_next.clone() - s4.clone()),
        is_swapdw.clone() * (s13_next.clone() - s5.clone()),
        is_swapdw.clone() * (s14_next.clone() - s6.clone()),
        is_swapdw * (s15_next.clone() - s7.clone()),
    ]);

    // CSWAP / CSWAPW: conditional swaps using s0 as the selector.
    let cswap_c = s0.clone();
    let cswap_c_inv = AB::Expr::ONE - cswap_c.clone();

    // Binary constraint for the cswap selector (must be 0 or 1).
    builder.assert_zero(is_cswap.clone() * (cswap_c.clone() * (cswap_c.clone() - AB::Expr::ONE)));

    // Conditional swap equations for the top two stack items.
    builder.when_transition().assert_zeros([
        is_cswap.clone()
            * (s0_next.clone() - (cswap_c.clone() * s2.clone() + cswap_c_inv.clone() * s1.clone())),
        is_cswap
            * (s1_next.clone() - (cswap_c.clone() * s1.clone() + cswap_c_inv.clone() * s2.clone())),
    ]);

    // Binary constraint for the cswapw selector (same selector as cswap).
    builder.assert_zero(is_cswapw.clone() * (cswap_c.clone() * (cswap_c.clone() - AB::Expr::ONE)));

    // Conditional swap equations for the top two words.
    builder.when_transition().assert_zeros([
        is_cswapw.clone()
            * (s0_next.clone() - (cswap_c.clone() * s5.clone() + cswap_c_inv.clone() * s1.clone())),
        is_cswapw.clone()
            * (s1_next.clone() - (cswap_c.clone() * s6.clone() + cswap_c_inv.clone() * s2.clone())),
        is_cswapw.clone()
            * (s2_next.clone() - (cswap_c.clone() * s7.clone() + cswap_c_inv.clone() * s3.clone())),
        is_cswapw.clone()
            * (s3_next.clone() - (cswap_c.clone() * s8.clone() + cswap_c_inv.clone() * s4.clone())),
        is_cswapw.clone()
            * (s4_next.clone() - (cswap_c.clone() * s1.clone() + cswap_c_inv.clone() * s5.clone())),
        is_cswapw.clone()
            * (s5_next.clone() - (cswap_c.clone() * s2.clone() + cswap_c_inv.clone() * s6.clone())),
        is_cswapw.clone()
            * (s6_next.clone() - (cswap_c.clone() * s3.clone() + cswap_c_inv.clone() * s7.clone())),
        is_cswapw
            * (s7_next.clone() - (cswap_c.clone() * s4.clone() + cswap_c_inv.clone() * s8.clone())),
    ]);

    // ASSERT: top element must be 1 (shift handled by stack general).
    builder.assert_zero(is_assert * (s0 - AB::Expr::ONE));

    // CALLER: load fn_hash into the top 4 stack elements.
    builder.when_transition().assert_zeros([
        is_caller.clone() * (s0_next.clone() - fn_hash_0),
        is_caller.clone() * (s1_next.clone() - fn_hash_1),
        is_caller.clone() * (s2_next.clone() - fn_hash_2),
        is_caller * (s3_next.clone() - fn_hash_3),
    ]);

    // SDEPTH: push current stack depth to the top.
    builder.when_transition().assert_zero(is_sdepth * (s0_next - stack_depth));
}
