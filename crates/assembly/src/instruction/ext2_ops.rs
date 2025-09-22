use miden_core::{Operation::*, sys_events::SystemEvent::Ext2Inv};

use super::BasicBlockBuilder;
use crate::{Report, ZERO};

/// Given a stack in the following initial configuration [b1, b0, a1, a0, ...] where a = (a0, a1)
/// and b = (b0, b1) represent elements in the extension field of degree 2, this series of
/// operations outputs the result c = (c1, c0) where c1 = a1 + b1 and c0 = a0 + b0.
///
/// This operation takes 5 VM cycles.
pub fn ext2_add(block_builder: &mut BasicBlockBuilder) {
    #[rustfmt::skip]
    let ops = [
        Swap,           // [b0, b1, a1, a0, ...]
        MovUp3,         // [a0, b0, b1, a1, ...]
        Add,            // [a0+b0, b1, a1, ...]
        MovDn2,         // [b1, a1, a0+b0, ...]
        Add             // [b1+a1, a0+b0, ...]
    ];
    block_builder.push_ops(ops);
}

/// Given a stack in the following initial configuration [b1, b0, a1, a0, ...] where a = (a0, a1)
/// and b = (b0, b1) represent elements in the extension field of degree 2, this series of
/// operations outputs the result c = (c1, c0) where c1 = a1 - b1 and c0 = a0 - b0.
///
/// This operation takes 7 VM cycles.
pub fn ext2_sub(block_builder: &mut BasicBlockBuilder) {
    #[rustfmt::skip]
    let ops = [
        Neg,        // [-b1, b0, a1, a0, ...]
        Swap,       // [b0, -b1, a1, a0, ...]
        Neg,        // [-b0, -b1, a1, a0, ...]
        MovUp3,     // [a0, -b0, -b1, a1, ...]
        Add,        // [a0-b0, -b1, a1, ...]
        MovDn2,     // [-b1, a1, a0-b0, ...]
        Add         // [a1-b1, a0-b0, ...]
    ];
    block_builder.push_ops(ops);
}

/// Given a stack with initial configuration given by [b1, b0, a1, a0, ...] where a = (a0, a1) and
/// b = (b0, b1) represent elements in the extension field of degree 2, this series of operations
/// outputs the product c = (c1, c0) where c0 = a0b0 - 2(a1b1) and c1 = (a0 + a1)(b0 + b1) - a0b0
///
/// This operation takes 3 VM cycles.
pub fn ext2_mul(block_builder: &mut BasicBlockBuilder) {
    block_builder.push_ops([Ext2Mul, Drop, Drop]);
}

/// Given a stack in the following initial configuration [b1, b0, a1, a0, ...] where a = (a0, a1)
/// and b = (b0, b1) represent elements in the extension field of degree 2, this series of
/// operations outputs the result c = (c1, c0) where c = a * b^-1.
///
/// This operation takes 11 VM cycles.
pub fn ext2_div(block_builder: &mut BasicBlockBuilder) {
    block_builder.push_system_event(Ext2Inv);
    #[rustfmt::skip]
    let ops = [
        AdvPop,         // [b0', b1, b0, a1, a0, ...]
        AdvPop,         // [b1', b0', b1, b0, a1, a0, ...]
        Ext2Mul,        // [b1', b0', 0, 1, a1, a0, ...]
        MovUp2,         // [0, b1', b0', 1, a1, a0, ...]
        Eqz,            // [1, b1', b0', 1, a1, a0, ...]
        Assert(ZERO),   // [b1', b0', 1, a1, a0, ...]
        MovUp2,         // [1, b1', b0', a1, a0, ...]
        Assert(ZERO),   // [b1', b0', a1, a0, ...]
        Ext2Mul,        // [b1', b0', a1*b1', a0*b0', ...]
        Drop,           // [b0', a1*b1', a0*b0'...]
        Drop            // [a1*b1', a0*b0'...]
    ];
    block_builder.push_ops(ops);
}

/// Given a stack with initial configuration given by [a1, a0, ...] where a = (a0, a1) represents
/// elements in the extension field of degree 2, the procedure outputs the negative of a, i.e.
/// [-a1, -a0, ...]
///
/// This operation takes 4 VM cycles.
pub fn ext2_neg(block_builder: &mut BasicBlockBuilder) {
    #[rustfmt::skip]
    let ops = [
        Neg,            // [a1, a0, ...]
        Swap,           // [a0, -a1, ...]
        Neg,            // [-a0, -a1, ...]
        Swap            // [-a1, -a0, ...]
    ];
    block_builder.push_ops(ops);
}

/// Given an invertible quadratic extension field element on the stack, this routine computes
/// multiplicative inverse of that element, using non-deterministic technique ( i.e. it takes help
/// of advice provider ). To ensure that non-deterministic computation resulted in correct value,
/// it multiplies input operand with computed output, over quadratic extension field which must
/// produce multiplicative identity (1, 0) of quadratic extension field. In case input operand is
/// additive identity which can't be inverted, program execution fails, as advice provider won't
/// calculate multiplicative inverse in that case.
///
/// Expected input stack
///
/// [a1, a0, ...] | a = (a0, a1) ∈ Quadratic extension field over F_p, p = 2^64 - 2^32 + 1
///
/// Expected output stack
///
/// [a'1, a'0, ...] | a' = (a'0, a'1) ∈ Quadratic extension field over F_p, p = 2^64 - 2^32 + 1
///
/// Following is what is checked after reading result of computation, performed outside of VM
///
/// a  = (a0, a1)
/// a' = (a'0, a'1) ( = a ^ -1 )
///
/// b  = a * a' ( mod Q ) | Q = irreducible polynomial x^2 - x + 2 over F_p, p = 2^64 - 2^32 + 1
/// assert b  = (1, 0) | (1, 0) is the multiplicative identity of extension field.
///
/// This operation takes 8 VM cycles.
pub fn ext2_inv(block_builder: &mut BasicBlockBuilder) -> Result<(), Report> {
    block_builder.push_system_event(Ext2Inv);
    #[rustfmt::skip]
    let ops = [
        AdvPop,         // [a0', a1, a0, ...]
        AdvPop,         // [a1', a0', a1, a0, ...]
        Ext2Mul,        // [a1', a0', 0, 1, ...]
        MovUp2,         // [0, a1', a0', 1, ...]
        Eqz,            // [1, a1', a0', 1, ...]
        Assert(ZERO),   // [a1', a0', 1, ...]
        MovUp2,         // [1, a1', a0', ...]
        Assert(ZERO),   // [a1', a0', ...]
    ];
    block_builder.push_ops(ops);

    Ok(())
}
