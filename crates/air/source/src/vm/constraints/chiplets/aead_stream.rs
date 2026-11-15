//! AEAD stream constraints.
//!
//! Each stream entry spans eight rows; each row proves one u32 XOR as four AND8 byte lookups.
//! These constraints bind the row phases and carry the plaintext/ciphertext limbs across the
//! eight-row schedule.

use core::borrow::Borrow;

use miden_stark::air::native::{Frame, LiftedAirBuilder};
use p3_field::Dup;

use crate::vm::{
    NativeMidenAirBuilder,
    constraints::{
        chiplets::{
            columns::{AeadStreamCols, PeriodicCols},
            selectors::ChipletSelectors,
        },
        constants::{TWO_POW_32, TWO_POW_32_MINUS_1},
        utils::{BoolNot, pack_u32_bytes_le, pack_u32_xor_bytes_le},
    },
};

// ENTRY POINT
// ================================================================================================

/// Enforce stream-row phase alignment, u32-XOR recomposition, canonical splits, and carries.
pub fn enforce_aead_stream_constraints<AB>(
    frame: &Frame<'_, AB>,
    builder: &mut AB,
    cols: &AeadStreamCols<AB::Expr>,
    cols_next: &AeadStreamCols<AB::Expr>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: NativeMidenAirBuilder,
{
    let stream = selectors.aead_stream_active.clone();
    let stream_next = selectors.aead_stream_next_active.clone();
    let periodic: &PeriodicCols<_> = frame.periodic.borrow();
    let phases: [AB::Expr; 8] = periodic.aead_stream.phases.clone();

    // Any entry into the stream follows phase seven, including entry from the controller.
    builder.when(stream.not() * stream_next.clone()).assert_one(phases[7].clone());

    builder.when(stream.clone() * phases[7].clone().not()).assert_one(stream_next);

    // Carry the first and second plaintext pairs across their row phases.
    carry_read_to_high_first(builder, stream.clone() * phases[0].clone(), cols, cols_next, 0);
    carry_high_first_to_low_second(builder, stream.clone() * phases[1].clone(), cols, cols_next);
    carry_low_second_to_high_second(builder, stream.clone() * phases[2].clone(), cols, cols_next);

    carry_read_to_high_first(builder, stream.clone() * phases[4].clone(), cols, cols_next, 2);
    carry_high_first_to_low_second(builder, stream.clone() * phases[5].clone(), cols, cols_next);
    carry_low_second_to_high_second(builder, stream * phases[6].clone(), cols, cols_next);
}

// CARRY CONSTRAINTS
// ================================================================================================

fn carry_read_to_high_first<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    cols: &AeadStreamCols<AB::Expr>,
    cols_next: &AeadStreamCols<AB::Expr>,
    plaintext_offset: usize,
) where
    AB: NativeMidenAirBuilder,
{
    let curr = cols.read();
    let next = cols_next.high_first();

    {
        let builder = &mut builder.when(gate.clone());
        for (left, right) in [
            next.ctx.dup(),
            next.clk.dup(),
            next.src_ptr.dup(),
            next.lane_base.dup(),
            next.next_plaintext.dup(),
        ]
        .into_iter()
        .zip([
            curr.ctx.dup(),
            curr.clk.dup(),
            curr.src_ptr.dup(),
            curr.lane_base.dup(),
            curr.plaintext[plaintext_offset + 1].dup(),
        ]) {
            builder.assert_eq(left, right);
        }
    }
    builder
        .when(gate.clone())
        .assert_eq(next.c_prev0.dup(), pack_u32_xor_bytes_le::<_, AB::Expr>(curr.bytes.clone()));
    enforce_canonical_split(
        builder,
        gate,
        curr.plaintext[plaintext_offset].dup(),
        a_limb_expr::<AB>(&curr.bytes),
        a_limb_expr::<AB>(&next.bytes),
        next.hi_quotient.dup(),
    );
}

fn carry_high_first_to_low_second<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    cols: &AeadStreamCols<AB::Expr>,
    cols_next: &AeadStreamCols<AB::Expr>,
) where
    AB: NativeMidenAirBuilder,
{
    let curr = cols.high_first();
    let next = cols_next.low_second();

    {
        let builder = &mut builder.when(gate.clone());
        for (left, right) in [
            next.ctx.dup(),
            next.clk.dup(),
            next.src_ptr.dup(),
            next.lane_base.dup(),
            next.active_plaintext.dup(),
            next.c_prev0.dup(),
        ]
        .into_iter()
        .zip([
            curr.ctx.dup(),
            curr.clk.dup(),
            curr.src_ptr.dup(),
            curr.lane_base.dup(),
            curr.next_plaintext.dup(),
            curr.c_prev0.dup(),
        ]) {
            builder.assert_eq(left, right);
        }
    }
    builder
        .when(gate)
        .assert_eq(next.c_prev1.dup(), pack_u32_xor_bytes_le::<_, AB::Expr>(curr.bytes.clone()));
}

fn carry_low_second_to_high_second<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    cols: &AeadStreamCols<AB::Expr>,
    cols_next: &AeadStreamCols<AB::Expr>,
) where
    AB: NativeMidenAirBuilder,
{
    let curr = cols.low_second();
    let next = cols_next.high_second();

    {
        let builder = &mut builder.when(gate.clone());
        for (left, right) in [
            next.ctx.dup(),
            next.clk.dup(),
            next.dst_ptr.dup(),
            next.lane_base.dup(),
            next.c_prev0.dup(),
            next.c_prev1.dup(),
        ]
        .into_iter()
        .zip([
            curr.ctx.dup(),
            curr.clk.dup(),
            curr.dst_ptr.dup(),
            curr.lane_base.dup(),
            curr.c_prev0.dup(),
            curr.c_prev1.dup(),
        ]) {
            builder.assert_eq(left, right);
        }
    }
    builder
        .when(gate.clone())
        .assert_eq(next.c_prev2.dup(), pack_u32_xor_bytes_le::<_, AB::Expr>(curr.bytes.clone()));
    enforce_canonical_split(
        builder,
        gate,
        curr.active_plaintext.dup(),
        a_limb_expr::<AB>(&curr.bytes),
        a_limb_expr::<AB>(&next.bytes),
        next.hi_quotient.dup(),
    );
}

// HELPERS
// ================================================================================================

fn enforce_canonical_split<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    plaintext: AB::Expr,
    lo: AB::Expr,
    hi: AB::Expr,
    hi_quotient: AB::Expr,
) where
    AB: NativeMidenAirBuilder,
{
    builder
        .when(gate.clone())
        .assert_eq(plaintext, lo.clone() + AB::Expr::from(TWO_POW_32) * hi.clone());

    let hi_gap = AB::Expr::from(TWO_POW_32_MINUS_1) - hi;
    // If the high limb is all ones, canonical packing requires the low limb to be zero.
    builder.when(gate).assert_eq(hi_quotient * hi_gap, lo);
}

fn a_limb_expr<AB>(bytes: &[AB::Expr; 12]) -> AB::Expr
where
    AB: NativeMidenAirBuilder,
{
    pack_u32_bytes_le::<_, AB::Expr>(core::array::from_fn(|i| bytes[i].dup()))
}
