//! AEAD stream constraints.
//!
//! Each stream entry spans eight rows; each row proves one u32 XOR as four AND8 byte lookups.
//! These constraints bind the row phases and carry the plaintext/ciphertext limbs across the
//! eight-row schedule.

use core::borrow::Borrow;

use miden_stark::air::AirBuilder;

use crate::vm::{
    MidenAirBuilder,
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
    builder: &mut AB,
    cols: &AeadStreamCols<AB::Var>,
    cols_next: &AeadStreamCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let stream = selectors.aead_stream_active.clone();
    let stream_next = selectors.aead_stream_next_active.clone();
    let periodic: &PeriodicCols<_> = builder.periodic_values().borrow();
    let phases: [AB::Expr; 8] = periodic.aead_stream.phases.map(Into::into);

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
    cols: &AeadStreamCols<AB::Var>,
    cols_next: &AeadStreamCols<AB::Var>,
    plaintext_offset: usize,
) where
    AB: MidenAirBuilder,
{
    let curr = cols.read();
    let next = cols_next.high_first();

    builder.when(gate.clone()).assert_eq_arrays(
        [next.ctx, next.clk, next.src_ptr, next.lane_base, next.next_plaintext],
        [
            curr.ctx,
            curr.clk,
            curr.src_ptr,
            curr.lane_base,
            curr.plaintext[plaintext_offset + 1],
        ],
    );
    builder
        .when(gate.clone())
        .assert_eq(next.c_prev0, pack_u32_xor_bytes_le::<_, AB::Expr>(curr.bytes));
    enforce_canonical_split(
        builder,
        gate,
        curr.plaintext[plaintext_offset],
        a_limb_expr::<AB>(curr.bytes),
        a_limb_expr::<AB>(next.bytes),
        next.hi_quotient,
    );
}

fn carry_high_first_to_low_second<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    cols: &AeadStreamCols<AB::Var>,
    cols_next: &AeadStreamCols<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    let curr = cols.high_first();
    let next = cols_next.low_second();

    builder.when(gate.clone()).assert_eq_arrays(
        [
            next.ctx,
            next.clk,
            next.src_ptr,
            next.lane_base,
            next.active_plaintext,
            next.c_prev0,
        ],
        [
            curr.ctx,
            curr.clk,
            curr.src_ptr,
            curr.lane_base,
            curr.next_plaintext,
            curr.c_prev0,
        ],
    );
    builder
        .when(gate)
        .assert_eq(next.c_prev1, pack_u32_xor_bytes_le::<_, AB::Expr>(curr.bytes));
}

fn carry_low_second_to_high_second<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    cols: &AeadStreamCols<AB::Var>,
    cols_next: &AeadStreamCols<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    let curr = cols.low_second();
    let next = cols_next.high_second();

    builder.when(gate.clone()).assert_eq_arrays(
        [next.ctx, next.clk, next.dst_ptr, next.lane_base, next.c_prev0, next.c_prev1],
        [curr.ctx, curr.clk, curr.dst_ptr, curr.lane_base, curr.c_prev0, curr.c_prev1],
    );
    builder
        .when(gate.clone())
        .assert_eq(next.c_prev2, pack_u32_xor_bytes_le::<_, AB::Expr>(curr.bytes));
    enforce_canonical_split(
        builder,
        gate,
        curr.active_plaintext,
        a_limb_expr::<AB>(curr.bytes),
        a_limb_expr::<AB>(next.bytes),
        next.hi_quotient,
    );
}

// HELPERS
// ================================================================================================

fn enforce_canonical_split<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    plaintext: AB::Var,
    lo: AB::Expr,
    hi: AB::Expr,
    hi_quotient: AB::Var,
) where
    AB: MidenAirBuilder,
{
    builder
        .when(gate.clone())
        .assert_eq(plaintext, lo.clone() + AB::Expr::from(TWO_POW_32) * hi.clone());

    let hi_gap = AB::Expr::from(TWO_POW_32_MINUS_1) - hi;
    // If the high limb is all ones, canonical packing requires the low limb to be zero.
    builder.when(gate).assert_eq(hi_quotient * hi_gap, lo);
}

pub(crate) fn a_limb_expr<AB>(bytes: [AB::Var; 12]) -> AB::Expr
where
    AB: MidenAirBuilder,
{
    pack_u32_bytes_le::<_, AB::Expr>([bytes[0], bytes[1], bytes[2], bytes[3]])
}
