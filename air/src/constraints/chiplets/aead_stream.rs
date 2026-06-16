//! AEAD stream constraints.
//!
//! Stream rows live in the bitwise selector region with `stream_mode = 1`. One stream entry spans
//! eight rows; each row proves one u32 XOR as four AND8 byte lookups. These constraints bind the
//! row phases and carry the plaintext/ciphertext limbs across the eight-row schedule.

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use crate::{
    ChipletCols, MidenAirBuilder,
    constraints::{
        chiplets::{
            columns::{AeadStreamCols, PeriodicCols},
            selectors::ChipletSelectors,
        },
        constants::{TWO_POW_32, TWO_POW_32_MINUS_1},
        utils::{BoolNot, pack_u32_bytes_le},
    },
};

// ENTRY POINT
// ================================================================================================

/// Enforce stream-row phase alignment, u32-XOR recomposition, canonical splits, and carries.
pub fn enforce_aead_stream_constraints<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let periodic: &PeriodicCols<_> = builder.periodic_values().borrow();
    let phase = periodic.aead_stream;

    let phases: [AB::Expr; 8] = [
        phase.r0.into(),
        phase.r1.into(),
        phase.r2.into(),
        phase.r3.into(),
        phase.r4.into(),
        phase.r5.into(),
        phase.r6.into(),
        phase.r7.into(),
    ];

    let cols = local.aead_stream();
    let cols_next = next.aead_stream();
    let stream = selectors.stream_mode.aead_stream.clone();
    let stream_next = aead_stream_active_next::<AB>(next);

    enforce_phase_alignment(builder, selectors, stream.clone(), stream_next, phases[7].clone());
    enforce_carry_constraints(builder, cols, cols_next, stream, &phases);
}

// PHASE ALIGNMENT
// ================================================================================================

fn enforce_phase_alignment<AB>(
    builder: &mut AB,
    selectors: &ChipletSelectors<AB::Expr>,
    stream: AB::Expr,
    stream_next: AB::Expr,
    r7: AB::Expr,
) where
    AB: MidenAirBuilder,
{
    builder
        .when(selectors.bitwise.next_is_first.clone() * stream_next.clone())
        .assert_one(r7.clone());

    builder.when(stream.clone().not() * stream_next.clone()).assert_one(r7.clone());

    builder.when(stream * r7.not()).assert_one(stream_next);
}

// CARRY CONSTRAINTS
// ================================================================================================

fn enforce_carry_constraints<AB>(
    builder: &mut AB,
    cols: &AeadStreamCols<AB::Var>,
    cols_next: &AeadStreamCols<AB::Var>,
    stream: AB::Expr,
    r: &[AB::Expr; 8],
) where
    AB: MidenAirBuilder,
{
    carry_read_to_high_first(builder, stream.clone() * r[0].clone(), cols, cols_next, 0);
    carry_high_first_to_low_second(builder, stream.clone() * r[1].clone(), cols, cols_next);
    carry_low_second_to_high_second(builder, stream.clone() * r[2].clone(), cols, cols_next);

    carry_read_to_high_first(builder, stream.clone() * r[4].clone(), cols, cols_next, 2);
    carry_high_first_to_low_second(builder, stream.clone() * r[5].clone(), cols, cols_next);
    carry_low_second_to_high_second(builder, stream * r[6].clone(), cols, cols_next);
}

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

    assert_eq_on(builder, gate.clone(), next.ctx, curr.ctx);
    assert_eq_on(builder, gate.clone(), next.clk, curr.clk);
    assert_eq_on(builder, gate.clone(), next.src_ptr, curr.src_ptr);
    assert_eq_on(builder, gate.clone(), next.lane_base, curr.lane_base);
    assert_eq_on(builder, gate.clone(), next.next_plaintext, curr.plaintext[plaintext_offset + 1]);
    assert_eq_expr_on(builder, gate.clone(), next.c_prev0, xor_limb_expr::<AB>(curr.bytes));
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

    assert_eq_on(builder, gate.clone(), next.ctx, curr.ctx);
    assert_eq_on(builder, gate.clone(), next.clk, curr.clk);
    assert_eq_on(builder, gate.clone(), next.src_ptr, curr.src_ptr);
    assert_eq_on(builder, gate.clone(), next.lane_base, curr.lane_base);
    assert_eq_on(builder, gate.clone(), next.active_plaintext, curr.next_plaintext);
    assert_eq_on(builder, gate.clone(), next.c_prev0, curr.c_prev0);
    assert_eq_expr_on(builder, gate, next.c_prev1, xor_limb_expr::<AB>(curr.bytes));
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

    assert_eq_on(builder, gate.clone(), next.ctx, curr.ctx);
    assert_eq_on(builder, gate.clone(), next.clk, curr.clk);
    assert_eq_on(builder, gate.clone(), next.dst_ptr, curr.dst_ptr);
    assert_eq_on(builder, gate.clone(), next.lane_base, curr.lane_base);
    assert_eq_on(builder, gate.clone(), next.c_prev0, curr.c_prev0);
    assert_eq_on(builder, gate.clone(), next.c_prev1, curr.c_prev1);
    assert_eq_expr_on(builder, gate.clone(), next.c_prev2, xor_limb_expr::<AB>(curr.bytes));
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

fn aead_stream_active_next<AB>(next: &ChipletCols<AB::Var>) -> AB::Expr
where
    AB: MidenAirBuilder,
{
    let s_ctrl_next: AB::Expr = next.chiplets[0].into();
    let s1_next: AB::Expr = next.chiplets[1].into();
    let stream_mode_next: AB::Expr = next.bitwise_stream_mode().into();
    s_ctrl_next.not() * s1_next.not() * stream_mode_next
}

fn assert_eq_on<AB>(builder: &mut AB, gate: AB::Expr, next: AB::Var, current: AB::Var)
where
    AB: MidenAirBuilder,
{
    builder.when(gate).assert_eq(next, current);
}

fn assert_eq_expr_on<AB>(builder: &mut AB, gate: AB::Expr, next: AB::Var, current: AB::Expr)
where
    AB: MidenAirBuilder,
{
    builder.when(gate).assert_eq(next, current);
}

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
    builder.when(gate).assert_eq(Into::<AB::Expr>::into(hi_quotient) * hi_gap, lo);
}

pub(crate) fn a_limb_expr<AB>(bytes: [AB::Var; 12]) -> AB::Expr
where
    AB: MidenAirBuilder,
{
    pack_u32::<AB>([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub(crate) fn xor_limb_expr<AB>(bytes: [AB::Var; 12]) -> AB::Expr
where
    AB: MidenAirBuilder,
{
    let two = AB::Expr::from_u8(2);
    let xor_bytes = [
        Into::<AB::Expr>::into(bytes[0]) + Into::<AB::Expr>::into(bytes[4])
            - two.clone() * Into::<AB::Expr>::into(bytes[8]),
        Into::<AB::Expr>::into(bytes[1]) + Into::<AB::Expr>::into(bytes[5])
            - two.clone() * Into::<AB::Expr>::into(bytes[9]),
        Into::<AB::Expr>::into(bytes[2]) + Into::<AB::Expr>::into(bytes[6])
            - two.clone() * Into::<AB::Expr>::into(bytes[10]),
        Into::<AB::Expr>::into(bytes[3]) + Into::<AB::Expr>::into(bytes[7])
            - two * Into::<AB::Expr>::into(bytes[11]),
    ];
    pack_u32_bytes_le::<_, AB::Expr>(xor_bytes)
}

fn pack_u32<AB>(bytes: [AB::Var; 4]) -> AB::Expr
where
    AB: MidenAirBuilder,
{
    pack_u32_bytes_le::<_, AB::Expr>(bytes)
}
