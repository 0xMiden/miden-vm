//! Crypto operation constraints.
//!
//! This module contains constraints for crypto-related stack ops:
//! - CRYPTOSTREAM
//! - HORNERBASE
//! - HORNEREXT
//! - FRIE2F4 (placeholder; semantics updated post-Winterfell → Plonky3)

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::op_flags::OpFlags;
use crate::{MainTraceRow, trace::decoder::USER_OP_HELPERS_OFFSET};

// CONSTANTS
// ================================================================================================

/// Number of crypto op constraints.
#[allow(dead_code)]
pub const NUM_CONSTRAINTS: usize = 46;

/// Degrees of the crypto op constraints.
#[allow(dead_code)]
pub const CONSTRAINT_DEGREES: [usize; NUM_CONSTRAINTS] = [
    // CRYPTOSTREAM (8 constraints, degree 4 flag + degree 1 = 5).
    5, 5, 5, 5, 5, 5, 5, 5,
    // HORNERBASE: 14 unchanged positions (degree 6), 6 accumulator constraints (degree 8/9).
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, // s0'..s13' = s0..s13
    8, 8, 9, 9, 9, 9, // tmp0_0, tmp0_1, tmp1_0, tmp1_1, acc0', acc1'
    // HORNEREXT: 14 unchanged positions (degree 6), 4 accumulator constraints (degree 8).
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, // s0'..s13' = s0..s13
    8, 8, 8, 8, // acc_tmp0, acc_tmp1, acc0', acc1'
];

// ENTRY POINTS
// ================================================================================================

/// Enforces crypto operation constraints.
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    enforce_cryptostream_constraints(builder, local, next, op_flags);
    enforce_hornerbase_constraints(builder, local, next, op_flags);
    enforce_hornerext_constraints(builder, local, next, op_flags);
    enforce_frie2f4_placeholder(builder, local, next, op_flags);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces CRYPTOSTREAM stack updates.
///
/// - Positions 8..11 (capacity) are unchanged.
/// - Positions 12..13 (src/dst pointers) increment by 8.
/// - Positions 14..15 are unchanged.
/// - Ciphertext update on stack[0..7] is enforced via the chiplets bus by tying the memory read
///   words to (next.stack[0..7] - local.stack[0..7]).
fn enforce_cryptostream_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let eight: AB::Expr = AB::Expr::from_u16(8);
    let gate = builder.is_transition() * op_flags.cryptostream();

    let constraints = [
        // Capacity unchanged.
        next.stack[8].clone().into() - local.stack[8].clone().into(),
        next.stack[9].clone().into() - local.stack[9].clone().into(),
        next.stack[10].clone().into() - local.stack[10].clone().into(),
        next.stack[11].clone().into() - local.stack[11].clone().into(),
        // Pointer increments.
        next.stack[12].clone().into() - (local.stack[12].clone().into() + eight.clone()),
        next.stack[13].clone().into() - (local.stack[13].clone().into() + eight),
        // Remaining positions unchanged.
        next.stack[14].clone().into() - local.stack[14].clone().into(),
        next.stack[15].clone().into() - local.stack[15].clone().into(),
    ];

    builder.when(gate).assert_zeros(constraints);
}

/// Enforces HORNERBASE stack and helper constraints.
///
/// Hornerbase evaluates a degree-7 polynomial with base-field coefficients at the
/// quadratic extension point α = (a0, a1) in 𝔽p[x]/(x² - 7).
///
/// Helper registers layout:
/// - h0, h1: α0, α1
/// - h2, h3: tmp1 (quadratic extension)
/// - h4, h5: tmp0 (quadratic extension)
fn enforce_hornerbase_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let gate = builder.is_transition() * op_flags.hornerbase();

    // Positions 0-13 are unchanged.
    builder.when(gate.clone()).assert_zeros([
        next.stack[0].clone().into() - local.stack[0].clone().into(),
        next.stack[1].clone().into() - local.stack[1].clone().into(),
        next.stack[2].clone().into() - local.stack[2].clone().into(),
        next.stack[3].clone().into() - local.stack[3].clone().into(),
        next.stack[4].clone().into() - local.stack[4].clone().into(),
        next.stack[5].clone().into() - local.stack[5].clone().into(),
        next.stack[6].clone().into() - local.stack[6].clone().into(),
        next.stack[7].clone().into() - local.stack[7].clone().into(),
        next.stack[8].clone().into() - local.stack[8].clone().into(),
        next.stack[9].clone().into() - local.stack[9].clone().into(),
        next.stack[10].clone().into() - local.stack[10].clone().into(),
        next.stack[11].clone().into() - local.stack[11].clone().into(),
        next.stack[12].clone().into() - local.stack[12].clone().into(),
        next.stack[13].clone().into() - local.stack[13].clone().into(),
    ]);

    let base = USER_OP_HELPERS_OFFSET;
    let a0: AB::Expr = local.decoder[base].clone().into();
    let a1: AB::Expr = local.decoder[base + 1].clone().into();
    let tmp1_0: AB::Expr = local.decoder[base + 2].clone().into();
    let tmp1_1: AB::Expr = local.decoder[base + 3].clone().into();
    let tmp0_0: AB::Expr = local.decoder[base + 4].clone().into();
    let tmp0_1: AB::Expr = local.decoder[base + 5].clone().into();

    let acc0: AB::Expr = local.stack[14].clone().into();
    let acc1: AB::Expr = local.stack[15].clone().into();
    let acc0_next: AB::Expr = next.stack[14].clone().into();
    let acc1_next: AB::Expr = next.stack[15].clone().into();

    let c0: AB::Expr = local.stack[0].clone().into();
    let c1: AB::Expr = local.stack[1].clone().into();
    let c2: AB::Expr = local.stack[2].clone().into();
    let c3: AB::Expr = local.stack[3].clone().into();
    let c4: AB::Expr = local.stack[4].clone().into();
    let c5: AB::Expr = local.stack[5].clone().into();
    let c6: AB::Expr = local.stack[6].clone().into();
    let c7: AB::Expr = local.stack[7].clone().into();

    let two: AB::Expr = AB::Expr::from_u16(2);
    let three: AB::Expr = AB::Expr::from_u16(3);
    let seven: AB::Expr = AB::Expr::from_u16(7);
    let twenty_one: AB::Expr = AB::Expr::from_u16(21);
    let forty_nine: AB::Expr = AB::Expr::from_u16(49);

    let a0_sq = a0.clone() * a0.clone();
    let a1_sq = a1.clone() * a1.clone();
    let a0_a1 = a0.clone() * a1.clone();
    let a0_cu = a0_sq.clone() * a0.clone();
    let a1_cu = a1_sq.clone() * a1.clone();

    // α² = (a0² + 7·a1², 2·a0·a1)
    let alpha_sq_0 = a0_sq.clone() + seven.clone() * a1_sq.clone();
    let alpha_sq_1 = two.clone() * a0_a1.clone();

    // α³ = (a0³ + 21·a0·a1², 3·a0²·a1 + 7·a1³)
    let alpha_cu_0 = a0_cu.clone() + twenty_one.clone() * a0.clone() * a1_sq.clone();
    let alpha_cu_1 = three.clone() * a0_sq.clone() * a1.clone() + seven.clone() * a1_cu.clone();

    // tmp0 = acc·α² + c0·α + c1
    let expected_tmp0_0 = acc0.clone() * alpha_sq_0.clone()
        + acc1.clone() * (seven.clone() * alpha_sq_1.clone())
        + c0.clone() * a0.clone()
        + c1.clone();
    let expected_tmp0_1 = acc0.clone() * alpha_sq_1.clone()
        + acc1.clone() * alpha_sq_0.clone()
        + c0.clone() * a1.clone();

    // tmp1 = tmp0·α³ + c2·α² + c3·α + c4
    let expected_tmp1_0 = tmp0_0.clone() * alpha_cu_0.clone()
        + tmp0_1.clone()
            * (twenty_one.clone() * a0_sq.clone() * a1.clone()
                + forty_nine.clone() * a1_cu.clone())
        + c2.clone() * alpha_sq_0.clone()
        + c3.clone() * a0.clone()
        + c4.clone();
    let expected_tmp1_1 = tmp0_0.clone() * alpha_cu_1.clone()
        + tmp0_1.clone() * alpha_cu_0.clone()
        + c2.clone() * alpha_sq_1.clone()
        + c3.clone() * a1.clone();

    // acc' = tmp1·α³ + c5·α² + c6·α + c7
    let expected_acc0 = tmp1_0.clone() * alpha_cu_0.clone()
        + tmp1_1.clone() * (twenty_one * a0_sq * a1.clone() + forty_nine * a1_cu)
        + c5.clone() * alpha_sq_0.clone()
        + c6.clone() * a0
        + c7;
    let expected_acc1 = tmp1_0.clone() * alpha_cu_1
        + tmp1_1.clone() * alpha_cu_0
        + c5.clone() * alpha_sq_1
        + c6 * a1;

    builder.when(gate).assert_zeros([
        tmp0_0 - expected_tmp0_0,
        tmp0_1 - expected_tmp0_1,
        tmp1_0 - expected_tmp1_0,
        tmp1_1 - expected_tmp1_1,
        acc0_next - expected_acc0,
        acc1_next - expected_acc1,
    ]);
}

/// Enforces HORNEREXT stack and helper constraints.
///
/// Hornerext evaluates a degree-3 polynomial with extension-field coefficients at
/// α = (a0, a1) in 𝔽p[x]/(x² - 7). Coefficients are stored as pairs on the stack.
///
/// Helper registers layout:
/// - h0, h1: α0, α1
/// - h4, h5: acc_tmp (quadratic extension)
fn enforce_hornerext_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let gate = builder.is_transition() * op_flags.hornerext();

    // Positions 0-13 are unchanged.
    builder.when(gate.clone()).assert_zeros([
        next.stack[0].clone().into() - local.stack[0].clone().into(),
        next.stack[1].clone().into() - local.stack[1].clone().into(),
        next.stack[2].clone().into() - local.stack[2].clone().into(),
        next.stack[3].clone().into() - local.stack[3].clone().into(),
        next.stack[4].clone().into() - local.stack[4].clone().into(),
        next.stack[5].clone().into() - local.stack[5].clone().into(),
        next.stack[6].clone().into() - local.stack[6].clone().into(),
        next.stack[7].clone().into() - local.stack[7].clone().into(),
        next.stack[8].clone().into() - local.stack[8].clone().into(),
        next.stack[9].clone().into() - local.stack[9].clone().into(),
        next.stack[10].clone().into() - local.stack[10].clone().into(),
        next.stack[11].clone().into() - local.stack[11].clone().into(),
        next.stack[12].clone().into() - local.stack[12].clone().into(),
        next.stack[13].clone().into() - local.stack[13].clone().into(),
    ]);

    let base = USER_OP_HELPERS_OFFSET;
    let a0: AB::Expr = local.decoder[base].clone().into();
    let a1: AB::Expr = local.decoder[base + 1].clone().into();
    let tmp0: AB::Expr = local.decoder[base + 4].clone().into();
    let tmp1: AB::Expr = local.decoder[base + 5].clone().into();

    let acc0: AB::Expr = local.stack[14].clone().into();
    let acc1: AB::Expr = local.stack[15].clone().into();
    let acc0_next: AB::Expr = next.stack[14].clone().into();
    let acc1_next: AB::Expr = next.stack[15].clone().into();

    let c0_0: AB::Expr = local.stack[0].clone().into();
    let c0_1: AB::Expr = local.stack[1].clone().into();
    let c1_0: AB::Expr = local.stack[2].clone().into();
    let c1_1: AB::Expr = local.stack[3].clone().into();
    let c2_0: AB::Expr = local.stack[4].clone().into();
    let c2_1: AB::Expr = local.stack[5].clone().into();
    let c3_0: AB::Expr = local.stack[6].clone().into();
    let c3_1: AB::Expr = local.stack[7].clone().into();

    let two: AB::Expr = AB::Expr::from_u16(2);
    let seven: AB::Expr = AB::Expr::from_u16(7);
    let a0_sq = a0.clone() * a0.clone();
    let a1_sq = a1.clone() * a1.clone();
    let a0_a1 = a0.clone() * a1.clone();

    // α² = (a0² + 7·a1², 2·a0·a1)
    let alpha_sq_0 = a0_sq.clone() + seven.clone() * a1_sq.clone();
    let alpha_sq_1 = two.clone() * a0_a1.clone();

    // acc_tmp = acc·α² + c0·α + c1
    let expected_tmp0 = acc0.clone() * alpha_sq_0.clone()
        + acc1.clone() * (seven.clone() * alpha_sq_1.clone())
        + c0_0.clone() * a0.clone()
        + seven.clone() * c0_1.clone() * a1.clone()
        + c1_0.clone();
    let expected_tmp1 = acc1.clone() * alpha_sq_0.clone()
        + acc0.clone() * alpha_sq_1.clone()
        + c0_1.clone() * a0.clone()
        + c0_0.clone() * a1.clone()
        + c1_1.clone();

    // acc' = acc_tmp·α² + c2·α + c3
    let expected_acc0 = tmp0.clone() * alpha_sq_0.clone()
        + tmp1.clone() * (seven.clone() * alpha_sq_1.clone())
        + c2_0.clone() * a0.clone()
        + seven * c2_1.clone() * a1.clone()
        + c3_0.clone();
    let expected_acc1 = tmp1.clone() * alpha_sq_0.clone()
        + tmp0.clone() * alpha_sq_1
        + c2_1.clone() * a0
        + c2_0.clone() * a1
        + c3_1;

    builder.when(gate).assert_zeros([
        tmp0 - expected_tmp0,
        tmp1 - expected_tmp1,
        acc0_next - expected_acc0,
        acc1_next - expected_acc1,
    ]);
}

/// Placeholder for FRIE2F4 constraints.
///
/// TODO(Al): Implement once the FRIE2F4 semantics are updated for the Plonky3 migration.
fn enforce_frie2f4_placeholder<AB>(
    _builder: &mut AB,
    _local: &MainTraceRow<AB::Var>,
    _next: &MainTraceRow<AB::Var>,
    _op_flags: &OpFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
}
