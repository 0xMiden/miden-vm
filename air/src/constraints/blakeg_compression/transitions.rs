//! Within-round transitions: A->B, B->C, C->D.
//!
//! These three transitions implement one G application across two row pairs:
//!
//!   A row computes `add3(x) + xor + rot16` -> output goes into B row.
//!   B row computes `add2 + rot12` -> output goes into C row.
//!   C row computes `add3(y) + xor + rot8` -> output goes into D row.
//!
//! Each transition is gated by the matching row-type selector. The boundary
//! case D -> next-A is handled in `boundary.rs`.

use miden_core::Felt;
use miden_crypto::stark::air::{AirBuilder, LiftedAirBuilder};

use super::selectors::Selectors;
use super::views::{ACRow, BDRow, NUM_G};

/// Helper: `2^32` as an `AB::Expr`.
#[inline]
fn two_pow_32<AB: LiftedAirBuilder<F = Felt>>() -> AB::Expr {
    AB::Expr::from(Felt::new_unchecked(1u64 << 32))
}

/// Enforce `lhs = rhs` on rows selected by `gate`.
#[inline]
fn gated_eq<AB: LiftedAirBuilder<F = Felt>>(
    builder: &mut AB,
    gate: AB::Expr,
    lhs: AB::Expr,
    rhs: AB::Expr,
) {
    builder.when(gate).assert_zero(lhs - rhs);
}

/// A -> B: `add3(x) + xor + rot16` finishes on B.
///
/// Constraints per lane:
///
/// - `B.a_word = a + b + msg - 2^32 * k3`
/// - `pack(B.b_byte) = A.b_word`
/// - `B.d_word = d_new_rot16(A)`
/// - `A.c_word + d_new_rot16(A) = pack(B.c_new_byte) + 2^32 * B.k2`
pub fn enforce_a_to_b<AB>(
    builder: &mut AB,
    a_local: &ACRow<AB>,
    b_next: &BDRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let gate = sel.gate_a_b();

    for g in 0..NUM_G {
        // B.a_word = A.a_new_word.
        gated_eq(builder, gate.clone(), a_local.a_new_word(g), b_next.a(g));

        // pack(B.b_byte) = A.b_word.
        gated_eq(builder, gate.clone(), a_local.b(g), b_next.b_word(g));

        // B.d_word = d_new_rot16.
        let d_new = a_local.d_new_rot16(g);
        gated_eq(builder, gate.clone(), d_new.clone(), b_next.d(g));

        // A.c_word + d_new = pack(B.c_new_byte) + 2^32 * B.k2.
        gated_eq(
            builder,
            gate.clone(),
            a_local.c(g) + d_new,
            b_next.c_new_word(g) + two_pow_32::<AB>() * b_next.k2(g),
        );
    }
}

/// B -> C: rotation-contribution finalization plus state forwarding.
///
/// Constraints per lane:
///
/// - `C.a_word = B.a_word`
/// - `C.b_word = sum(B.rotation_contribution[0..4])`
/// - `C.c_word = pack(B.c_new_byte)`
/// - `pack(C.d_byte) = B.d_word`
pub fn enforce_b_to_c<AB>(
    builder: &mut AB,
    b_local: &BDRow<AB>,
    c_next: &ACRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let gate = sel.gate_b_c();

    for g in 0..NUM_G {
        // C.a_word = B.a_word.
        gated_eq(builder, gate.clone(), b_local.a(g), c_next.a(g));

        // C.b_word = rot12 output of B.
        gated_eq(builder, gate.clone(), b_local.b_new_from_contributions(g), c_next.b(g));

        // C.c_word = pack(B.c_new_byte).
        gated_eq(builder, gate.clone(), b_local.c_new_word(g), c_next.c(g));

        // pack(C.d_byte) = B.d_word.
        gated_eq(builder, gate.clone(), b_local.d(g), c_next.d_word(g));
    }
}

/// C -> D: `add3(y) + xor + rot8` finishes on D. Mirror of A -> B with rot8.
pub fn enforce_c_to_d<AB>(
    builder: &mut AB,
    c_local: &ACRow<AB>,
    d_next: &BDRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let gate = sel.gate_c_d();

    for g in 0..NUM_G {
        // D.a_word = C.a_new_word.
        gated_eq(builder, gate.clone(), c_local.a_new_word(g), d_next.a(g));

        // pack(D.b_byte) = C.b_word.
        gated_eq(builder, gate.clone(), c_local.b(g), d_next.b_word(g));

        // D.d_word = d_new_rot8.
        let d_new = c_local.d_new_rot8(g);
        gated_eq(builder, gate.clone(), d_new.clone(), d_next.d(g));

        // C.c_word + d_new = pack(D.c_new_byte) + 2^32 * D.k2.
        gated_eq(
            builder,
            gate.clone(),
            c_local.c(g) + d_new,
            d_next.c_new_word(g) + two_pow_32::<AB>() * d_next.k2(g),
        );
    }
}
