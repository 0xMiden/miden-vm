//! Interface and message-row constraints.
//!
//! The interface block sits at rows 60..63:
//!
//! - Row 60: M0 (message row, m[0..7]). Carries message words and limb
//!   ranges in the fixed slot bank, plus canonicality witnesses, C/D
//!   accumulators, and AEAD-XOF labels.
//! - Row 61: M1 (message row, m[8..15]). Same slot-bank shape, carries
//!   routed M0 limbs and R[0..3] computed on M0.
//! - Row 62: I (interface). Carries HIN-pair slots, routed M-row
//!   ranges, R[0..7], C[0..3], D[0..3], multiplicity, and AEAD-XOF labels.
//! - Row 63: O (idle row). No bus interactions and no constrained payload.
//!
//! This module enforces:
//! - The packing identity `I.C[t] = I.H[2t] + 2^32 * I.H[2t+1]`.
//! - M0 -> M1 forwarding of routed limbs, C/D, and AEAD-XOF labels.
//! - M1 -> I forwarding of routed limbs, R[0..3], C/D, and AEAD-XOF labels.
//! - 16-bit limb reconstruction of `m[k]` on M0 and M1.
//! - Canonicality of the Goldilocks-u64 (lo, hi) decomposition via an
//!   inverse-or-zero witness and zero flag.
//! - The rate-binding identity `R[j] = m[2j] + 2^32 * m[2j+1]`.

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::{AirBuilder, LiftedAirBuilder};

use super::selectors::Selectors;
use super::{
    AEAD_XOF_CLK_COL, AEAD_XOF_MODE_COL, IFACE_C_BASE_COL, IFACE_D_BASE_COL, IFACE_R_BASE_COL,
    MSG_C_BASE_COL, MSG_CANON_Z_BASE_COL, MSG_D_BASE_COL, MSG_M0_ROUTE_CARRY_BASE_COL,
    MSG_M1_R_CARRY_BASE_COL, ROUTED_M0_RANGE_COUNT, ROUTED_M1_RANGE_COUNT, iface_h_word_col,
    iface_m0_route_col, iface_m1_route_col, msg_canon_inv_col, msg_m0_range_col, msg_m1_range_col,
    msg_word_col,
};

/// `I.C[t] = I.H[2t] + 2^32 * I.H[2t+1]` for `t in 0..4`.
///
/// `I.C` is the packed (felt-level) chaining value seen by the LogUp HIN
/// bus; `I.H` is the unpacked u32-level form used by F0..F3's per-row XOR
/// witnesses (via the F3 -> I forwarding).
pub fn enforce_iface_in_c_h_consistency<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_iface_in = sel.is_iface_in();
    let two_pow_32 = AB::Expr::from(Felt::new_unchecked(1u64 << 32));
    for t in 0..4 {
        let c_t: AB::Expr = local[IFACE_C_BASE_COL + t].clone().into();
        let h_even: AB::Expr = local[iface_h_word_col(2 * t)].clone().into();
        let h_odd: AB::Expr = local[iface_h_word_col(2 * t + 1)].clone().into();
        builder
            .when(is_iface_in.clone())
            .assert_zero(c_t - h_even - h_odd * two_pow_32.clone());
    }
}

/// M0 -> M1: forward routed limbs, `C[0..3]`, `D[0..3]`, and AEAD-XOF labels.
///
/// R[0..3] is computed directly into M1 by `enforce_msg_rate_binding`.
/// C and D propagate as same-col copies through the M-row chain.
pub fn enforce_m0_to_m1<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_msg_row0 = sel.is_msg_row0();
    let builder = &mut builder.when(is_msg_row0);
    // C[0..3] and D[0..3] same-col copy.
    for t in 0..4 {
        let m0_c: AB::Expr = local[MSG_C_BASE_COL + t].clone().into();
        let m1_c: AB::Expr = next[MSG_C_BASE_COL + t].clone().into();
        builder.assert_zero(m0_c - m1_c);

        let m0_d: AB::Expr = local[MSG_D_BASE_COL + t].clone().into();
        let m1_d: AB::Expr = next[MSG_D_BASE_COL + t].clone().into();
        builder.assert_zero(m0_d - m1_d);
    }
    for col in [AEAD_XOF_MODE_COL, AEAD_XOF_CLK_COL] {
        let m0_value: AB::Expr = local[col].clone().into();
        let m1_value: AB::Expr = next[col].clone().into();
        builder.assert_zero(m0_value - m1_value);
    }
    for i in 0..ROUTED_M0_RANGE_COUNT {
        // M1 carries selected M0 limbs; row I emits their range checks.
        let routed: AB::Expr = local[msg_m0_range_col(12 + i)].clone().into();
        let carry: AB::Expr = next[MSG_M0_ROUTE_CARRY_BASE_COL + i].clone().into();
        builder.assert_zero(routed - carry);
    }
}

/// M1 -> I: forward `R[0..3]`, routed limbs, C/D, and AEAD-XOF labels.
///
/// R[4..7] is computed directly into I by `enforce_msg_rate_binding`.
pub fn enforce_m1_to_iface_in<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_msg_row1 = sel.is_msg_row1();
    let builder = &mut builder.when(is_msg_row1);
    // R[0..3]: M1 carry columns -> I R prefix.
    for k in 0..4 {
        let m1_r: AB::Expr = local[MSG_M1_R_CARRY_BASE_COL + k].clone().into();
        let i_r: AB::Expr = next[IFACE_R_BASE_COL + k].clone().into();
        builder.assert_zero(m1_r - i_r);
    }
    // C[0..3]: M1 accumulator slots -> I C slots.
    for t in 0..4 {
        let m1_c: AB::Expr = local[MSG_C_BASE_COL + t].clone().into();
        let i_c: AB::Expr = next[IFACE_C_BASE_COL + t].clone().into();
        builder.assert_zero(m1_c - i_c);
    }
    // D[0..3]: M1 accumulator slots -> I D slots.
    for t in 0..4 {
        let m1_d: AB::Expr = local[MSG_D_BASE_COL + t].clone().into();
        let i_d: AB::Expr = next[IFACE_D_BASE_COL + t].clone().into();
        builder.assert_zero(m1_d - i_d);
    }
    for col in [AEAD_XOF_MODE_COL, AEAD_XOF_CLK_COL] {
        let m1_value: AB::Expr = local[col].clone().into();
        let i_value: AB::Expr = next[col].clone().into();
        builder.assert_zero(m1_value - i_value);
    }
    for i in 0..ROUTED_M0_RANGE_COUNT {
        // Forward the M0 limbs carried by M1 into row I.
        let m0_routed: AB::Expr = local[MSG_M0_ROUTE_CARRY_BASE_COL + i].clone().into();
        let i_m0_routed: AB::Expr = next[iface_m0_route_col(i)].clone().into();
        builder.assert_zero(m0_routed - i_m0_routed);
    }

    for i in 0..ROUTED_M1_RANGE_COUNT {
        let m1_routed: AB::Expr = local[msg_m1_range_col(8 + i)].clone().into();
        let i_m1_routed: AB::Expr = next[iface_m1_route_col(i)].clone().into();
        builder.assert_zero(m1_routed - i_m1_routed);
    }
}

/// Output mode is packed or AEAD-XOF, with a clock label only for AEAD rows.
pub fn enforce_aead_mode_and_label_constraints<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_iface_in = sel.is_iface_in();
    let builder = &mut builder.when(is_iface_in);
    let mode: AB::Expr = local[AEAD_XOF_MODE_COL].clone().into();
    let inactive = AB::Expr::ONE - mode.clone();
    builder.assert_zero(mode.clone() * inactive.clone());
    builder.assert_zero(inactive * Into::<AB::Expr>::into(local[AEAD_XOF_CLK_COL].clone()));
}

/// 16-bit limb reconstruction on the message rows.
///
/// On M0 and M1, `m[k] = L[2k] + 2^16 * L[2k+1]` for `k in 0..8`.
/// The 16-bit limbs are themselves range-checked via the shared VM range-bus,
/// which enforces that each `m[*]` is a 32-bit word.
pub fn enforce_msg_row_limb_reconstruction<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_msg_row0 = sel.is_msg_row0();
    let is_msg_row1 = sel.is_msg_row1();
    let two_pow_16 = AB::Expr::from(Felt::new_unchecked(1u64 << 16));

    for k in 0..8 {
        let w_k: AB::Expr = local[msg_word_col(k)].clone().into();
        let m0_lo: AB::Expr = local[msg_m0_range_col(2 * k)].clone().into();
        let m0_hi: AB::Expr = local[msg_m0_range_col(2 * k + 1)].clone().into();
        let m1_lo: AB::Expr = local[msg_m1_range_col(2 * k)].clone().into();
        let m1_hi: AB::Expr = local[msg_m1_range_col(2 * k + 1)].clone().into();
        builder
            .when(is_msg_row0.clone())
            .assert_zero(w_k.clone() - m0_lo - m0_hi * two_pow_16.clone());
        builder
            .when(is_msg_row1.clone())
            .assert_zero(w_k - m1_lo - m1_hi * two_pow_16.clone());
    }
}

/// Rate-binding: `R[j] = m[2j] + 2^32 * m[2j+1]` on the message rows.
///
/// The bus treats `R` as 64-bit-packed felts (so each `R[j]` in
/// `Goldilocks`); the chiplet works on 32-bit words. This identity binds
/// the two views together: M0 defines R[0..3]; M1 defines R[4..7].
pub fn enforce_msg_rate_binding<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    next: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_msg_row0 = sel.is_msg_row0();
    let is_msg_row1 = sel.is_msg_row1();
    let two_pow_32 = AB::Expr::from(Felt::new_unchecked(1u64 << 32));

    // M0 computes R[0..3] into M1's carry columns.
    for j in 0..4 {
        let r_j: AB::Expr = next[MSG_M1_R_CARRY_BASE_COL + j].clone().into();
        let w_lo: AB::Expr = local[msg_word_col(2 * j)].clone().into();
        let w_hi: AB::Expr = local[msg_word_col(2 * j + 1)].clone().into();
        builder
            .when(is_msg_row0.clone())
            .assert_zero(r_j - w_lo - w_hi * two_pow_32.clone());
    }
    // M1 computes R[4..7] directly into I.
    for j in 0..4 {
        let r_j: AB::Expr = next[IFACE_R_BASE_COL + 4 + j].clone().into();
        let w_lo: AB::Expr = local[msg_word_col(2 * j)].clone().into();
        let w_hi: AB::Expr = local[msg_word_col(2 * j + 1)].clone().into();
        builder
            .when(is_msg_row1.clone())
            .assert_zero(r_j - w_lo - w_hi * two_pow_32.clone());
    }
}

/// Canonicality gadget on M0 / M1: enforce that each `R[k] = lo + 2^32 * hi`
/// uses the *canonical* Goldilocks-u64 representation, i.e. the felt's value
/// in `[0, p)` cannot be aliased by a non-canonical `(lo, hi)` pair where
/// `lo + 2^32 * hi >= p`.
///
/// For each of the 4 felt pairs `(m[2k], m[2k+1])` per M-row, with
/// `lo = m[2k]`, `hi = m[2k+1]`, inverse witness `inv`, and zero flag `z`, let
/// `h = hi - (2^32 - 1)` and enforce:
///
/// ```text
/// h * inv + z - 1 = 0
/// z * h             = 0
/// z * lo            = 0
/// ```
///
/// The first two constraints force `z = 1` iff `hi = 2^32 - 1`; the third
/// then forces `lo = 0` in exactly that case. The message-limb range checks
/// ensure `lo` and `hi` are 32-bit words.
///
/// Gated by `is_msg_row` (= `is_msg_row0 + is_msg_row1`).
pub fn enforce_msg_canonicality<AB>(builder: &mut AB, local: &[AB::Var], sel: &Selectors<AB>)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_msg_row = sel.is_msg_row();
    let max_u32 = AB::Expr::from(Felt::new_unchecked((1u64 << 32) - 1));

    for k in 0..4 {
        let lo: AB::Expr = local[msg_word_col(2 * k)].clone().into();
        let hi: AB::Expr = local[msg_word_col(2 * k + 1)].clone().into();
        let inv: AB::Expr = local[msg_canon_inv_col(k)].clone().into();
        let z: AB::Expr = local[MSG_CANON_Z_BASE_COL + k].clone().into();
        let h = hi - max_u32.clone();

        let builder = &mut builder.when(is_msg_row.clone());
        builder.assert_zero(h.clone() * inv + z.clone() - AB::Expr::ONE);
        builder.assert_zero(z.clone() * h);
        builder.assert_zero(z * lo);
    }
}
