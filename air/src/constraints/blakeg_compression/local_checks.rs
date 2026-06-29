//! Per-row local constraints: carry checks, message binding, footer top-bit
//! Booleanity, accumulator zero-init, and IV initialization.
//!
//! These constraints use only the current row. Keeping them separate gives
//! each row-local binding a focused test surface.

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::{AirBuilder, LiftedAirBuilder};

use super::{
    AEAD_XOF_CLK_COL, AEAD_XOF_MODE_COL, FOOTER_C_BASE_COL, FOOTER_D_BASE_COL, FOOTER_SPARE_COL,
    layout::NUM_G,
    selectors::Selectors,
    views::{ACRow, BDRow, FooterRow},
};

/// BlakeG IV (the 8 fractional-bit constants of `sqrt(p)` for the first eight
/// primes). The chiplet trace seeds `v[8..15] = IV[0..7]` at row 0; this AIR
/// constant must match `processor::trace::chiplets::blakeg_trace::IV` and
/// `vendor/miden-crypto/src/hash/blakeg.rs::IV` exactly.
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// `k3 in {0, 1, 2}` carry check on A/C rows.
///
/// `k3` is the 33rd-bit overflow of `a + b + msg` (sum of three 32-bit
/// values, so carry can be 0, 1, or 2). We decompose it as
/// `k3 = bit0 + 2 * bit1` with mutually exclusive Boolean bits. This keeps
/// the row-gated constraints at degree 3.
pub fn enforce_ac_k3_ternary<AB>(builder: &mut AB, ac_local: &ACRow<AB>, sel: &Selectors<AB>)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_ac = sel.is_ac();
    let two = AB::Expr::from(Felt::new_unchecked(2));
    for g in 0..NUM_G {
        let builder = &mut builder.when(is_ac.clone());
        let k3 = ac_local.k3(g);
        let bit0 = ac_local.k3_bit0(g);
        let bit1 = ac_local.k3_bit1(g);

        builder.assert_zero(bit0.clone() * (AB::Expr::ONE - bit0.clone()));
        builder.assert_zero(bit1.clone() * (AB::Expr::ONE - bit1.clone()));
        builder.assert_zero(bit0.clone() * bit1.clone());
        builder.assert_zero(k3 - bit0 - two.clone() * bit1);
    }
}

/// Bind the byte witness used by the XOR path to the add3 arithmetic word.
///
/// The AND lookup only proves that `a_new_byte[j]` is a byte and that `and1[j]` is
/// `d_byte[j] & a_new_byte[j]`. This local check makes those bytes the same value as
/// `a + b + msg - 2^32*k3`, which is forwarded as the next `a` word.
pub fn enforce_ac_a_new_bytes_match_word<AB>(
    builder: &mut AB,
    ac_local: &ACRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_ac = sel.is_ac();
    for g in 0..NUM_G {
        builder
            .when(is_ac.clone())
            .assert_zero(ac_local.packed_a_new_bytes(g) - ac_local.add3_result_word(g));
    }
}

/// Pin each A/C row to the BlakeG SIGMA message schedule.
///
/// The message-word bus balances the global multiset of consumed message words. This local
/// constraint supplies the missing positional binding: lane `g` on each A/C row must use the
/// schedule index fixed by the row's round and half-round.
pub fn enforce_ac_message_schedule<AB>(builder: &mut AB, ac_local: &ACRow<AB>, sel: &Selectors<AB>)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_ac = sel.is_ac();
    for g in 0..NUM_G {
        builder
            .when(is_ac.clone())
            .assert_zero(ac_local.msg_index(g) - sel.sigma_msg_index(g));
    }
}

/// `k2 in {0, 1}` Boolean carry check on B/D rows.
///
/// `k2` is the 33rd-bit overflow of `c + d` (sum of two 32-bit values, carry
/// is 0 or 1).
pub fn enforce_bd_k2_binary<AB>(builder: &mut AB, bd_local: &BDRow<AB>, sel: &Selectors<AB>)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_bd = sel.is_bd();
    for g in 0..NUM_G {
        let k2 = bd_local.k2(g);
        builder.when(is_bd.clone()).assert_zero(k2.clone() * (AB::Expr::ONE - k2));
    }
}

/// Bind routed HIN pairs 2 and 3 to the byte-decomposed first-B `b` lanes.
///
/// Pair 0 and pair 1 are emitted directly from row 0 `A.a`. Pair 2 and pair 3
/// are routed through narrow slots 16 and 17 on the first B row. These
/// equalities make the routed fields inherit the byte range checks already
/// applied to `B.b`.
pub fn enforce_first_b_hin_matches_b_words<AB>(
    builder: &mut AB,
    bd_local: &BDRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_first_b = sel.is_first_b();
    let two = AB::Expr::from(Felt::new_unchecked(2));
    let three = AB::Expr::from(Felt::new_unchecked(3));
    let builder = &mut builder.when(is_first_b);

    builder.assert_zero(bd_local.first_b_hin_pair_index(2) - two);
    builder.assert_zero(bd_local.first_b_hin_even_word(2) - bd_local.packed_b_bytes(0));
    builder.assert_zero(bd_local.first_b_hin_odd_word(2) - bd_local.packed_b_bytes(1));

    builder.assert_zero(bd_local.first_b_hin_pair_index(3) - three);
    builder.assert_zero(bd_local.first_b_hin_even_word(3) - bd_local.packed_b_bytes(2));
    builder.assert_zero(bd_local.first_b_hin_odd_word(3) - bd_local.packed_b_bytes(3));
}

/// Footer output-top-bit Boolean check.
///
/// The flag is Boolean on every footer row. The AND8 lookup binds it to the
/// actual top bit of `Out_odd[3]`.
pub fn enforce_footer_top_bit_flag_boolean<AB>(
    builder: &mut AB,
    footer_local: &FooterRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let m = footer_local.out_odd_top_bit_flag();
    builder.when(sel.is_footer()).assert_zero(m.clone() * (AB::Expr::ONE - m));
}

/// `v[8..15] = IV[0..7]` initialization on row 0 (the first A-col row of a
/// compression block).
///
/// At row 0, `G_g` operates on `(v[g], v[4+g], v[8+g], v[12+g])`, so:
/// - `c(g) = v[8 + g]` must equal `IV[g]`,
/// - `pack(d_byte[g]) = v[12 + g]` must equal `IV[4 + g]`.
///
/// `v[0..7]` is the chaining value `h[0..7]` and is bound by the
/// input-chaining relation; but `v[8..15]` is not exposed on any bus, so
/// without this constraint an adversarial trace can replace those eight u32
/// slots with arbitrary values and produce a trace for the wrong initial
/// state. Gating by `is_first_comp` (1 only on row 0) makes this a local
/// degree-2 constraint.
pub fn enforce_iv_init<AB>(builder: &mut AB, ac_local: &ACRow<AB>, sel: &Selectors<AB>)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_first = sel.is_first_comp();
    for g in 0..NUM_G {
        let builder = &mut builder.when(is_first.clone());
        let iv_c = AB::Expr::from(Felt::new_unchecked(IV[g] as u64));
        let iv_d = AB::Expr::from(Felt::new_unchecked(IV[4 + g] as u64));
        builder.assert_zero(ac_local.c(g) - iv_c);
        builder.assert_zero(ac_local.packed_d_bytes(g) - iv_d);
    }
}

/// Footer tail constraints: mode Booleanity, packed-mode clock gating, and spare-column zero.
pub fn enforce_footer_tail_constraints<AB>(builder: &mut AB, local: &[AB::Var], sel: &Selectors<AB>)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_footer = sel.is_footer();
    let builder = &mut builder.when(is_footer);
    let mode: AB::Expr = local[AEAD_XOF_MODE_COL].into();
    let inactive = AB::Expr::ONE - mode.clone();

    builder.assert_zero(mode.clone() * inactive.clone());
    builder.assert_zero(inactive * Into::<AB::Expr>::into(local[AEAD_XOF_CLK_COL]));
    builder.assert_zero(Into::<AB::Expr>::into(local[FOOTER_SPARE_COL]));
}

/// Footer accumulator zero-initialization on F0, F1, F2.
///
/// The C[*] and D[*] accumulators are filled progressively across F0..F3.
/// On any row before the slot is written, that slot must read zero, so an
/// adversary cannot smuggle a non-zero "initial" accumulator value.
///
/// - F0 writes C[0] and D[0]; the remaining C/D slots must be zero.
/// - F1 writes C[1] and D[1]; slots 2 and 3 must be zero.
/// - F2 writes C[2] and D[2]; C[3] and D[3] must be zero on F2.
/// - F3 writes C[3] and D[3]; nothing is required to be zero on F3.
pub fn enforce_footer_accumulator_zero_init<AB>(
    builder: &mut AB,
    local: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_f0 = sel.is_f(0);
    let is_f1 = sel.is_f(1);
    let is_f2 = sel.is_f(2);
    let gates = [is_f0.clone(), is_f0.clone() + is_f1.clone(), is_f0 + is_f1 + is_f2];

    for (idx, gate) in gates.iter().enumerate() {
        let t = idx + 1;
        let builder = &mut builder.when(gate.clone());
        builder.assert_zero(Into::<AB::Expr>::into(local[FOOTER_C_BASE_COL + t]));
        builder.assert_zero(Into::<AB::Expr>::into(local[FOOTER_D_BASE_COL + t]));
    }
}
