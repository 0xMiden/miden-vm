//! Per-row local constraints: carry checks, message binding, mask_bit Boolean,
//! footer accumulator zero-init, and IV initialization.
//!
//! These are the "no transition needed, same row" constraints. Splitting them
//! out makes the row-by-row sanity checks easy to audit independently of the
//! more involved row-to-row transition logic.

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::{AirBuilder, LiftedAirBuilder};

use super::selectors::Selectors;
use super::views::{ACRow, BDRow, FooterRow, NUM_G};
use super::{FOOTER_C_BASE_COL, FOOTER_D_BASE_COL, FOOTER_SPARE_COL, TAIL_CLK_COL, TAIL_LABEL_COL};

/// BlakeG IV (the 8 fractional-bit constants of `sqrt(p)` for the first eight
/// primes). The chiplet trace seeds `v[8..16] = IV[0..8]` at row 0; this AIR
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
            .assert_zero(ac_local.a_new_byte_word(g) - ac_local.a_new_word(g));
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
/// Pair 0 and pair 1 are emitted directly from row-0 `A.a`. Pair 2 and pair 3
/// are routed through spare fields on the first B row, so they need this local
/// equality to inherit the byte range checks already applied to `B.b`.
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
    builder.assert_zero(bd_local.first_b_hin_even_word(2) - bd_local.b_word(0));
    builder.assert_zero(bd_local.first_b_hin_odd_word(2) - bd_local.b_word(1));

    builder.assert_zero(bd_local.first_b_hin_pair_index(3) - three);
    builder.assert_zero(bd_local.first_b_hin_even_word(3) - bd_local.b_word(2));
    builder.assert_zero(bd_local.first_b_hin_odd_word(3) - bd_local.b_word(3));
}

/// Footer `mask_bit` Boolean check.
///
/// `mask_bit in {0, 1}` on every footer row. The Boolean form is enforced here; the AND8 lookup
/// binds it to the actual top bit of `Out_odd[3]`.
pub fn enforce_footer_mask_bit_boolean<AB>(
    builder: &mut AB,
    footer_local: &FooterRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let m = footer_local.mask_bit();
    builder.when(sel.is_footer()).assert_zero(m.clone() * (AB::Expr::ONE - m));
}

/// `v[8..16] = IV[0..8]` initialization on row 0 (the first A-col row of a
/// compression block).
///
/// At row 0, `G_g` operates on `(v[g], v[4+g], v[8+g], v[12+g])`, so:
/// - `c(g) = v[8 + g]` must equal `IV[g]`,
/// - `d_word(g) = v[12 + g]` must equal `IV[4 + g]`.
///
/// `v[0..8]` is the chaining value `h[0..8]` and is bound by the LogUp HIN
/// bus (in `blakeg_air.rs`); but `v[8..16]` is *not* exposed on any bus, so
/// without this constraint an adversarial trace could replace those eight u32
/// slots with arbitrary values and produce a valid-looking compression that
/// is not actually BlakeG. Gating by `is_first_comp` (1 only on row 0) makes
/// this a pure local constraint of degree 2.
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
        builder.assert_zero(ac_local.d_word(g) - iv_d);
    }
}

/// Footer tail constraints for columns unused by the packed-output interface.
pub fn enforce_footer_tail_constraints<AB>(builder: &mut AB, local: &[AB::Var], sel: &Selectors<AB>)
where
    AB: LiftedAirBuilder<F = Felt>,
{
    let is_footer = sel.is_footer();
    let builder = &mut builder.when(is_footer);

    for col in [TAIL_LABEL_COL, TAIL_CLK_COL, FOOTER_SPARE_COL] {
        builder.assert_zero(Into::<AB::Expr>::into(local[col].clone()));
    }
}

/// Footer accumulator zero-initialization on F0, F1, F2.
///
/// The C[*] and D[*] accumulators are filled progressively across F0..F3.
/// On any row before the slot is written, that slot must read zero, so an
/// adversary cannot smuggle a non-zero "initial" accumulator value.
///
/// - F0 writes C[0] and D[0]; C[1..4] and D[1..4] must be zero on F0.
/// - F1 writes C[1] and D[1]; C[2..4] and D[2..4] must be zero on F1.
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
        builder.assert_zero(Into::<AB::Expr>::into(local[FOOTER_C_BASE_COL + t].clone()));
        builder.assert_zero(Into::<AB::Expr>::into(local[FOOTER_D_BASE_COL + t].clone()));
    }
}
