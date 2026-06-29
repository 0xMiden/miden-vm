//! Typed row views over the 80-column BlakeG trace.
//!
//! Every BlakeG row carries one of a handful of distinct slot maps. Rather
//! than thread named slot offsets through call sites, we wrap a `&[AB::Var]`
//! in a typed view (`ACRow`, `BDRow`, `FooterRow`) whose methods expose the
//! columns by their semantic role.
//!
//! Views are zero-cost wrappers; they hold a slice reference and a
//! `PhantomData<AB>` and exist only at compile time. Method calls return
//! `AB::Expr` constructed from the underlying variable.
//!
//! Physical column positions live in `layout.rs`. Computed expressions, such
//! as `xor1[j] = d[j] + a_new[j] - 2*and1[j]`, are exposed as methods so they
//! are written once and reused across constraints.

use core::marker::PhantomData;

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::LiftedAirBuilder;

use super::layout::{
    AC_A_BASE_COL, AC_B_BASE_COL, AC_C_BASE_COL, AC_K3_BIT0_BASE_COL, AC_K3_BIT1_BASE_COL,
    AC_MSG_SLOT_BASE_COL, BD_A_BASE_COL, BD_D_BASE_COL, BD_K2_BASE_COL, BYTE_SLOT_WIDTH,
    BYTES_PER_WORD, FIRST_B_HIN_PAIR2_BASE_COL, FIRST_B_HIN_PAIR3_BASE_COL, FOOTER_C_BASE_COL,
    FOOTER_D_BASE_COL, FOOTER_H_CANON_INV_COL, FOOTER_H_CANON_Z_COL, FOOTER_H_EVEN_WORD_COL,
    FOOTER_H_ODD_WORD_COL, FOOTER_OUT_MASKED_TOP_BIT_COL, FOOTER_OUT_ODD_TOP_BYTE_COL,
    FOOTER_ROW_INDEX_COL, NUM_G, byte_slot_base, footer_future_w_col,
};

// ===================================================================
// Footer constants
// ===================================================================

// Multiplicative inverse of 128 in the base field.
const FOOTER_TOP_BIT_MASK_INV: Felt = Felt::new_unchecked(18302628881372282881);

// ===================================================================
// Small packing helpers
// ===================================================================

#[inline]
fn felt<AB: LiftedAirBuilder<F = Felt>>(v: u64) -> AB::Expr {
    AB::Expr::from(Felt::new_unchecked(v))
}

/// `b0 + 256*b1 + 65536*b2 + 16777216*b3`, with each `b_j` a byte expression.
#[inline]
pub(super) fn pack4_bytes<AB: LiftedAirBuilder<F = Felt>>(
    b0: AB::Expr,
    b1: AB::Expr,
    b2: AB::Expr,
    b3: AB::Expr,
) -> AB::Expr {
    b0 + b1 * felt::<AB>(256) + b2 * felt::<AB>(256 * 256) + b3 * felt::<AB>(256 * 256 * 256)
}

// ===================================================================
// A / C row view
// ===================================================================

/// View of a row whose locals are `add3 + xor + rot` (A or C row).
///
/// A rows use rotation-by-16; C rows use rotation-by-8. The slot layout is
/// identical between A and C; the rotation choice drives only which computed
/// expression the consumer calls.
pub struct ACRow<'a, AB: LiftedAirBuilder<F = Felt>> {
    cols: &'a [AB::Var],
    _phantom: PhantomData<AB>,
}

impl<'a, AB: LiftedAirBuilder<F = Felt>> ACRow<'a, AB> {
    /// Wrap a row slice as an A/C view. The caller is responsible for using an
    /// A or C row; the view itself does not gate by row type.
    pub fn new(cols: &'a [AB::Var]) -> Self {
        Self { cols, _phantom: PhantomData }
    }

    #[inline]
    fn col(&self, idx: usize) -> AB::Expr {
        Into::<AB::Expr>::into(self.cols[idx])
    }

    /// `a` input of G_g.
    pub fn a(&self, g: usize) -> AB::Expr {
        debug_assert!(g < NUM_G);
        self.col(AC_A_BASE_COL + g)
    }

    /// `b` input of G_g.
    pub fn b(&self, g: usize) -> AB::Expr {
        debug_assert!(g < NUM_G);
        self.col(AC_B_BASE_COL + g)
    }

    /// `c` input of G_g.
    pub fn c(&self, g: usize) -> AB::Expr {
        debug_assert!(g < NUM_G);
        self.col(AC_C_BASE_COL + g)
    }

    /// Message word `x` (on A row) or `y` (on C row) used by G_g.
    pub fn msg(&self, g: usize) -> AB::Expr {
        debug_assert!(g < NUM_G);
        self.col(AC_MSG_SLOT_BASE_COL + BYTE_SLOT_WIDTH * g + 1)
    }

    /// Message word index paired with [`Self::msg`].
    pub fn msg_index(&self, g: usize) -> AB::Expr {
        debug_assert!(g < NUM_G);
        self.col(AC_MSG_SLOT_BASE_COL + BYTE_SLOT_WIDTH * g)
    }

    /// 33rd-bit carry of `a + b + msg`, reconstructed from two Boolean bits.
    pub fn k3(&self, g: usize) -> AB::Expr {
        self.k3_bit0(g) + felt::<AB>(2) * self.k3_bit1(g)
    }

    /// Low bit of the ternary carry decomposition `k3 = bit0 + 2*bit1`.
    pub fn k3_bit0(&self, g: usize) -> AB::Expr {
        debug_assert!(g < NUM_G);
        self.col(AC_K3_BIT0_BASE_COL + g)
    }

    /// High bit of the ternary carry decomposition `k3 = bit0 + 2*bit1`.
    pub fn k3_bit1(&self, g: usize) -> AB::Expr {
        debug_assert!(g < NUM_G);
        self.col(AC_K3_BIT1_BASE_COL + g)
    }

    /// `j`-th byte of `d` (LE).
    pub fn d_byte(&self, g: usize, j: usize) -> AB::Expr {
        self.col(byte_slot_base(g, j))
    }

    /// `j`-th byte of `a_new = a + b + msg - 2^32*k3` (LE).
    pub fn a_new_byte(&self, g: usize, j: usize) -> AB::Expr {
        self.col(byte_slot_base(g, j) + 1)
    }

    /// `j`-th byte of the AND witness for `d ^ a_new`. Range-checked and AND-checked by the
    /// AND8 lookup.
    pub fn and1(&self, g: usize, j: usize) -> AB::Expr {
        self.col(byte_slot_base(g, j) + 2)
    }

    // --- computed expressions --------------------------------------------

    /// Result of the add3 step: `a + b + msg - 2^32 * k3`.
    pub fn add3_result_word(&self, g: usize) -> AB::Expr {
        self.a(g) + self.b(g) + self.msg(g) - felt::<AB>(1u64 << 32) * self.k3(g)
    }

    /// Little-endian packing of the four `a_new_byte` values.
    pub fn packed_a_new_bytes(&self, g: usize) -> AB::Expr {
        pack4_bytes::<AB>(
            self.a_new_byte(g, 0),
            self.a_new_byte(g, 1),
            self.a_new_byte(g, 2),
            self.a_new_byte(g, 3),
        )
    }

    /// Little-endian packing of the four `d_byte` values.
    pub fn packed_d_bytes(&self, g: usize) -> AB::Expr {
        pack4_bytes::<AB>(
            self.d_byte(g, 0),
            self.d_byte(g, 1),
            self.d_byte(g, 2),
            self.d_byte(g, 3),
        )
    }

    /// `j`-th byte of `xor1 = d ^ a_new`, expressed via the byte-XOR identity
    /// `xor1[j] = d[j] + a_new[j] - 2 * and1[j]`.
    ///
    /// The AND8 lookup binds `and1[j] = d_byte[j] & a_new_byte[j]`.
    pub fn d_xor_a_new_byte(&self, g: usize, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.d_byte(g, j) + self.a_new_byte(g, j) - self.and1(g, j) - self.and1(g, j)
    }

    /// `d_new` after rot16 (used on A rows): packed bytes
    /// `(xor1[2], xor1[3], xor1[0], xor1[1])`.
    pub fn rot16_d_xor_a_new_word(&self, g: usize) -> AB::Expr {
        pack4_bytes::<AB>(
            self.d_xor_a_new_byte(g, 2),
            self.d_xor_a_new_byte(g, 3),
            self.d_xor_a_new_byte(g, 0),
            self.d_xor_a_new_byte(g, 1),
        )
    }

    /// `d_new` after rot8 (used on C rows): packed bytes
    /// `(xor1[1], xor1[2], xor1[3], xor1[0])`.
    pub fn rot8_d_xor_a_new_word(&self, g: usize) -> AB::Expr {
        pack4_bytes::<AB>(
            self.d_xor_a_new_byte(g, 1),
            self.d_xor_a_new_byte(g, 2),
            self.d_xor_a_new_byte(g, 3),
            self.d_xor_a_new_byte(g, 0),
        )
    }
}

// ===================================================================
// B / D row view
// ===================================================================

/// View of a row whose locals are `add2 + rot` (B or D row).
///
/// B rows use rotation-by-12; D rows use rotation-by-7. The byte-pair lookup
/// binds each slot's contribution to the selected rotation and byte position.
pub struct BDRow<'a, AB: LiftedAirBuilder<F = Felt>> {
    cols: &'a [AB::Var],
    _phantom: PhantomData<AB>,
}

impl<'a, AB: LiftedAirBuilder<F = Felt>> BDRow<'a, AB> {
    pub fn new(cols: &'a [AB::Var]) -> Self {
        Self { cols, _phantom: PhantomData }
    }

    #[inline]
    fn col(&self, idx: usize) -> AB::Expr {
        Into::<AB::Expr>::into(self.cols[idx])
    }

    /// `a` input of G_g (carried unchanged across the B/D step).
    pub fn a(&self, g: usize) -> AB::Expr {
        debug_assert!(g < NUM_G);
        self.col(BD_A_BASE_COL + g)
    }

    /// `d` input of G_g (carried as packed word).
    pub fn d(&self, g: usize) -> AB::Expr {
        debug_assert!(g < NUM_G);
        self.col(BD_D_BASE_COL + g)
    }

    /// 33rd-bit carry of `c + d`. Constrained Boolean.
    pub fn k2(&self, g: usize) -> AB::Expr {
        debug_assert!(g < NUM_G);
        self.col(BD_K2_BASE_COL + g)
    }

    /// `j`-th byte of `b` input (LE).
    pub fn b_byte(&self, g: usize, j: usize) -> AB::Expr {
        self.col(byte_slot_base(g, j))
    }

    /// `j`-th byte of `c_new = c + d mod 2^32` (LE).
    pub fn c_new_byte(&self, g: usize, j: usize) -> AB::Expr {
        self.col(byte_slot_base(g, j) + 1)
    }

    /// Contribution of byte position `j` to the rotated `b ^ c_new` word.
    ///
    /// The byte-pair lookup binds this to `rotr((b_byte[j] ^ c_new_byte[j]) << (8*j), r)`,
    /// where `r` is 12 on B rows and 7 on D rows.
    pub fn rot_contribution(&self, g: usize, j: usize) -> AB::Expr {
        self.col(byte_slot_base(g, j) + 2)
    }

    // --- computed expressions --------------------------------------------

    /// Little-endian packing of the four `b_byte` values.
    pub fn packed_b_bytes(&self, g: usize) -> AB::Expr {
        pack4_bytes::<AB>(
            self.b_byte(g, 0),
            self.b_byte(g, 1),
            self.b_byte(g, 2),
            self.b_byte(g, 3),
        )
    }

    /// Little-endian packing of the four `c_new_byte` values.
    pub fn packed_c_new_bytes(&self, g: usize) -> AB::Expr {
        pack4_bytes::<AB>(
            self.c_new_byte(g, 0),
            self.c_new_byte(g, 1),
            self.c_new_byte(g, 2),
            self.c_new_byte(g, 3),
        )
    }

    /// Routed HIN pair index on the first B row.
    pub fn first_b_hin_pair_index(&self, pair_idx: usize) -> AB::Expr {
        self.col(first_b_hin_pair_base(pair_idx))
    }

    /// Even word in a routed HIN pair on the first B row.
    pub fn first_b_hin_even_word(&self, pair_idx: usize) -> AB::Expr {
        self.col(first_b_hin_pair_base(pair_idx) + 1)
    }

    /// Odd word in a routed HIN pair on the first B row.
    pub fn first_b_hin_odd_word(&self, pair_idx: usize) -> AB::Expr {
        self.col(first_b_hin_pair_base(pair_idx) + 2)
    }

    /// `b_new` after the B/D rotation selected by the lookup bus.
    ///
    /// The row view only sums byte contributions. The lookup bus fixes whether
    /// those contributions are rot12 (B rows) or rot7 (D rows).
    pub fn rotated_b_xor_c_new_word(&self, g: usize) -> AB::Expr {
        (0..BYTES_PER_WORD).fold(AB::Expr::ZERO, |acc, j| acc + self.rot_contribution(g, j))
    }
}

#[inline]
fn first_b_hin_pair_base(pair_idx: usize) -> usize {
    match pair_idx {
        2 => FIRST_B_HIN_PAIR2_BASE_COL,
        3 => FIRST_B_HIN_PAIR3_BASE_COL,
        _ => panic!("first-B HIN pair index must be 2 or 3"),
    }
}

// ===================================================================
// Footer row view (F0..F3)
// ===================================================================

/// View of a footer row `F_t` for `t = 0..3`.
///
/// Footer rows use the fixed byte-slot bank. Output bytes are computed from the
/// `v_lo`, `v_hi`, and AND-witness fields; they are not stored as a separate
/// byte block.
pub struct FooterRow<'a, AB: LiftedAirBuilder<F = Felt>> {
    cols: &'a [AB::Var],
    _phantom: PhantomData<AB>,
}

impl<'a, AB: LiftedAirBuilder<F = Felt>> FooterRow<'a, AB> {
    pub fn new(cols: &'a [AB::Var]) -> Self {
        Self { cols, _phantom: PhantomData }
    }

    #[inline]
    fn col(&self, idx: usize) -> AB::Expr {
        Into::<AB::Expr>::into(self.cols[idx])
    }

    /// Input-chaining-value accumulator slot `C[t]` for `t = 0..3`.
    pub fn c(&self, t: usize) -> AB::Expr {
        debug_assert!(t < 4);
        self.col(FOOTER_C_BASE_COL + t)
    }

    /// Output-digest accumulator slot `D[t]` for `t = 0..3`.
    pub fn d(&self, t: usize) -> AB::Expr {
        debug_assert!(t < 4);
        self.col(FOOTER_D_BASE_COL + t)
    }

    /// Queued future W word. On F_t this stores words needed by later footer rows.
    pub fn future_w(&self, idx: usize) -> AB::Expr {
        debug_assert!(idx < 12);
        self.col(footer_future_w_col(idx))
    }

    /// Footer-row index field used by the HIN-pair slot.
    pub fn row_index(&self) -> AB::Expr {
        self.col(FOOTER_ROW_INDEX_COL)
    }

    /// Stored even H word, bound to the row's `H_even` bytes.
    pub fn stored_h_even_word(&self) -> AB::Expr {
        self.col(FOOTER_H_EVEN_WORD_COL)
    }

    /// Stored odd H word, bound to the row's `H_odd` bytes.
    pub fn stored_h_odd_word(&self) -> AB::Expr {
        self.col(FOOTER_H_ODD_WORD_COL)
    }

    /// `j`-th byte of `H_even` (= `h[2t]`) used by the row's XOR derivation.
    pub fn h_even_byte(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.col(3 * j + 1)
    }

    /// `j`-th byte of `H_odd` (= `h[2t+1]`).
    pub fn h_odd_byte(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.col(3 * (4 + j) + 1)
    }

    /// `j`-th byte of `Vlo_even` (= `v[2t]`).
    pub fn vlo_even_byte(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.col(3 * (8 + j))
    }

    /// `j`-th byte of `Vlo_odd` (= `v[2t+1]`).
    pub fn vlo_odd_byte(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.col(3 * (12 + j))
    }

    /// `j`-th byte of `Vhi_even` (= `v[8 + 2t]`).
    pub fn vhi_even_byte(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.col(3 * j)
    }

    /// `j`-th byte of `Vhi_odd` (= `v[8 + 2t + 1]`).
    pub fn vhi_odd_byte(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.col(3 * (4 + j))
    }

    /// `j`-th duplicated `Vhi_even` byte used by the output AND slot.
    pub fn vhi_even_output_byte(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.col(3 * (8 + j) + 1)
    }

    /// `j`-th duplicated `Vhi_odd` byte used by the output AND slot.
    pub fn vhi_odd_output_byte(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.col(3 * (12 + j) + 1)
    }

    /// `j`-th byte of `Out_even` (= `y[2t]`), computed from the output slot.
    pub fn out_even_byte(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.vlo_even_byte(j) + self.vhi_even_output_byte(j) - felt::<AB>(2) * self.a1_even(j)
    }

    /// `j`-th byte of `Out_odd` (= `y[2t + 1]`), computed from the output slot.
    pub fn out_odd_byte(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.vlo_odd_byte(j) + self.vhi_odd_output_byte(j) - felt::<AB>(2) * self.a1_odd(j)
    }

    /// `j`-th byte of the BlakeG output AND witness `a1 = v_lo & v_hi` (even half).
    /// Used by `out_even_byte`; the AND8 lookup binds `a1[j] = v_lo[j] & v_hi[j]`.
    pub fn a1_even(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.col(3 * (8 + j) + 2)
    }

    /// `j`-th byte of the BlakeG output AND witness `a1 = v_lo & v_hi` (odd half).
    /// See `a1_even` for the companion XOR identity and soundness notes.
    pub fn a1_odd(&self, j: usize) -> AB::Expr {
        debug_assert!(j < BYTES_PER_WORD);
        self.col(3 * (12 + j) + 2)
    }

    /// Inverse-or-zero witness for the input-CV canonicality check.
    pub fn h_canon_inv(&self) -> AB::Expr {
        self.col(FOOTER_H_CANON_INV_COL)
    }

    /// Zero flag for the input-CV canonicality check.
    pub fn h_canon_z(&self) -> AB::Expr {
        self.col(FOOTER_H_CANON_Z_COL)
    }

    /// Duplicated `Out_odd[3]` field used by the output top-bit lookup.
    pub fn out_odd_top_byte(&self) -> AB::Expr {
        self.col(FOOTER_OUT_ODD_TOP_BYTE_COL)
    }

    /// Masked top-bit field `Out_odd[3] & 128`.
    pub fn masked_top_bit(&self) -> AB::Expr {
        self.col(FOOTER_OUT_MASKED_TOP_BIT_COL)
    }

    /// Top bit of `Out_odd[3]`. Constrained Boolean and bound to the actual
    /// top bit by the footer top-bit lookup.
    pub fn out_odd_top_bit_flag(&self) -> AB::Expr {
        self.masked_top_bit() * AB::Expr::from(FOOTER_TOP_BIT_MASK_INV)
    }

    // --- computed expressions --------------------------------------------

    /// `Vlo_even` packed into a u32 word.
    pub fn packed_vlo_even_bytes(&self) -> AB::Expr {
        pack4_bytes::<AB>(
            self.vlo_even_byte(0),
            self.vlo_even_byte(1),
            self.vlo_even_byte(2),
            self.vlo_even_byte(3),
        )
    }

    /// `Vlo_odd` packed into a u32 word.
    pub fn packed_vlo_odd_bytes(&self) -> AB::Expr {
        pack4_bytes::<AB>(
            self.vlo_odd_byte(0),
            self.vlo_odd_byte(1),
            self.vlo_odd_byte(2),
            self.vlo_odd_byte(3),
        )
    }

    /// `Vhi_even` packed into a u32 word.
    pub fn packed_vhi_even_bytes(&self) -> AB::Expr {
        pack4_bytes::<AB>(
            self.vhi_even_byte(0),
            self.vhi_even_byte(1),
            self.vhi_even_byte(2),
            self.vhi_even_byte(3),
        )
    }

    /// `Vhi_odd` packed into a u32 word.
    pub fn packed_vhi_odd_bytes(&self) -> AB::Expr {
        pack4_bytes::<AB>(
            self.vhi_odd_byte(0),
            self.vhi_odd_byte(1),
            self.vhi_odd_byte(2),
            self.vhi_odd_byte(3),
        )
    }

    /// `H_even` packed into a u32 word (raw, no top-bit mask).
    pub fn packed_h_even_bytes(&self) -> AB::Expr {
        pack4_bytes::<AB>(
            self.h_even_byte(0),
            self.h_even_byte(1),
            self.h_even_byte(2),
            self.h_even_byte(3),
        )
    }

    /// `H_odd` packed into a u32 word (raw, no top-bit mask).
    pub fn packed_h_odd_bytes(&self) -> AB::Expr {
        pack4_bytes::<AB>(
            self.h_odd_byte(0),
            self.h_odd_byte(1),
            self.h_odd_byte(2),
            self.h_odd_byte(3),
        )
    }

    /// `Out_even` packed into a u32 word.
    pub fn packed_out_even_bytes(&self) -> AB::Expr {
        pack4_bytes::<AB>(
            self.out_even_byte(0),
            self.out_even_byte(1),
            self.out_even_byte(2),
            self.out_even_byte(3),
        )
    }

    /// `Out_odd` packed into a u32 word, with the top bit stripped into the
    /// `out_odd_top_bit_flag` witness.
    pub fn packed_masked_out_odd_bytes(&self) -> AB::Expr {
        let masked_msb = self.out_odd_byte(3) - self.masked_top_bit();
        pack4_bytes::<AB>(
            self.out_odd_byte(0),
            self.out_odd_byte(1),
            self.out_odd_byte(2),
            masked_msb,
        )
    }

    /// Felt-level packing of `H_even || H_odd` for the row's `C[t]` definition.
    /// `C[t] = H_even_word + 2^32 * H_odd_word`.
    pub fn packed_c_from_stored_h_words(&self) -> AB::Expr {
        self.stored_h_even_word() + self.stored_h_odd_word() * felt::<AB>(1u64 << 32)
    }

    /// Felt-level packing of `Out_even || Out_odd_masked` for `D[t]`.
    /// `D[t] = Out_even_word + 2^32 * Out_odd_masked_word`.
    pub fn packed_d_from_output_bytes(&self) -> AB::Expr {
        self.packed_out_even_bytes() + self.packed_masked_out_odd_bytes() * felt::<AB>(1u64 << 32)
    }
}

#[cfg(test)]
mod tests {
    use super::{super::FOOTER_TOP_BIT_MASK, *};

    #[test]
    fn precomputed_footer_mask_inverse_is_correct() {
        assert_eq!(
            Felt::new_unchecked(FOOTER_TOP_BIT_MASK as u64) * FOOTER_TOP_BIT_MASK_INV,
            Felt::ONE
        );
    }
}

// ===================================================================
// Interface input row view (I, row 62)
// ===================================================================
