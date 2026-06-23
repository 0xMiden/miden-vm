//! Half-round boundary (D -> next-A) and last-row -> F0 binding.
//!
//! At a D-row we have the partial output `(a, b_new, c_new, d)` for each G_g.
//! The next row starts a fresh A-row, but the lane mapping from G_g to the
//! `(a, b, c, d)` slots changes between half-rounds:
//!
//! - **Column -> diagonal** (rows 3 -> 4): `a[g] -> a[g]`, `b[g] -> b[(g+3)%4]`,
//!   `c[g] -> c[(g+2)%4]`, `d[g] -> d[(g+1)%4]`.
//! - **Diagonal -> column** (rows 7 -> 0 of the next round): `a[g] -> a[g]`,
//!   `b[g] -> b[(g+1)%4]`, `c[g] -> c[(g+2)%4]`, `d[g] -> d[(g+3)%4]`.
//!
//! The very last D-diagonal row (row 55) has no next-A to forward into. It
//! instead binds the final working state into F0's `W[0..15]` columns,
//! using the *diagonal -> column* index mapping (so `W[g] = a[g]`,
//! `W[4 + (g+1)%4] = b_new[g]`, `W[8 + (g+2)%4] = c_new[g]`,
//! `W[12 + (g+3)%4] = d[g]`).

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::{AirBuilder, LiftedAirBuilder};

use super::selectors::Selectors;
use super::views::{ACRow, BDRow, FooterRow, NUM_G};

/// D -> next-A remap for both half-round boundaries.
pub fn enforce_d_to_next_a<AB>(
    builder: &mut AB,
    d_local: &BDRow<AB>,
    a_next: &ACRow<AB>,
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let gate = sel.gate_d_to_next_a();
    let is_diag = sel.is_diag();
    let is_col = AB::Expr::ONE - is_diag.clone();

    for g in 0..NUM_G {
        let builder = &mut builder.when(gate.clone());
        let b_rot7 = d_local.rotated_b_xor_c_new_word(g);
        let c_new = d_local.packed_c_new_bytes(g);

        let next_b = is_col.clone() * a_next.b((g + 3) % NUM_G)
            + is_diag.clone() * a_next.b((g + 1) % NUM_G);
        let next_d = is_col.clone() * a_next.packed_d_bytes((g + 1) % NUM_G)
            + is_diag.clone() * a_next.packed_d_bytes((g + 3) % NUM_G);

        // a[g] -> a[g]
        builder.assert_zero(d_local.a(g) - a_next.a(g));
        // b uses the column/diagonal remap selected by `is_diag`.
        builder.assert_zero(b_rot7 - next_b);
        // c_new[g] -> c[(g+2)%4]
        builder.assert_zero(c_new - a_next.c((g + 2) % NUM_G));
        // d uses the column/diagonal remap selected by `is_diag`.
        builder.assert_zero(d_local.d(g) - next_d);
    }
}

/// Final D-diagonal row (row 55) -> F0.W[0..15].
///
/// Uses the *diagonal -> column* index mapping (the final state lands in the
/// column ordering, so the bus sees the canonical state at the end of round 7).
pub fn enforce_last_d_to_f0<AB>(
    builder: &mut AB,
    d_local: &BDRow<AB>,
    f0_next: &[AB::Var],
    sel: &Selectors<AB>,
) where
    AB: LiftedAirBuilder<F = Felt>,
{
    let gate = sel.gate_last_d();
    let f0 = FooterRow::<AB>::new(f0_next);
    let b_words: [AB::Expr; NUM_G] = core::array::from_fn(|g| d_local.rotated_b_xor_c_new_word(g));
    let c_words: [AB::Expr; NUM_G] = core::array::from_fn(|g| d_local.packed_c_new_bytes(g));

    // The final D row is diagonal. Undo the diagonal lane placement so F0 sees
    // the canonical W[0..15] order.
    let final_w = |idx: usize| -> AB::Expr {
        match idx {
            0..=3 => d_local.a(idx),
            4..=7 => b_words[(idx - 1) % NUM_G].clone(),
            8..=11 => c_words[(idx - 6) % NUM_G].clone(),
            12..=15 => d_local.d((idx - 11) % NUM_G),
            _ => unreachable!("BlakeG W index must be in 0..=15"),
        }
    };

    let builder = &mut builder.when(gate);
    builder.assert_zero(f0.packed_vlo_even_bytes() - final_w(0));
    builder.assert_zero(f0.packed_vlo_odd_bytes() - final_w(1));
    builder.assert_zero(f0.packed_vhi_even_bytes() - final_w(8));
    builder.assert_zero(f0.packed_vhi_odd_bytes() - final_w(9));

    // F0 consumes W0,W1,W8,W9 locally; the queue carries the remaining words
    // in the order consumed by F1, F2, and F3.
    let queued = [2, 3, 10, 11, 4, 5, 12, 13, 6, 7, 14, 15];
    for (idx, w_idx) in queued.into_iter().enumerate() {
        builder.assert_zero(f0.future_w(idx) - final_w(w_idx));
    }
}
