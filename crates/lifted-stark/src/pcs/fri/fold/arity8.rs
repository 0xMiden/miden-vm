//! Arity-8 FRI folding using inverse FFT.
//!
//! Given evaluations of a polynomial `f` on a coset `s·⟨ω⟩` where `ω` is a primitive
//! 8th root of unity, we recover the folded value `g(s⁸)` for a challenge `β`
//! (and when `deg f < 8`, this equals `f(β)`).
//!
//! ## Algorithm
//!
//! 1. **Inverse FFT**: Recover coefficients of `f(sX)` from evaluations on `⟨ω⟩`.
//! 2. **Evaluate**: Compute `f(sX)` at `X = β/s`, yielding the folded value `g(s⁸)`.
//!
//! The inverse FFT uses a 3-stage Cooley-Tukey DIT butterfly structure.
//!
//! We decompose `f` by residue class modulo 8:
//! `f(X) = Σⱼ X^j · fⱼ(X⁸)` for j ∈ {0..7}.
//! The folded polynomial is `g(X) = Σⱼ β^j · fⱼ(X)`.

use core::array;

use p3_field::{Algebra, TwoAdicField};

/// Evaluate the folded value `g(s⁸)` from evaluations on a coset
/// (equals `f(β)` when `deg f < 8`).
///
/// ## Inputs
///
/// - `evals`: slice of 8 evaluations `[f(s), f(ω⁴s), f(ω²s), f(ω⁶s), f(ωs), f(ω⁵s), f(ω³s),
///   f(ω⁷s)]` in bit-reversed order, where `ω` is the primitive 8th root of unity.
/// - `s_inv`: the inverse of the coset generator `s`.
/// - `beta`: the FRI folding challenge `β`.
#[inline(always)]
pub fn fold_evals<F, PF, PEF>(evals: &[PEF], s_inv: PF, beta: PEF) -> PEF
where
    F: TwoAdicField,
    PF: Algebra<F> + Algebra<PF>,
    PEF: Algebra<PF>,
{
    debug_assert_eq!(evals.len(), 8, "evals must have 8 elements");
    let evals = array::from_fn(|i| evals[i].clone());
    // Recover coefficients [c₀, ..., c₇] of 8·f(sX) via inverse FFT.
    let coeffs = ifft8::<F, PF, PEF>(evals);

    // Folded value g(s⁸) = (1/8) · Σᵢ cᵢ · xⁱ  where x = β/s.
    let x = beta * s_inv;

    // Compute powers of x efficiently
    let x2 = x.square();
    let x3 = x2.clone() * x.clone();
    let x4 = x2.square();
    let x5 = x4.clone() * x.clone();
    let x6 = x4.clone() * x2.clone();
    let x7 = x4.clone() * x3.clone();

    let terms = [
        coeffs[0].clone(),
        coeffs[1].clone() * x,
        coeffs[2].clone() * x2,
        coeffs[3].clone() * x3,
        coeffs[4].clone() * x4,
        coeffs[5].clone() * x5,
        coeffs[6].clone() * x6,
        coeffs[7].clone() * x7,
    ];

    // Divide by 8
    let eight_inv: PF = F::ONE.halve().halve().halve().into();
    PEF::sum_array::<8>(&terms) * eight_inv
}

/// Size-8 inverse FFT (unscaled), input in bit-reversed order.
///
/// Returns coefficients `[c₀, c₁, ..., c₇]` of `8·f(sX)`.
///
/// Uses DIT butterfly operations following the pattern from [`p3_dft::DitButterfly`].
#[inline(always)]
fn ifft8<F, PF, PEF>(evals: [PEF; 8]) -> [PEF; 8]
where
    F: TwoAdicField,
    PF: Algebra<PF> + Algebra<F>,
    PEF: Algebra<PF>,
{
    // Compute powers of ω₈ needed for inverse twiddles
    let w8 = F::two_adic_generator(3);
    let w8_2 = F::two_adic_generator(2);
    let w8_3 = w8_2 * w8;
    let w8_5 = w8_3 * w8_2;
    let w8_6 = w8_3.square();
    let w8_7 = w8_6 * w8;

    // Inverse twiddles: ω⁻ᵏ = ω^(n-k)
    // Note: ω₄⁻¹ = ω₄³ = (ω₈²)³ = ω₈⁶
    let w4_inv: PF = w8_6.into();
    let w8_inv_1: PF = w8_7.into();
    let w8_inv_2: PF = w8_6.into();
    let w8_inv_3: PF = w8_5.into();

    // Bit-reversed input: [y₀, y₄, y₂, y₆, y₁, y₅, y₃, y₇]
    let [y0, y4, y2, y6, y1, y5, y3, y7] = evals;

    // -------------------------------------------------------------------------
    // Stage 0: 4 twiddle-free butterflies
    // -------------------------------------------------------------------------
    let (a0, a1) = twiddle_free_butterfly(y0, y4);
    let (a2, a3) = twiddle_free_butterfly(y2, y6);
    let (a4, a5) = twiddle_free_butterfly(y1, y5);
    let (a6, a7) = twiddle_free_butterfly(y3, y7);

    // -------------------------------------------------------------------------
    // Stage 1: length-4 butterflies with twiddle ω₄⁻¹
    // -------------------------------------------------------------------------
    let (b0, b2) = twiddle_free_butterfly(a0, a2);
    let (b1, b3) = dit_butterfly(a1, a3, &w4_inv);

    let (b4, b6) = twiddle_free_butterfly(a4, a6);
    let (b5, b7) = dit_butterfly(a5, a7, &w4_inv);

    // -------------------------------------------------------------------------
    // Stage 2: length-8 butterflies with twiddles ω₈⁻ᵏ
    // -------------------------------------------------------------------------
    let (c0, c4) = twiddle_free_butterfly(b0, b4);
    let (c1, c5) = dit_butterfly(b1, b5, &w8_inv_1);
    let (c2, c6) = dit_butterfly(b2, b6, &w8_inv_2);
    let (c3, c7) = dit_butterfly(b3, b7, &w8_inv_3);

    [c0, c1, c2, c3, c4, c5, c6, c7]
}

// ============================================================================
// Butterfly Helpers
// ============================================================================

/// DIT butterfly: `(x1 + twiddle * x2, x1 - twiddle * x2)`
///
/// See [`p3_dft::DitButterfly`] for the standard implementation.
/// This version supports mixed-type operations where values are extension field
/// elements and twiddles are base field elements.
#[inline(always)]
fn dit_butterfly<F: Clone, EF: Algebra<EF> + Algebra<F>>(x1: EF, x2: EF, twiddle: &F) -> (EF, EF) {
    let x2_tw = x2 * twiddle.clone();
    (x1.clone() + x2_tw.clone(), x1 - x2_tw)
}

/// Twiddle-free butterfly: `(x1 + x2, x1 - x2)`
///
/// See [`p3_dft::TwiddleFreeButterfly`] for the standard implementation.
#[inline(always)]
fn twiddle_free_butterfly<F: Algebra<F>>(x1: F, x2: F) -> (F, F) {
    (x1.clone() + x2.clone(), x1 - x2)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use p3_dft::{NaiveDft, TwoAdicSubgroupDft};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_util::reverse_slice_index_bits;
    use rand::{RngExt, SeedableRng, distr::StandardUniform, prelude::SmallRng};

    use super::*;
    use crate::testing::configs::goldilocks_poseidon2::{Felt, QuadFelt};

    /// Test that ifft8 correctly recovers polynomial coefficients from DFT evaluations.
    #[test]
    fn test_ifft8() {
        let mut rng = SmallRng::seed_from_u64(42);

        // Random polynomial coefficients
        let coeffs: [QuadFelt; 8] = array::from_fn(|_| rng.sample(StandardUniform));

        // Compute DFT using NaiveDft (standard order)
        let coeffs_matrix = RowMajorMatrix::new(coeffs.to_vec(), 1);
        let evals_matrix = NaiveDft.dft_batch(coeffs_matrix);
        let mut evals = evals_matrix.values;

        // Convert to bit-reversed order for ifft8
        reverse_slice_index_bits(&mut evals);
        let evals_br: [QuadFelt; 8] = evals.try_into().unwrap();

        // Run ifft8 (returns 8 * coefficients)
        let recovered_scaled = ifft8::<Felt, Felt, QuadFelt>(evals_br);

        // Verify: recovered_scaled[i] == 8 * coeffs[i]
        for (i, (recovered, &original)) in recovered_scaled.iter().zip(coeffs.iter()).enumerate() {
            let expected = original.double().double().double(); // 8 * original
            assert_eq!(*recovered, expected, "Coefficient mismatch at index {i}");
        }
    }
}
