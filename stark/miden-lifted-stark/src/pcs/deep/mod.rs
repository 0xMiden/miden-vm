//! # DEEP Quotient for Lifted FRI
//!
//! DEEP converts evaluation claims into a low-degree test. Given W committed polynomials
//! `{fᵢ}` and claimed evaluations `fᵢ(zⱼ) = vᵢⱼ`, the quotient
//!
//! ```text
//! Q(X) = Σⱼ βʲ · Σᵢ αᵂ⁻¹⁻ⁱ · (vᵢⱼ - fᵢ(X)) / (zⱼ - X)
//! ```
//!
//! is low-degree iff all claims are correct. A false claim creates a pole, detectable by FRI.
//!
//! ## Design Choices
//!
//! **Uniform opening points.** All columns share the same opening points `{zⱼ}`. This enables
//! factoring out `f_reduced(X) = Σᵢ αᵂ⁻¹⁻ⁱ·fᵢ(X)`, so the verifier computes one inner
//! product per query rather than one per column per point.
//!
//! **Two challenges.** Separating α (columns) from β (points) improves soundness. With a
//! single challenge, a cheating prover must avoid collisions among k·m terms; with two,
//! only k+m terms matter. This costs one extra field element in the transcript.
//!
//! **Lifting.** Polynomials of degree d on domain D embed into a larger domain D* via
//! `f(X) ↦ f(Xʳ)` where r = |D*|/|D|. In bit-reversed order, this means each evaluation
//! repeats r times consecutively—implemented by virtual upsampling without data movement.
//!
//! **Verifier's view of lifting.** From the verifier's perspective, all polynomials
//! appear to be evaluated at the same point z on the same domain. The prover computes
//! `fᵢ(zʳ)` for degree-d polynomials, but this equals `fᵢ'(z)` where `fᵢ'(X) = fᵢ(Xʳ)`
//! is the lifted polynomial. This uniformity enables the `f_reduced` factorization.
//!
//! ## Preconditions (caller responsibility)
//!
//! The DEEP constructors assume all opening points are valid: distinct and outside the
//! trace subgroup `H` and the LDE evaluation coset `gK`. Invalid points can trigger
//! division by zero in the barycentric weights. In practice, the outer STARK protocol
//! is expected to enforce this before invoking DEEP.
//!
//! ## Random Linear Combination Convention
//!
//! The batching challenge `α` reduces W columns via Horner evaluation:
//! `f_reduced = horner(α, [f₀, f₁, ..., fᵂ₋₁])`, where columns are flattened
//! across groups and matrices in commitment order. The `horner` function assigns
//! the highest power to the first element: `f₀·αᵂ⁻¹ + f₁·αᵂ⁻² + ... + fᵂ₋₁·α⁰`.
//!
//! This convention is shared by:
//! - Prover OOD reduction (`horner` over aligned batched evals)
//! - Verifier OOD reduction (inline in `verifier::DeepOracle::new` via `horner_acc`)
//! - Verifier query-time row reduction (`verifier::DeepOracle::open_batch` via `horner_acc`)
//! - Prover LDE evaluation (`prover::DeepPoly::from_trees` via explicit dot-product with reversed
//!   negated coefficients — see comments there)

pub mod interpolate;
pub mod proof;
pub mod prover;
pub mod verifier;

use alloc::vec::Vec;

use miden_stark_transcript::{TranscriptError, VerifierChannel};
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use proof::OpenedValues;

/// DEEP quotient parameters.
///
/// Controls proof-of-work grinding for DEEP challenge sampling.
/// Column alignment is handled at the LMCS layer and by padding evaluations.
#[derive(Clone, Copy, Debug)]
pub struct DeepParams {
    /// Grinding bits before DEEP challenge sampling.
    pub(crate) deep_pow_bits: usize,
}

/// Read OOD evaluation matrices from a verifier channel.
///
/// The prover sends one flat slice per evaluation point containing all matrices'
/// column values concatenated. This function splits by widths and reshapes into
/// per-group, per-matrix `RowMajorMatrix<EF>` with `num_eval_points` rows each.
pub fn read_eval_matrices<F, EF, Ch>(
    group_widths: &[&[usize]],
    num_eval_points: usize,
    channel: &mut Ch,
) -> Result<OpenedValues<EF>, TranscriptError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    Ch: VerifierChannel<F = F>,
{
    let all_widths: Vec<usize> = group_widths.iter().flat_map(|gw| gw.iter().copied()).collect();
    let total_width: usize = all_widths.iter().sum();

    let mut values: Vec<Vec<EF>> =
        all_widths.iter().map(|&w| Vec::with_capacity(w * num_eval_points)).collect();

    for _ in 0..num_eval_points {
        let flat = channel.receive_algebra_slice::<EF>(total_width)?;
        let mut offset = 0;
        for (m, &w) in all_widths.iter().enumerate() {
            values[m].extend_from_slice(&flat[offset..offset + w]);
            offset += w;
        }
    }

    let mut mat_iter = values
        .into_iter()
        .zip(&all_widths)
        .map(|(vals, &w)| RowMajorMatrix::new(vals, w));
    let evals = group_widths
        .iter()
        .map(|gw| mat_iter.by_ref().take(gw.len()).collect())
        .collect();

    Ok(evals)
}

#[cfg(test)]
mod tests;
