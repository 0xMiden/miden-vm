//! Constraint evaluation and quotient reconstruction for the verifier.
//!
//! This module provides:
//! - [`ConstraintFolder`]: Minimal EF-only folder for verifier constraint evaluation
//! - [`reconstruct_quotient`]: Reconstructs Q(z) from quotient chunk evaluations
//! - [`row_to_packed_ext`]: Reconstitutes EF elements from opened base field evaluations

use alloc::vec::Vec;
use core::marker::PhantomData;

use miden_lifted_air::{
    AirBuilder, EmptyWindow, ExtensionBuilder, PeriodicAirBuilder, PermutationAirBuilder, RowWindow,
};
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_util::log2_strict_usize;

use crate::{coset::LiftedCoset, selectors::Selectors, verifier::VerifierError};

// ============================================================================
// ConstraintFolder
// ============================================================================

/// Minimal constraint folder for verifier OOD evaluation.
///
/// Implements the AIR builder traits needed to evaluate constraints at an out-of-domain
/// point. Uses the extension field throughout since the verifier only evaluates at a
/// single EF point (z).
///
/// The verifier folds constraints on the fly using Horner:
///
/// acc = acc·α + Cₖ(z).
///
/// This matches the prover's random linear combination
/// `Σₖ α^{K−1−k}·Cₖ(z)`, but is cheaper for a single-point evaluation.
/// The prover computes an equivalent fold over the whole quotient domain, optimized
/// with base-field SIMD where possible.
pub struct ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub main: RowWindow<'a, EF>,
    pub aux: RowWindow<'a, EF>,
    pub randomness: &'a [EF],
    pub public_values: &'a [F],
    pub periodic_values: &'a [EF],
    pub permutation_values: &'a [EF],
    pub selectors: Selectors<EF>,
    pub alpha: EF,
    pub accumulator: EF,
    pub _phantom: PhantomData<F>,
}

impl<'a, F, EF> AirBuilder for ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type F = F;
    type Expr = EF;
    type Var = EF;
    type PreprocessedWindow = EmptyWindow<EF>;
    type MainWindow = RowWindow<'a, EF>;
    type PublicVar = F;

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        EmptyWindow::empty_ref()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.selectors.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.selectors.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.selectors.is_transition
        } else {
            panic!("only window size 2 supported in this prototype")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.accumulator = self.accumulator * self.alpha + x.into();
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<'a, F, EF> ExtensionBuilder for ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type EF = EF;
    type ExprEF = EF;
    type VarEF = EF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.accumulator = self.accumulator * self.alpha + x.into();
    }
}

impl<'a, F, EF> PermutationAirBuilder for ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type MP = RowWindow<'a, EF>;
    type RandomVar = EF;
    type PermutationVar = EF;

    fn permutation(&self) -> Self::MP {
        self.aux
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.randomness
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        self.permutation_values
    }
}

impl<'a, F, EF> PeriodicAirBuilder for ConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type PeriodicVar = EF;

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.periodic_values
    }
}

// ============================================================================
// Quotient Reconstruction
// ============================================================================

/// Reconstruct `Q(z)` from `D` quotient chunk evaluations.
///
/// The quotient `Q` is committed as `D` chunk polynomials qₜ of degree `< N`, one for
/// each `H`-coset inside `J`:
///
/// qₜ agrees with `Q` on the coset `g·ω_Jᵗ·H`.
///
/// During verification we open all qₜ(z) at the same OOD point `z` and need to
/// recombine them into `Q(z)`.
///
/// The key observation is that the map `x → xᴺ` collapses each coset
/// `g·ω_Jᵗ·H` to a single `D`-th root of unity. Let
/// - ωₛ = ω_Jᴺ (a `D`-th root of unity),
/// - u = (z/s)ᴺ where s = coset.lde_shift().
///
/// Then `Q(z)` is the barycentric interpolation of the values qₜ(z) at the points
/// ωₛᵗ:
///
/// ```text
/// wₜ = ωₛᵗ / (u − ωₛᵗ)
/// Q(z) = (Σₜ wₜ·qₜ(z)) / (Σₜ wₜ)
/// ```
pub fn reconstruct_quotient<F, EF>(z: EF, coset: &LiftedCoset, chunks: &[EF]) -> EF
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    let log_d = log2_strict_usize(chunks.len());
    let shift: F = coset.lde_shift();
    let omega_s = F::two_adic_generator(log_d);

    // u = (z/s)ᴺ where s = lde_shift
    let u = (z * shift.inverse()).exp_power_of_2(coset.log_trace_height as usize);

    // Compute weighted sum: Σₜ wₜ·qₜ(z) and Σₜ wₜ
    let mut numerator = EF::ZERO;
    let mut denominator = EF::ZERO;
    let mut omega_s_t = F::ONE; // ωₛᵗ

    for &q_t in chunks.iter() {
        let a_t = u - omega_s_t; // aₜ = u − ωₛᵗ
        let w_t = a_t.inverse() * omega_s_t; // wₜ = ωₛᵗ / aₜ

        numerator += w_t * q_t;
        denominator += w_t;

        omega_s_t *= omega_s;
    }

    numerator * denominator.inverse()
}

/// Reconstitute EF elements from opened base field polynomial evaluations.
///
/// When an EF polynomial is committed, it becomes DIM base field polynomials.
/// Opening at EF point z gives DIM EF values (F-polys evaluated at EF point).
/// Reconstruct each EF element: `vᵢ = Σⱼ basisⱼ·row[i·DIM + j]`.
///
/// An EF element `v = Σⱼ cⱼ·basisⱼ` is committed as DIM base field polynomials pⱼ
/// (one per basis coordinate cⱼ). Opening at `z` returns the DIM values pⱼ(z), and we
/// recover the original EF value as `v(z) = Σⱼ basisⱼ·pⱼ(z)`.
pub fn row_to_packed_ext<F, EF>(row: &[EF]) -> Result<Vec<EF>, VerifierError>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    if !row.len().is_multiple_of(EF::DIMENSION) {
        return Err(VerifierError::InvalidAuxShape);
    }
    let num_elements = row.len() / EF::DIMENSION;
    Ok((0..num_elements)
        .map(|i| {
            let start = i * EF::DIMENSION;
            (0..EF::DIMENSION)
                .map(|j| EF::ith_basis_element(j).unwrap() * row[start + j])
                .sum()
        })
        .collect())
}
