//! Verifier-side periodic column handling.
//!
//! Periodic columns are stored as polynomial coefficients for efficient evaluation
//! at the OOD point using Horner's method.

extern crate alloc;

use alloc::vec::Vec;

use p3_dft::{NaiveDft, TwoAdicSubgroupDft};
use p3_field::{ExtensionField, TwoAdicField};

/// Verifier-side periodic polynomials for OOD evaluation.
///
/// Stores polynomial coefficients computed from the AIR's periodic columns.
/// Used to evaluate periodic values at the OOD point during verification.
#[derive(Clone, Debug)]
pub struct PeriodicPolys<F> {
    /// Polynomial coefficients for each column.
    polys: Vec<Vec<F>>,
}

impl<F: TwoAdicField> PeriodicPolys<F> {
    /// Construct from subgroup evaluations (canonical order).
    ///
    /// Converts subgroup evaluations to polynomial coefficients via inverse DFT.
    ///
    /// # Panics
    /// Panics if any column length is zero or not a power of two.
    /// This is a trusted path — the AIR should pass
    /// [`LiftedAir::validate`](miden_lifted_air::LiftedAir::validate).
    pub fn new(column_evals: &[Vec<F>]) -> Self {
        let dft = NaiveDft;
        let mut polys = Vec::with_capacity(column_evals.len());

        for (i, column) in column_evals.iter().enumerate() {
            let p = column.len();
            assert!(
                p > 0 && p.is_power_of_two(),
                "periodic column {i}: length must be positive power of two, got {p}"
            );
            let coeffs = dft.idft(column.clone());
            polys.push(coeffs);
        }

        Self { polys }
    }

    /// Evaluate all periodic polynomials at the OOD point.
    ///
    /// For a column with period `p`, evaluates at `z^(trace_height / p)`.
    /// Uses Horner's method for efficient polynomial evaluation.
    ///
    /// # Arguments
    /// - `trace_height`: Height of the trace
    /// - `z`: The OOD evaluation point
    ///
    /// The evaluation point is `z^{n/p}` rather than `z` directly. A periodic
    /// column with period p is a polynomial P(X) of degree < p defined on the subgroup of
    /// order p. At trace row i, the value is P(ωₙⁱ) = P(ωₚ^{i mod p}).
    /// Since ωₙ^{n/p} = ωₚ, the map X → X^{n/p} collapses the trace domain H
    /// (order n) onto the periodic subgroup (order p). So evaluating P at z^{n/p} gives
    /// the same result as evaluating the periodic extension of P at z on the full trace
    /// domain.
    pub fn eval_at<EF>(&self, trace_height: usize, z: EF) -> Vec<EF>
    where
        EF: ExtensionField<F>,
    {
        let mut result = Vec::with_capacity(self.polys.len());

        for coeffs in &self.polys {
            let period = coeffs.len();
            let y = z.exp_u64((trace_height / period) as u64);
            result.push(horner_eval(coeffs, y));
        }

        result
    }
}

/// Evaluate a polynomial at a point using Horner's method.
fn horner_eval<F, EF>(coeffs: &[F], x: EF) -> EF
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
{
    let mut acc = EF::ZERO;
    for coeff in coeffs.iter().rev() {
        acc = acc * x + *coeff;
    }
    acc
}
