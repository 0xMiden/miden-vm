//! Protocol-level instance types for the lifted STARK prover and verifier.
//!
//! - [`AirWitness`]: Prover witness — trace + public values
//! - [`AirInstance`]: Verifier instance — public values + variable-length inputs

use alloc::vec::Vec;

use miden_lifted_air::{AirValidationError, LiftedAir, VarLenPublicInputs};
use p3_field::Field;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

/// Prover witness: trace matrix, public values, and variable-length public inputs.
///
/// Validates on construction that the trace height is a power of two.
///
/// **Commitment:** callers **must** bind both `public_values` and
/// `var_len_public_inputs` to the Fiat-Shamir challenger state before proving.
pub struct AirWitness<'a, F> {
    /// Main trace matrix.
    pub trace: &'a RowMajorMatrix<F>,
    /// Public values for this AIR.
    pub public_values: &'a [F],
    /// Variable-length public inputs (reducible inputs for bus identity checks).
    pub var_len_public_inputs: VarLenPublicInputs<'a, F>,
}

impl<'a, F> AirWitness<'a, F> {
    /// Create a new prover witness with validation.
    ///
    /// # Panics
    ///
    /// - If `trace.height()` is not a power of two
    pub fn new(
        trace: &'a RowMajorMatrix<F>,
        public_values: &'a [F],
        var_len_public_inputs: VarLenPublicInputs<'a, F>,
    ) -> Self
    where
        F: Field,
    {
        assert!(
            trace.height().is_power_of_two(),
            "trace height must be power of two, got {}",
            trace.height()
        );
        Self {
            trace,
            public_values,
            var_len_public_inputs,
        }
    }

    /// Convert to a verifier instance (drops the trace).
    pub fn to_instance(&self) -> AirInstance<'a, F> {
        AirInstance {
            public_values: self.public_values,
            var_len_public_inputs: self.var_len_public_inputs,
        }
    }
}

// ============================================================================
// Validation
// ============================================================================

/// Validate all protocol inputs: AIR structure, instance dimensions, and trace
/// height constraints.
///
/// Checks that:
/// - Each AIR is structurally valid ([`LiftedAir::validate`])
/// - Each instance's public values / var-len inputs match its AIR
/// - Heights are in ascending order
/// - The maximum height is at least 2 (log ≥ 1), required for the 2-row window
/// - Each trace height is at least as large as the AIR's max periodic column length
///
/// Returns the log of the maximum trace height.
///
/// TODO(0xMiden/crypto#941): Instead of rejecting non-ascending heights, compute
/// the permutation `π: trace_id → air_id` that sorts instances by ascending
/// trace height. Return the permutation alongside `log_max_trace_height`. Remove
/// the `NotAscending` check.
pub(crate) fn validate_inputs<F, EF, A>(
    instances: &[(&A, AirInstance<'_, F>)],
    log_trace_heights: &[u8],
) -> Result<u8, AirValidationError>
where
    F: Field,
    A: LiftedAir<F, EF>,
{
    assert_eq!(instances.len(), log_trace_heights.len(), "instance/height count mismatch");
    let mut log_prev: u8 = 0;
    for ((air, inst), &log_h) in instances.iter().zip(log_trace_heights) {
        air.validate()?;
        let expected_pv = air.num_public_values();
        if inst.public_values.len() != expected_pv {
            return Err(AirValidationError::PublicValuesMismatch {
                expected: expected_pv,
                actual: inst.public_values.len(),
            });
        }
        let expected_vl = air.num_var_len_public_inputs();
        if inst.var_len_public_inputs.len() != expected_vl {
            return Err(AirValidationError::VarLenPublicInputsMismatch {
                expected: expected_vl,
                actual: inst.var_len_public_inputs.len(),
            });
        }
        if log_h < log_prev {
            return Err(AirValidationError::NotAscending);
        }
        let trace_height = 1usize << log_h as usize;
        let max_period = air.periodic_columns().iter().map(Vec::len).max().unwrap_or(0);
        if trace_height < max_period {
            return Err(AirValidationError::TraceHeightBelowPeriod { trace_height, max_period });
        }
        log_prev = log_h;
    }
    // log_prev == 0 means either no instances or all traces have height 1,
    // both invalid for a protocol with a 2-row transition window.
    if log_prev == 0 {
        return Err(AirValidationError::Empty);
    }
    Ok(log_prev)
}

// ============================================================================
// Types
// ============================================================================

/// Verifier instance: public values and variable-length inputs.
///
/// Both the prover and verifier carry `var_len_public_inputs`. The verifier uses
/// them in [`LiftedAir::reduced_aux_values`](miden_lifted_air::LiftedAir::reduced_aux_values)
/// for the cross-AIR identity check.
///
/// Log trace heights are not part of the instance — they are carried in the
/// [`StarkProof`](crate::StarkProof) and absorbed into the Fiat-Shamir state.
#[derive(Clone, Copy)]
pub struct AirInstance<'a, F> {
    /// Public values for this AIR.
    pub public_values: &'a [F],
    /// Reducible inputs for the cross-AIR identity check. Empty slice if no buses.
    pub var_len_public_inputs: VarLenPublicInputs<'a, F>,
}
