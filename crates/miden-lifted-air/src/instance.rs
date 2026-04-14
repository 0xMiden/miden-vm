//! Shared instance types for the lifted STARK prover and verifier.
//!
//! - [`AirWitness`]: Prover witness — trace + public values
//! - [`AirInstance`]: Verifier instance — log trace height + public values

use alloc::vec::Vec;

use p3_field::Field;
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{LiftedAir, VarLenPublicInputs, air::AirValidationError, util::log2_strict_u8};

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

    /// Convert to a verifier instance (drops the trace, keeps log height).
    ///
    /// Returns an error if the trace height is not a power of two.
    pub fn to_instance(&self) -> Result<AirInstance<'a, F>, AirValidationError>
    where
        F: Clone + Send + Sync,
    {
        let height = self.trace.height();
        if !height.is_power_of_two() {
            return Err(AirValidationError::InvalidTraceHeight { height });
        }
        Ok(AirInstance {
            log_trace_height: log2_strict_u8(height),
            public_values: self.public_values,
            var_len_public_inputs: self.var_len_public_inputs,
        })
    }
}

/// Verifier instance: log trace height, public values, and variable-length inputs.
///
/// Both the prover and verifier carry `var_len_public_inputs`. The verifier uses
/// them in [`LiftedAir::reduced_aux_values`](crate::LiftedAir::reduced_aux_values)
/// for the cross-AIR identity check.
#[derive(Clone, Copy)]
pub struct AirInstance<'a, F> {
    /// Log₂ of the trace height.
    pub log_trace_height: u8,
    /// Public values for this AIR.
    pub public_values: &'a [F],
    /// Reducible inputs for the cross-AIR identity check. Empty slice if no buses.
    pub var_len_public_inputs: VarLenPublicInputs<'a, F>,
}

/// Validate AIR and instance dimensions for a slice of `(air, instance)` pairs.
///
/// Checks that instances are non-empty, sorted by ascending log height, and that
/// the maximum trace height is at least 2 (required for the 2-row transition window).
/// Runs [`LiftedAir::validate`] + [`AirInstance::validate`] on each pair.
///
/// Returns the log of the maximum trace height.
pub fn validate_instances<F, EF, A>(
    instances: &[(&A, AirInstance<'_, F>)],
) -> Result<u8, AirValidationError>
where
    F: Field,
    A: LiftedAir<F, EF>,
{
    let mut log_prev_height: u8 = 0;
    for (air, inst) in instances {
        air.validate()?;
        inst.validate(*air)?;
        if inst.log_trace_height < log_prev_height {
            return Err(AirValidationError::NotAscending);
        }
        log_prev_height = inst.log_trace_height;
    }
    // log_prev_height == 0 means either no instances or all traces have height 1,
    // both invalid for a protocol with a 2-row transition window.
    if log_prev_height == 0 {
        return Err(AirValidationError::Empty);
    }
    Ok(log_prev_height)
}

impl<'a, F> AirInstance<'a, F> {
    /// Validate that this instance matches an AIR's specification.
    ///
    /// Checks public values length, var-len public inputs count, and that the
    /// trace height is at least the max periodic column length.
    pub fn validate<EF>(&self, air: &impl LiftedAir<F, EF>) -> Result<(), AirValidationError>
    where
        F: Field,
    {
        let expected = air.num_public_values();
        let actual = self.public_values.len();
        if actual != expected {
            return Err(AirValidationError::PublicValuesMismatch { expected, actual });
        }
        let expected = air.num_var_len_public_inputs();
        let actual = self.var_len_public_inputs.len();
        if actual != expected {
            return Err(AirValidationError::VarLenPublicInputsMismatch { expected, actual });
        }
        let trace_height = 1 << self.log_trace_height as usize;
        let max_period = air.periodic_columns().iter().map(Vec::len).max().unwrap_or(0);
        if trace_height < max_period {
            return Err(AirValidationError::TraceHeightBelowPeriod { trace_height, max_period });
        }
        Ok(())
    }
}
