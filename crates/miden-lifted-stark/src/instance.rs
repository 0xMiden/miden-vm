//! Protocol-level instance types for the lifted STARK prover and verifier.
//!
//! - [`AirInstance`]: Verifier instance — public values + variable-length inputs
//! - [`AirWitness`]: Prover witness — trace + public values
//! - [`InstanceShapes`]: Per-instance trace heights carried on [`StarkProof`](crate::StarkProof)

extern crate alloc;

use alloc::vec::Vec;

use miden_lifted_air::{AirStructureError, LiftedAir, VarLenPublicInputs, log2_strict_u8};
use p3_challenger::CanObserve;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Instance data
// ============================================================================

/// Verifier instance: public values and variable-length inputs.
///
/// Both the prover and verifier carry `var_len_public_inputs`. The verifier uses
/// them in [`LiftedAir::reduced_aux_values`] for the cross-AIR identity check.
///
/// Log trace heights are not part of the instance — they are carried on the
/// [`StarkProof`](crate::StarkProof) as [`InstanceShapes`] and absorbed into
/// the Fiat-Shamir state.
#[derive(Clone, Copy, Debug)]
pub struct AirInstance<'a, F> {
    /// Public values for this AIR.
    pub public_values: &'a [F],
    /// Reducible inputs for the cross-AIR identity check. Empty slice if no buses.
    pub var_len_public_inputs: VarLenPublicInputs<'a, F>,
}

/// Prover witness: trace matrix, public values, and variable-length public inputs.
///
/// Validates on construction that the trace height is a power of two.
///
/// **Commitment:** callers **must** bind both `public_values` and
/// `var_len_public_inputs` to the Fiat-Shamir challenger state before proving.
#[derive(Debug)]
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
// Shape metadata
// ============================================================================

/// Per-instance shape metadata carried on [`StarkProof`](crate::StarkProof).
///
/// Holds one log₂ trace height per instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceShapes {
    // `pub(crate)` so in-crate tests can construct malformed shapes to
    // exercise the verifier-path validation in `validate_inputs`. External
    // callers go through `InstanceShapes::from_trace_heights`.
    pub(crate) log_trace_heights: Vec<u8>,
}

impl InstanceShapes {
    /// Construct from raw trace heights. Rejects non-power-of-two heights
    /// and non-ascending order, and stores their log₂.
    pub fn from_trace_heights(trace_heights: Vec<usize>) -> Result<Self, InstanceValidationError> {
        let mut log_trace_heights = Vec::with_capacity(trace_heights.len());
        let mut log_prev: u8 = 0;
        for h in trace_heights {
            if !h.is_power_of_two() {
                return Err(InstanceValidationError::InvalidTraceHeight { height: h });
            }
            let log_h = log2_strict_u8(h);
            if log_h < log_prev {
                return Err(InstanceValidationError::NotAscending);
            }
            log_trace_heights.push(log_h);
            log_prev = log_h;
        }
        Ok(Self { log_trace_heights })
    }

    /// Log₂ of the trace height for each instance, in input order.
    pub fn log_trace_heights(&self) -> &[u8] {
        &self.log_trace_heights
    }

    pub fn len(&self) -> usize {
        self.log_trace_heights.len()
    }

    pub fn is_empty(&self) -> bool {
        self.log_trace_heights.is_empty()
    }

    pub fn size_in_bytes(&self) -> usize {
        size_of_val(self.log_trace_heights.as_slice())
    }

    /// Absorb the shape metadata into a Fiat-Shamir challenger as one base
    /// field element per `log_h`.
    pub(crate) fn observe<F, C>(&self, challenger: &mut C)
    where
        F: Field + PrimeCharacteristicRing,
        C: CanObserve<F>,
    {
        for &h in &self.log_trace_heights {
            challenger.observe(F::from_u8(h));
        }
    }
}

// ============================================================================
// Validation
// ============================================================================

/// Errors from validating instance- and protocol-level inputs.
#[derive(Debug, Error)]
pub enum InstanceValidationError {
    #[error(transparent)]
    AirStructure(#[from] AirStructureError),
    #[error("no instances provided")]
    Empty,
    #[error("instances not in ascending height order")]
    NotAscending,
    #[error("trace height {height} is not a power of two")]
    InvalidTraceHeight { height: usize },
    #[error("trace width mismatch: expected {expected}, got {actual}")]
    WidthMismatch { expected: usize, actual: usize },
    #[error("public values length mismatch: expected {expected}, got {actual}")]
    PublicValuesMismatch { expected: usize, actual: usize },
    #[error("var-len public inputs count mismatch: expected {expected}, got {actual}")]
    VarLenPublicInputsMismatch { expected: usize, actual: usize },
    #[error("trace height {trace_height} is less than max periodic column length {max_period}")]
    TraceHeightBelowPeriod { trace_height: usize, max_period: usize },
    #[error(
        "instance count {instances} does not match log trace heights count {log_trace_heights}"
    )]
    HeightCountMismatch {
        instances: usize,
        log_trace_heights: usize,
    },
    #[error("LDE domain log-size {log_h} + {log_blowup} exceeds field two-adicity {two_adicity}")]
    LdeDomainExceedsTwoAdicity {
        log_h: u8,
        log_blowup: u8,
        two_adicity: usize,
    },
}

/// Cross-check instances against their shapes and return the log of the
/// maximum trace height.
///
/// Checks:
/// - shape count matches instance count
/// - each `log_h + log_blowup` fits in both `F::TWO_ADICITY` and `usize::BITS - 1` (guards
///   downstream `two_adic_generator` and `1usize << log_lde_height` against wire-format shapes; the
///   `usize` bound only bites on 32-bit targets)
/// - each AIR is structurally valid ([`LiftedAir::validate`])
/// - each instance's public values / var-len inputs match its AIR
/// - heights are ascending (prover-side constraint; verifier rejects defensively)
/// - max height ≥ 2 (needed for the 2-row transition window)
/// - each trace height covers the AIR's longest periodic column
pub(crate) fn validate_inputs<F, EF, A>(
    instances: &[(&A, AirInstance<'_, F>)],
    shapes: &InstanceShapes,
    log_blowup: u8,
) -> Result<u8, InstanceValidationError>
where
    F: TwoAdicField,
    A: LiftedAir<F, EF>,
{
    if instances.len() != shapes.len() {
        return Err(InstanceValidationError::HeightCountMismatch {
            instances: instances.len(),
            log_trace_heights: shapes.len(),
        });
    }
    // Upper bound on `log_h + log_blowup`: the two-adic generator must exist,
    // and `1usize << log_lde_height` must not overflow on this target.
    let max_log_lde_height = F::TWO_ADICITY.min((usize::BITS - 1) as usize);
    let mut log_prev: u8 = 0;
    for ((air, inst), &log_h) in instances.iter().zip(shapes.log_trace_heights()) {
        if log_h as usize + log_blowup as usize > max_log_lde_height {
            return Err(InstanceValidationError::LdeDomainExceedsTwoAdicity {
                log_h,
                log_blowup,
                two_adicity: F::TWO_ADICITY,
            });
        }
        air.validate()?;
        let expected_pv = air.num_public_values();
        if inst.public_values.len() != expected_pv {
            return Err(InstanceValidationError::PublicValuesMismatch {
                expected: expected_pv,
                actual: inst.public_values.len(),
            });
        }
        let expected_vl = air.num_var_len_public_inputs();
        if inst.var_len_public_inputs.len() != expected_vl {
            return Err(InstanceValidationError::VarLenPublicInputsMismatch {
                expected: expected_vl,
                actual: inst.var_len_public_inputs.len(),
            });
        }
        if log_h < log_prev {
            return Err(InstanceValidationError::NotAscending);
        }
        let trace_height = 1usize << log_h as usize;
        let max_period = air.periodic_columns().iter().map(Vec::len).max().unwrap_or(0);
        if trace_height < max_period {
            return Err(InstanceValidationError::TraceHeightBelowPeriod {
                trace_height,
                max_period,
            });
        }
        log_prev = log_h;
    }
    // `log_prev == 0` catches both "no instances" and "all traces are
    // height 1" — both break the 2-row transition window.
    if log_prev == 0 {
        return Err(InstanceValidationError::Empty);
    }
    Ok(log_prev)
}
