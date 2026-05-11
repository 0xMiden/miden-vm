//! Protocol-level instance types for the lifted STARK prover and verifier.
//!
//! - [`AirInstance`]: Verifier instance — public values + variable-length inputs
//! - [`AirWitness`]: Prover witness — trace + public values
//! - [`InstanceShapes`]: Per-instance trace heights carried on [`StarkProof`](crate::StarkProof)

extern crate alloc;

use alloc::{vec, vec::Vec};

use miden_lifted_air::{AirStructureError, LiftedAir, VarLenPublicInputs, log2_strict_u8};
use p3_challenger::CanObserve;
use p3_field::{Field, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::domain::{DomainError, LiftedDomain};

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
#[derive(Clone, Copy, Debug)]
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
/// Stores log₂ trace heights (absorbed into the Fiat-Shamir challenger)
/// and the AIR ordering (not absorbed — see [`air_order`](Self::air_order)).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceShapes {
    // `pub(crate)` so in-crate tests can construct malformed shapes to
    // exercise the verifier-path validation in `validate_inputs`. External
    // callers go through `InstanceShapes::from_trace_heights`.
    pub(crate) log_trace_heights: Vec<u8>,
    /// The AIR ordering: `air_order[j]` is the caller's original index of
    /// the instance at position `j` in the proof's ordering.
    pub(crate) air_order: Vec<u32>,
}

impl InstanceShapes {
    /// Construct from raw trace heights (must be powers of two).
    ///
    /// Determines the proof's AIR ordering by sorting instances by
    /// `(log_trace_height, caller_index)`. The resulting
    /// [`air_order`](Self::air_order) maps each position in the proof's
    /// ordering back to the caller's original index.
    pub fn from_trace_heights(trace_heights: Vec<usize>) -> Result<Self, InstanceValidationError> {
        let log_heights: Vec<u8> = trace_heights
            .iter()
            .map(|&h| {
                if !h.is_power_of_two() {
                    return Err(InstanceValidationError::InvalidTraceHeight { height: h });
                }
                Ok(log2_strict_u8(h))
            })
            .collect::<Result<_, _>>()?;

        // Sort by (log_height, caller_index) for a canonical ordering.
        let mut perm: Vec<usize> = (0..log_heights.len()).collect();
        perm.sort_by_key(|&i| (log_heights[i], i));

        let sorted_log_heights: Vec<u8> = perm.iter().map(|&i| log_heights[i]).collect();
        let air_order: Vec<u32> = perm.iter().map(|&i| i as u32).collect();

        Ok(Self {
            log_trace_heights: sorted_log_heights,
            air_order,
        })
    }

    /// Log₂ of the trace height for each instance, in the proof's AIR
    /// ordering.
    pub fn log_trace_heights(&self) -> &[u8] {
        &self.log_trace_heights
    }

    /// The AIR ordering used by the proof: `air_order()[j]` is the caller's
    /// original index of the instance at position `j` in the proof's
    /// ordering. Not absorbed into the Fiat-Shamir transcript.
    pub fn air_order(&self) -> &[u32] {
        &self.air_order
    }

    pub(crate) fn len(&self) -> usize {
        self.log_trace_heights.len()
    }

    /// Reorder `data` from the caller's natural order to the proof's AIR
    /// ordering. Returns a `Vec` where position `j` holds
    /// `data[air_order[j]]`.
    ///
    /// Validates that `air_order` is a valid permutation before applying it.
    /// Returns an error if lengths mismatch or if `air_order` is malformed.
    pub(crate) fn reorder<T>(&self, mut data: Vec<T>) -> Result<Vec<T>, InstanceValidationError> {
        let n = data.len();
        validate_air_order(&self.air_order, n)?;
        let mut placed = vec![false; n];
        for start in 0..n {
            if placed[start] {
                continue;
            }
            let mut j = start;
            loop {
                let src = self.air_order[j] as usize;
                placed[j] = true;
                if src == start {
                    break;
                }
                data.swap(j, src);
                j = src;
            }
        }
        Ok(data)
    }

    pub fn size_in_bytes(&self) -> usize {
        size_of_val(self.log_trace_heights.as_slice()) + size_of_val(self.air_order.as_slice())
    }

    /// Absorb the log trace heights into a Fiat-Shamir challenger as one
    /// base field element per `log_h`. The `air_order` values are **not**
    /// absorbed.
    pub(crate) fn observe_heights<F, C>(&self, challenger: &mut C)
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
    #[error("log trace height {log_h} exceeds {max} (would overflow usize on this target)")]
    LogTraceHeightTooLarge { log_h: u8, max: u8 },
    #[error(
        "instance count {instances} does not match log trace heights count {log_trace_heights}"
    )]
    HeightCountMismatch {
        instances: usize,
        log_trace_heights: usize,
    },
    #[error("air_order length {air_order} does not match instance count {instances}")]
    AirOrderLengthMismatch { instances: usize, air_order: usize },
    #[error("invalid air_order permutation for {count} instances")]
    InvalidAirOrder { count: usize },
    #[error("log trace heights are not in ascending order")]
    HeightsNotAscending,
    #[error(transparent)]
    Domain(#[from] DomainError),
}

impl InstanceShapes {
    /// Per-instance data checks: count match, AIR structural validity, public
    /// values length, var-len public inputs length, log_h platform bound, and
    /// periodic column coverage. Independent of ordering — see
    /// [`Self::ascending_subdomains`] for the ordering + subdomain build.
    ///
    /// Instances and shapes must already be in the proof's AIR ordering.
    pub(crate) fn validate_instance_data<F, EF, A>(
        &self,
        instances: &[(&A, AirInstance<'_, F>)],
    ) -> Result<(), InstanceValidationError>
    where
        F: Field,
        A: LiftedAir<F, EF>,
    {
        if instances.len() != self.len() {
            return Err(InstanceValidationError::HeightCountMismatch {
                instances: instances.len(),
                log_trace_heights: self.len(),
            });
        }
        // Bound `log_h` so `1usize << log_h` cannot overflow on this target.
        // Field-relative bounds live in [`LiftedDomain::canonical`].
        let max_log_trace_height = (usize::BITS - 1) as u8;
        for ((air, inst), &log_h) in instances.iter().zip(self.log_trace_heights()) {
            if log_h > max_log_trace_height {
                return Err(InstanceValidationError::LogTraceHeightTooLarge {
                    log_h,
                    max: max_log_trace_height,
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
            let trace_height = 1usize << log_h as usize;
            let max_period = air.periodic_columns().iter().map(Vec::len).max().unwrap_or(0);
            if trace_height < max_period {
                return Err(InstanceValidationError::TraceHeightBelowPeriod {
                    trace_height,
                    max_period,
                });
            }
        }
        Ok(())
    }

    /// Build per-instance [`LiftedDomain`]s by lifting each height `n_j` into
    /// `max_lde_domain` with lift ratio `r_j = N / n_j` (the same ratio the
    /// per-AIR quotient pipeline uses). Enforces ascending heights (canonical
    /// for the proof) and that the max height ≥ 2 (required for the 2-row
    /// transition window).
    ///
    /// Returns the subdomains in the same order as
    /// [`Self::log_trace_heights`].
    pub(crate) fn ascending_subdomains<F: TwoAdicField>(
        &self,
        max_lde_domain: &LiftedDomain<F>,
    ) -> Result<Vec<LiftedDomain<F>>, InstanceValidationError> {
        // First: ordering + transition-window check, so errors here surface as
        // `HeightsNotAscending` / `Empty` rather than `DomainError` from a
        // later out-of-bounds `try_sub_domain`.
        let mut log_prev: u8 = 0;
        for &log_h in self.log_trace_heights() {
            if log_h < log_prev {
                return Err(InstanceValidationError::HeightsNotAscending);
            }
            log_prev = log_h;
        }
        if log_prev == 0 {
            return Err(InstanceValidationError::Empty);
        }
        // Then: build the subdomains.
        self.log_trace_heights()
            .iter()
            .map(|&h| max_lde_domain.try_sub_domain(h).map_err(Into::into))
            .collect()
    }
}

/// Validate that `air_order` is a valid permutation of `0..n`.
///
/// Called on the verifier side where `air_order` comes from an untrusted proof.
pub(crate) fn validate_air_order(
    air_order: &[u32],
    n: usize,
) -> Result<(), InstanceValidationError> {
    if air_order.len() != n {
        return Err(InstanceValidationError::AirOrderLengthMismatch {
            instances: n,
            air_order: air_order.len(),
        });
    }
    let mut seen = vec![false; n];
    for &idx in air_order {
        let Some(slot @ false) = seen.get_mut(idx as usize) else {
            return Err(InstanceValidationError::InvalidAirOrder { count: n });
        };
        *slot = true;
    }
    Ok(())
}
