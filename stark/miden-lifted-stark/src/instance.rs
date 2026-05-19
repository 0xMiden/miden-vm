//! Stark-side instance utilities: [`TraceOrder`] and [`validate_instance`].
//!
//! The air crate's [`Instance`] trait is order-agnostic: every list it
//! exposes is in **instance order** (the position returned by
//! [`Instance::airs`]). The stark crate is the only place that needs the
//! proof's wire-format AIR ordering (a deterministic stable sort of the
//! per-AIR heights). [`TraceOrder`] is the type that carries the
//! permutation between **instance order** and **proof order**; nothing
//! about it leaks into the air crate.
//!
//! - [`TraceOrder`]: built from instance-order trace heights. Owns the permutation between instance
//!   order and proof order, plus the heights themselves. Both prover and verifier construct one and
//!   pass it to [`validate_instance`].
//! - [`validate_instance`]: instance-level checks against a [`TraceOrder`] (count match,
//!   public-values length matches the shared declaration, trace height ≥ max periodic period). The
//!   AIR list itself is assumed structurally valid via [`miden_lifted_air::validate_airs`].

extern crate alloc;

use alloc::vec::Vec;

use miden_lifted_air::{BaseAir, Instance, LiftedAir, log2_strict_u8};
use p3_field::{ExtensionField, Field};
use thiserror::Error;

// ============================================================================
// Errors
// ============================================================================

/// Errors from parsing or validating proof shape metadata (the
/// caller-order `&[u8]` of log trace heights carried on the proof).
#[derive(Debug, Error)]
pub enum ShapeError {
    #[error("no instances provided")]
    Empty,
    #[error("trace height {height} is not a power of two")]
    InvalidTraceHeight { height: usize },
    #[error("log trace height {log_h} exceeds {max} (would overflow usize on this target)")]
    LogTraceHeightTooLarge { log_h: u8, max: u8 },
    #[error("more than 256 instances ({count}) — exceeds the u8 caller-index limit")]
    TooManyInstances { count: usize },
}

/// Errors from validating an [`Instance`] against a [`TraceOrder`].
///
/// The AIR's structural contract (no preprocessed trace, positive aux
/// width, power-of-two periodic columns) is the air-crate's domain — call
/// [`miden_lifted_air::validate_airs`] for that. This enum only covers
/// checks that depend on caller-supplied data the AIR trait cannot
/// validate on its own.
#[derive(Debug, Error)]
pub enum InstanceValidationError {
    #[error(transparent)]
    Shape(#[from] ShapeError),
    #[error("public values length mismatch: expected {expected}, got {actual}")]
    PublicValuesMismatch { expected: usize, actual: usize },
    #[error("trace height {trace_height} is less than max periodic column length {max_period}")]
    TraceHeightBelowPeriod { trace_height: usize, max_period: usize },
    #[error("prover input count mismatch: {airs} AIRs but {traces} traces")]
    AirTraceCountMismatch { airs: usize, traces: usize },
    #[error("trace width mismatch: expected {expected}, got {actual}")]
    WidthMismatch { expected: usize, actual: usize },
}

// ============================================================================
// TraceOrder
// ============================================================================

/// The permutation between **instance order** (the AIR positions as
/// returned by [`Instance::airs`]) and **proof order** (the wire-format
/// ordering used inside the prover/verifier), derived deterministically
/// from per-AIR trace heights.
///
/// Proof order is defined as the stable sort of instance indices by
/// `(log_trace_height, instance_index)`. Both prover and verifier compute
/// the same ordering from the same heights, so the proof commits to heights
/// only and the ordering is reconstructed locally.
///
/// Heights are stored in instance order (matching [`Instance::airs`]).
/// Use [`Self::to_proof_order`] / [`Self::to_instance_order`] (or
/// [`Self::reorder_to_proof_in_place`]) to move data between the two views.
#[derive(Clone, Debug)]
pub struct TraceOrder {
    log_heights_instance: Vec<u8>,
    /// `instance_indices[j]` = instance index at proof position `j`. Length
    /// matches `log_heights_instance`.
    instance_indices: Vec<u8>,
}

impl TraceOrder {
    /// Build from raw (non-log) trace heights in instance order.
    ///
    /// Validates that every height is a non-zero power of two, that the
    /// log-height fits in `u8` and within the host's `usize` width, and that
    /// the number of instances fits in `u8`.
    pub fn from_trace_heights(trace_heights: &[usize]) -> Result<Self, ShapeError> {
        if trace_heights.is_empty() {
            return Err(ShapeError::Empty);
        }
        if trace_heights.len() > u8::MAX as usize + 1 {
            return Err(ShapeError::TooManyInstances { count: trace_heights.len() });
        }
        let log_heights: Vec<u8> = trace_heights
            .iter()
            .map(|&h| {
                if !h.is_power_of_two() {
                    return Err(ShapeError::InvalidTraceHeight { height: h });
                }
                Ok(log2_strict_u8(h))
            })
            .collect::<Result<_, _>>()?;
        Self::from_log_heights(log_heights)
    }

    /// Build from instance-order log trace heights.
    ///
    /// Used on the verifier side, where heights are read straight off the
    /// proof as `u8`s. Power-of-two-ness is automatic (heights are stored
    /// as log₂); the only checks are non-emptiness, host-`usize` bound, and
    /// the u8 instance-count limit.
    pub fn from_log_heights(log_heights_instance: Vec<u8>) -> Result<Self, ShapeError> {
        if log_heights_instance.is_empty() {
            return Err(ShapeError::Empty);
        }
        if log_heights_instance.len() > u8::MAX as usize + 1 {
            return Err(ShapeError::TooManyInstances { count: log_heights_instance.len() });
        }
        let max_log = (usize::BITS - 1) as u8;
        for &h in &log_heights_instance {
            if h > max_log {
                return Err(ShapeError::LogTraceHeightTooLarge { log_h: h, max: max_log });
            }
        }
        let n = log_heights_instance.len();
        let mut instance_indices: Vec<u8> = (0..n as u8).collect();
        instance_indices.sort_by_key(|&i| (log_heights_instance[i as usize], i));
        Ok(Self { log_heights_instance, instance_indices })
    }

    /// Number of AIR instances.
    pub fn len(&self) -> usize {
        self.log_heights_instance.len()
    }

    /// Whether the order contains any instances.
    pub fn is_empty(&self) -> bool {
        self.log_heights_instance.is_empty()
    }

    /// Log trace heights in instance order. Matches [`Instance::airs`].
    pub fn log_heights_instance(&self) -> &[u8] {
        &self.log_heights_instance
    }

    /// Instance indices in proof order: `instance_indices()[j]` is the
    /// instance index of the AIR at proof position `j`.
    pub fn instance_indices(&self) -> &[u8] {
        &self.instance_indices
    }

    /// Log trace heights in proof order (ascending by construction).
    pub fn log_heights_proof(&self) -> Vec<u8> {
        self.instance_indices
            .iter()
            .map(|&i| self.log_heights_instance[i as usize])
            .collect()
    }

    /// The largest log trace height (= last entry of [`Self::log_heights_proof`]).
    pub fn max_log_height(&self) -> u8 {
        // `instance_indices` is non-empty (constructor rejects empty input).
        let last = *self.instance_indices.last().expect("TraceOrder is non-empty");
        self.log_heights_instance[last as usize]
    }

    /// Reorder instance-order data to proof order, cloning.
    ///
    /// Returns a `Vec` of length [`Self::len`] where position `j` holds
    /// `instance_data[instance_indices()[j]]`.
    pub fn to_proof_order<T: Clone>(&self, instance_data: &[T]) -> Vec<T> {
        debug_assert_eq!(instance_data.len(), self.len());
        self.instance_indices
            .iter()
            .map(|&i| instance_data[i as usize].clone())
            .collect()
    }

    /// Permute `data` in place from instance order to proof order.
    ///
    /// After the call, `data[j] == data_original[instance_indices()[j]]`.
    /// Avoids the clone in [`Self::to_proof_order`] for owned data like
    /// `RowMajorMatrix`.
    pub fn reorder_to_proof_in_place<T>(&self, data: &mut [T]) {
        assert_eq!(data.len(), self.len());
        let n = self.len();
        let perm = &self.instance_indices;
        let mut visited = alloc::vec![false; n];
        // Cycle decomposition: each cycle of the permutation is rotated in
        // place via swaps along the cycle.
        for start in 0..n {
            if visited[start] {
                continue;
            }
            visited[start] = true;
            let mut current = start;
            loop {
                let next = perm[current] as usize;
                if next == start {
                    break;
                }
                data.swap(current, next);
                visited[next] = true;
                current = next;
            }
        }
    }

    /// Reorder proof-order data back to instance order, cloning.
    ///
    /// Returns a `Vec` of length [`Self::len`] where position `i` holds the
    /// element at the proof position whose instance index is `i`.
    pub fn to_instance_order<T: Clone>(&self, proof_data: &[T]) -> Vec<T> {
        debug_assert_eq!(proof_data.len(), self.len());
        let n = self.len();
        let mut out: Vec<Option<T>> = (0..n).map(|_| None).collect();
        for (j, &i) in self.instance_indices.iter().enumerate() {
            out[i as usize] = Some(proof_data[j].clone());
        }
        out.into_iter()
            .map(|o| o.expect("instance_indices is a permutation of 0..n"))
            .collect()
    }
}

// ============================================================================
// Validation
// ============================================================================

/// Per-AIR contract checks driven by [`Instance::airs`] against a
/// pre-built [`TraceOrder`].
///
/// Assumes the AIR list itself is structurally valid (the air-crate's
/// [`validate_airs`](miden_lifted_air::validate_airs) is the right check
/// for that). This function only validates instance-level data the AIR
/// cannot check on its own:
///
/// - `airs.len() == trace_order.len()`
/// - for each AIR: `num_public_values() == air_inputs().len()`
/// - for each AIR: `trace_height ≥ max periodic column length`
///
/// Shape well-formedness (non-empty, `u8` instance count, `usize` bound on
/// `log_h`) is already enforced by [`TraceOrder::from_log_heights`].
pub fn validate_instance<F, EF, I>(
    instance: &I,
    trace_order: &TraceOrder,
) -> Result<(), InstanceValidationError>
where
    F: Field,
    EF: ExtensionField<F>,
    I: Instance<F, EF>,
{
    let airs = instance.airs();
    let log_heights_instance = trace_order.log_heights_instance();
    if airs.len() != log_heights_instance.len() {
        return Err(InstanceValidationError::AirTraceCountMismatch {
            airs: airs.len(),
            traces: log_heights_instance.len(),
        });
    }
    let air_inputs = instance.air_inputs();
    for (air, &log_h) in airs.iter().zip(log_heights_instance) {
        let expected_pv = air.num_public_values();
        if expected_pv != air_inputs.len() {
            return Err(InstanceValidationError::PublicValuesMismatch {
                expected: expected_pv,
                actual: air_inputs.len(),
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn trace_order_canonical_ordering() {
        // Instance order: heights [8, 2, 8, 4]. Sort by (log_h, idx) →
        // [1 (log=1), 3 (log=2), 0 (log=3), 2 (log=3)].
        let order = TraceOrder::from_trace_heights(&[8, 2, 8, 4]).unwrap();
        assert_eq!(order.instance_indices(), &[1, 3, 0, 2]);
        assert_eq!(order.log_heights_instance(), &[3, 1, 3, 2]);
        assert_eq!(order.log_heights_proof(), vec![1, 2, 3, 3]);
        assert_eq!(order.max_log_height(), 3);
    }

    #[test]
    fn trace_order_roundtrip() {
        let order = TraceOrder::from_trace_heights(&[8, 2, 8, 4]).unwrap();
        let instance_data = vec!["a", "b", "c", "d"];
        let proof_data = order.to_proof_order(&instance_data);
        assert_eq!(proof_data, vec!["b", "d", "a", "c"]);
        let back = order.to_instance_order(&proof_data);
        assert_eq!(back, instance_data);
    }

    #[test]
    fn trace_order_reorder_in_place_matches_clone() {
        // Mix of singletons and longer cycles in the permutation, plus
        // ties broken by instance index.
        let cases: &[&[usize]] = &[
            &[8, 2, 8, 4],
            &[2, 4, 8, 16],    // already sorted (identity permutation)
            &[16, 8, 4, 2],    // reverse-sorted
            &[4, 4, 4, 4],     // all equal (identity by tiebreak)
            &[8, 2, 4, 16, 4], // mixed
        ];
        for &heights in cases {
            let order = TraceOrder::from_trace_heights(heights).unwrap();
            let instance_data: Vec<usize> = (0..heights.len()).collect();
            let expected = order.to_proof_order(&instance_data);
            let mut data = instance_data;
            order.reorder_to_proof_in_place(&mut data);
            assert_eq!(data, expected, "in-place mismatch for heights {heights:?}");
        }
    }

    #[test]
    fn trace_order_rejects_non_pow2() {
        let err = TraceOrder::from_trace_heights(&[3]).unwrap_err();
        assert!(matches!(err, ShapeError::InvalidTraceHeight { height: 3 }));
    }

    #[test]
    fn trace_order_rejects_empty() {
        let err = TraceOrder::from_trace_heights(&[]).unwrap_err();
        assert!(matches!(err, ShapeError::Empty));
    }

    #[test]
    fn trace_order_rejects_oversized_log_h() {
        let err = TraceOrder::from_log_heights(vec![200]).unwrap_err();
        assert!(matches!(err, ShapeError::LogTraceHeightTooLarge { log_h: 200, .. }));
    }
}
