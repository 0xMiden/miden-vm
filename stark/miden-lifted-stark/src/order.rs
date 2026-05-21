//! Internal instance↔proof ordering helper: the crate-internal [`TraceOrder`]
//! plus the public [`ShapeError`].
//!
//! The air crate's [`MultiAir`](miden_lifted_air::MultiAir) trait is order-agnostic: every list it
//! exposes is in **instance order** (the position returned by
//! [`MultiAir::airs`](miden_lifted_air::MultiAir::airs)). The stark crate is the only place that
//! needs the proof's wire-format AIR ordering (a deterministic stable sort of the
//! per-AIR heights). [`TraceOrder`] is the crate-internal type that carries the
//! permutation between **instance order** and **proof order**; nothing
//! about it leaks into the air crate or out of this crate's public surface.
//!
//! Runtime instance-level checks live in [`miden_lifted_air::validate`];
//! the structural AIR contract lives in [`miden_lifted_air::debug`].

extern crate alloc;

use alloc::vec::Vec;

use miden_lifted_air::log2_strict_u8;
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

// ============================================================================
// TraceOrder
// ============================================================================

/// The permutation between **instance order** (the AIR positions as
/// returned by [`MultiAir::airs`](miden_lifted_air::MultiAir::airs)) and **proof order** (the
/// wire-format ordering used inside the prover/verifier), derived deterministically
/// from per-AIR trace heights.
///
/// Proof order is defined as the stable sort of instance indices by
/// `(log_trace_height, instance_index)`. Both prover and verifier compute
/// the same ordering from the same heights, so the proof commits to heights
/// only and the ordering is reconstructed locally.
///
/// Heights are stored in instance order (matching
/// [`MultiAir::airs`](miden_lifted_air::MultiAir::airs)). Use [`Self::to_proof_order`] /
/// [`Self::to_instance_order`] (or [`Self::reorder_to_proof_in_place`]) to move data between the
/// two views.
#[derive(Clone, Debug)]
pub(crate) struct TraceOrder {
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
    pub(crate) fn from_trace_heights(trace_heights: &[usize]) -> Result<Self, ShapeError> {
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
    pub(crate) fn from_log_heights(log_heights_instance: Vec<u8>) -> Result<Self, ShapeError> {
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
    pub(crate) fn len(&self) -> usize {
        self.log_heights_instance.len()
    }

    /// Whether the order contains any instances. The conventional companion to
    /// [`Self::len`]; constructors reject empty input, so it always returns
    /// `false` in practice.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.log_heights_instance.is_empty()
    }

    /// Log trace heights in instance order. Matches
    /// [`MultiAir::airs`](miden_lifted_air::MultiAir::airs).
    pub(crate) fn log_heights_instance(&self) -> &[u8] {
        &self.log_heights_instance
    }

    /// Instance indices in proof order: `instance_indices()[j]` is the
    /// instance index of the AIR at proof position `j`.
    pub(crate) fn instance_indices(&self) -> &[u8] {
        &self.instance_indices
    }

    /// Log trace heights in proof order (ascending by construction).
    pub(crate) fn log_heights_proof(&self) -> Vec<u8> {
        self.instance_indices
            .iter()
            .map(|&i| self.log_heights_instance[i as usize])
            .collect()
    }

    /// The largest log trace height (= last entry of [`Self::log_heights_proof`]).
    pub(crate) fn max_log_height(&self) -> u8 {
        // `instance_indices` is non-empty (constructor rejects empty input).
        let last = *self.instance_indices.last().expect("TraceOrder is non-empty");
        self.log_heights_instance[last as usize]
    }

    /// Reorder instance-order data to proof order, cloning.
    ///
    /// Returns a `Vec` of length [`Self::len`] where position `j` holds
    /// `instance_data[instance_indices()[j]]`.
    pub(crate) fn to_proof_order<T: Clone>(&self, instance_data: &[T]) -> Vec<T> {
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
    pub(crate) fn reorder_to_proof_in_place<T>(&self, data: &mut [T]) {
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
    pub(crate) fn to_instance_order<T: Clone>(&self, proof_data: &[T]) -> Vec<T> {
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
