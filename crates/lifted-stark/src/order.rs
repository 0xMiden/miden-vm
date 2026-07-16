//! Internal instance↔proof ordering helper: the crate-internal [`TraceOrder`]
//! plus the public [`ShapeError`].
//!
//! The air crate's [`MultiAir`](miden_lifted_air::MultiAir) trait is order-agnostic — every list it
//! exposes is in **instance order** (the position returned by
//! [`MultiAir::airs`](miden_lifted_air::MultiAir::airs)). [`TraceOrder`] carries the permutation
//! between instance order and the proof's wire-format **proof order** (a deterministic stable sort
//! of the per-AIR heights), and validates the proof-supplied log heights against the AIRs at
//! construction.

extern crate alloc;

use alloc::vec::Vec;

use miden_lifted_air::{LiftedAir, log2_strict_u8};
use p3_challenger::CanObserve;
use p3_field::Field;
use thiserror::Error;

// ============================================================================
// TraceOrder
// ============================================================================

/// The permutation between **instance order** (AIR positions from
/// [`MultiAir::airs`](miden_lifted_air::MultiAir::airs)) and **proof order**, the wire-format
/// ordering used inside the prover/verifier.
///
/// Proof order is the stable sort of instance indices by `(log_trace_height,
/// instance_index)`. Both sides recompute it from the heights, so the proof commits
/// to heights only. Use [`Self::to_proof_order`] / [`Self::to_instance_order`] (or
/// [`Self::reorder_to_proof_in_place`]) to move data between the two views.
#[derive(Clone, Debug)]
pub(crate) struct TraceOrder {
    /// Log trace heights in instance order.
    log_heights: Vec<u8>,
    /// `instance_indices[j]` = instance index at proof position `j`. Length
    /// matches `log_heights`.
    instance_indices: Vec<u8>,
}

impl TraceOrder {
    /// Build from raw (non-log) trace heights in instance order, validated
    /// against `airs`.
    ///
    /// Validates that every height is a power of two and at least 2, that the
    /// log-height fits in `u8` and within the host's `usize` width, that the
    /// number of instances fits in `u8`, and (via [`Self::from_log_heights`])
    /// that the heights match the AIRs.
    pub(crate) fn from_trace_heights<F, EF, A>(
        airs: &[A],
        trace_heights: &[usize],
    ) -> Result<Self, ShapeError>
    where
        F: Field,
        A: LiftedAir<F, EF>,
    {
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
        Self::from_log_heights::<F, EF, A>(airs, log_heights)
    }

    /// Build from instance-order log trace heights, validated against `airs`.
    ///
    /// Used on the verifier side, where heights are read straight off the
    /// (untrusted) proof as `u8`s. Power-of-two-ness is automatic (heights are
    /// stored as log₂). Checks: non-emptiness, at least 2 rows per trace,
    /// host-`usize` bound, the u8 instance-count limit, `airs.len()` matches the
    /// height count, and per AIR `(1 << log_h) >= air.max_periodic_length()`.
    /// Holding a `TraceOrder` thus guarantees the proof's heights are feasible
    /// for the AIRs.
    pub(crate) fn from_log_heights<F, EF, A>(
        airs: &[A],
        log_heights: Vec<u8>,
    ) -> Result<Self, ShapeError>
    where
        F: Field,
        A: LiftedAir<F, EF>,
    {
        if log_heights.is_empty() {
            return Err(ShapeError::Empty);
        }
        if log_heights.len() > u8::MAX as usize + 1 {
            return Err(ShapeError::TooManyInstances { count: log_heights.len() });
        }
        let max_log = (usize::BITS - 1) as u8;
        for (idx, &h) in log_heights.iter().enumerate() {
            if h == 0 {
                return Err(ShapeError::TraceHeightTooSmall { air: idx });
            }
            if h > max_log {
                return Err(ShapeError::LogTraceHeightTooLarge { log_h: h, max: max_log });
            }
        }
        if airs.len() != log_heights.len() {
            return Err(ShapeError::TraceCountMismatch {
                airs: airs.len(),
                heights: log_heights.len(),
            });
        }
        for (idx, (air, &log_h)) in airs.iter().zip(log_heights.iter()).enumerate() {
            let trace_height = 1usize << log_h as usize;
            let max_period = air.max_periodic_length();
            if trace_height < max_period {
                return Err(ShapeError::TraceHeightBelowPeriod {
                    air: idx,
                    trace_height,
                    max_period,
                });
            }
        }
        let n = log_heights.len();
        // `0..n as u8` would wrap to an empty range at the boundary n == 256
        // (`256 as u8 == 0`), which the `TooManyInstances` guard above permits.
        let mut instance_indices: Vec<u8> = (0..n).map(|i| i as u8).collect();
        instance_indices.sort_by_key(|&i| (log_heights[i as usize], i));
        Ok(Self { log_heights, instance_indices })
    }

    /// Number of AIR instances.
    pub(crate) fn len(&self) -> usize {
        self.log_heights.len()
    }

    /// Log trace heights in instance order. Matches
    /// [`MultiAir::airs`](miden_lifted_air::MultiAir::airs).
    pub(crate) fn log_heights(&self) -> &[u8] {
        &self.log_heights
    }

    /// Instance indices in proof order: `instance_indices()[j]` is the
    /// instance index of the AIR at proof position `j`.
    pub(crate) fn instance_indices(&self) -> &[u8] {
        &self.instance_indices
    }

    /// Bind protocol-owned instance shape into Fiat-Shamir.
    ///
    /// The instance count is observed first, followed by log trace heights in
    /// instance order. Proof order is derived deterministically from these
    /// heights, so it is not observed separately.
    pub(crate) fn observe_shape<F, C>(&self, challenger: &mut C)
    where
        F: Field,
        C: CanObserve<F>,
    {
        challenger.observe(F::from_usize(self.len()));
        for &log_h in self.log_heights() {
            challenger.observe(F::from_u8(log_h));
        }
    }

    /// Log trace heights in proof order (ascending by construction).
    pub(crate) fn log_heights_proof(&self) -> Vec<u8> {
        self.instance_indices.iter().map(|&i| self.log_heights[i as usize]).collect()
    }

    /// The largest log trace height (= last entry of [`Self::log_heights_proof`]).
    pub(crate) fn max_log_height(&self) -> u8 {
        // `instance_indices` is non-empty (constructor rejects empty input).
        let last = *self.instance_indices.last().expect("TraceOrder is non-empty");
        self.log_heights[last as usize]
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

    /// AIR instance index backing each committed preprocessed trace.
    ///
    /// The preprocessed commitment contains one committed LDE trace per AIR with
    /// [`preprocessed_width`](miden_lifted_air::BaseAir::preprocessed_width)
    /// `> 0`, in proof order (the LMCS height-monotone committed-trace order). The result
    /// length is the number of preprocessed AIRs, which is `<= len()`.
    pub(crate) fn preprocessed_air_for_trace_index<F, EF, A>(&self, airs: &[A]) -> Vec<u8>
    where
        F: Field,
        A: LiftedAir<F, EF>,
    {
        self.instance_indices
            .iter()
            .copied()
            .filter(|&i| airs[i as usize].preprocessed_width() > 0)
            .collect()
    }

    /// Preprocessed trace index for each AIR, or `None` when the AIR declares no
    /// preprocessed columns. Length is [`Self::len`]; the inverse of
    /// [`Self::preprocessed_air_for_trace_index`].
    pub(crate) fn preprocessed_trace_index_for_air<F, EF, A>(
        &self,
        airs: &[A],
    ) -> Vec<Option<usize>>
    where
        F: Field,
        A: LiftedAir<F, EF>,
    {
        let air_for_preprocessed_trace = self.preprocessed_air_for_trace_index::<F, EF, A>(airs);
        let mut v = alloc::vec![None; airs.len()];
        for (preprocessed_trace_idx, &air_idx) in air_for_preprocessed_trace.iter().enumerate() {
            v[air_idx as usize] = Some(preprocessed_trace_idx);
        }
        v
    }
}

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
    #[error("AIR {air}: trace height must be at least 2 rows")]
    TraceHeightTooSmall { air: usize },
    #[error("log trace height {log_h} exceeds {max} (would overflow usize on this target)")]
    LogTraceHeightTooLarge { log_h: u8, max: u8 },
    #[error("more than 256 instances ({count}) — exceeds the u8 caller-index limit")]
    TooManyInstances { count: usize },
    #[error("airs().len() = {airs} does not match log trace heights length {heights}")]
    TraceCountMismatch { airs: usize, heights: usize },
    #[error(
        "AIR {air}: trace height = {trace_height} is less than max periodic column \
         length {max_period}"
    )]
    TraceHeightBelowPeriod {
        air: usize,
        trace_height: usize,
        max_period: usize,
    },
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_lifted_air::{BaseAir, LiftedAirBuilder};
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;

    type TF = Goldilocks;

    /// Minimal AIR with no periodic columns, for the ordering tests (which only
    /// exercise the height permutation, not the periodic-feasibility check).
    #[derive(Clone)]
    struct OrderTestAir;

    impl BaseAir<TF> for OrderTestAir {
        fn width(&self) -> usize {
            1
        }
    }

    impl LiftedAir<TF, TF> for OrderTestAir {
        fn num_randomness(&self) -> usize {
            0
        }
        fn aux_width(&self) -> usize {
            1
        }
        fn num_aux_values(&self) -> usize {
            0
        }
        fn build_aux_trace(
            &self,
            _main: &RowMajorMatrix<TF>,
            _air_inputs: &[TF],
            _aux_inputs: &[TF],
            _challenges: &[TF],
        ) -> (RowMajorMatrix<TF>, Vec<TF>) {
            // Unused: these tests only exercise the height permutation.
            (RowMajorMatrix::new(Vec::new(), 1), Vec::new())
        }
        fn eval<AB: LiftedAirBuilder<F = TF>>(&self, _builder: &mut AB) {}
    }

    fn airs(n: usize) -> Vec<OrderTestAir> {
        vec![OrderTestAir; n]
    }

    #[test]
    fn trace_order_canonical_ordering() {
        // Instance order: heights [8, 2, 8, 4]. Sort by (log_h, idx) →
        // [1 (log=1), 3 (log=2), 0 (log=3), 2 (log=3)].
        let order = TraceOrder::from_trace_heights::<TF, TF, _>(&airs(4), &[8, 2, 8, 4]).unwrap();
        assert_eq!(order.instance_indices(), &[1, 3, 0, 2]);
        assert_eq!(order.log_heights(), &[3, 1, 3, 2]);
        assert_eq!(order.log_heights_proof(), vec![1, 2, 3, 3]);
        assert_eq!(order.max_log_height(), 3);
    }

    #[test]
    fn trace_order_roundtrip() {
        let order = TraceOrder::from_trace_heights::<TF, TF, _>(&airs(4), &[8, 2, 8, 4]).unwrap();
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
            let order =
                TraceOrder::from_trace_heights::<TF, TF, _>(&airs(heights.len()), heights).unwrap();
            let instance_data: Vec<usize> = (0..heights.len()).collect();
            let expected = order.to_proof_order(&instance_data);
            let mut data = instance_data;
            order.reorder_to_proof_in_place(&mut data);
            assert_eq!(data, expected, "in-place mismatch for heights {heights:?}");
        }
    }

    #[test]
    fn trace_order_accepts_max_instances() {
        // The boundary n == 256 (= u8::MAX + 1) is the largest accepted count;
        // index construction must not wrap `256 as u8` to an empty range.
        let n = 256;
        let order = TraceOrder::from_log_heights::<TF, TF, _>(&airs(n), vec![1; n]).unwrap();
        assert_eq!(order.instance_indices().len(), n);
        let mut seen = order.instance_indices().to_vec();
        seen.sort_unstable();
        assert!(seen.iter().copied().eq(0..=u8::MAX), "indices must be a permutation of 0..=255");
    }
}
