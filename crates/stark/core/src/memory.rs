//! Supplied allocation budgets for relation trace construction.
//!
//! Relations derive these coefficients from their AIR geometry and proving configuration. Trace
//! builders can enforce the resulting budget without choosing a relation or proof configuration.

/// Linear per-AIR costs plus a shared cost proportional to the greatest AIR height.
///
/// The safety multiplier is applied once to the checked total, with ceiling division. Applying
/// rounding to each coefficient separately would describe a different model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProverMemoryModel<const N: usize> {
    per_air_bytes_per_row: [u64; N],
    shared_bytes_per_max_row: u64,
    additional_shared_bytes_per_max_row: u64,
    fixed_bytes: u64,
    safety_numerator: u64,
    safety_denominator: u64,
}

impl<const N: usize> ProverMemoryModel<N> {
    /// Constructs a model from relation-derived costs.
    ///
    /// # Panics
    /// Panics if the safety denominator is zero.
    pub const fn new(
        per_air_bytes_per_row: [u64; N],
        shared_bytes_per_max_row: u64,
        safety_numerator: u64,
        safety_denominator: u64,
    ) -> Self {
        assert!(safety_denominator > 0, "memory-model denominator must be positive");
        Self {
            per_air_bytes_per_row,
            shared_bytes_per_max_row,
            additional_shared_bytes_per_max_row: 0,
            fixed_bytes: 0,
            safety_numerator,
            safety_denominator,
        }
    }

    /// Includes fixed setup buffers before applying the safety multiplier.
    pub const fn with_fixed_bytes(mut self, fixed_bytes: u64) -> Self {
        self.fixed_bytes = fixed_bytes;
        self
    }

    /// Includes another shared row cost, keeping its multiplication separately checked.
    ///
    /// Adding this coefficient to the first one before multiplying would reject some zero-height
    /// shapes merely because the coefficient sum overflows. Sum the products instead.
    pub const fn with_additional_shared_bytes_per_max_row(mut self, cost: u64) -> Self {
        self.additional_shared_bytes_per_max_row = cost;
        self
    }

    /// Returns the modelled peak bytes for the padded per-AIR heights, or `None` on overflow.
    pub fn prover_peak_bytes(&self, heights: &[usize; N]) -> Option<u64> {
        let mut per_air_total = 0u64;
        let mut max_height = 0u64;
        for (&cost, &height) in self.per_air_bytes_per_row.iter().zip(heights.iter()) {
            let height = u64::try_from(height).ok()?;
            per_air_total = per_air_total.checked_add(cost.checked_mul(height)?)?;
            max_height = max_height.max(height);
        }
        let shared_total = self
            .shared_bytes_per_max_row
            .checked_mul(max_height)?
            .checked_add(self.additional_shared_bytes_per_max_row.checked_mul(max_height)?)?;
        per_air_total
            .checked_add(shared_total)?
            .checked_add(self.fixed_bytes)?
            .checked_mul(self.safety_numerator)
            .map(|scaled| scaled.div_ceil(self.safety_denominator))
    }

    /// Largest single-AIR height that fits the budget, considering every AIR in turn.
    ///
    /// This permissive cap never rejects a shape accepted by the exact model.
    pub fn max_any_height_for_budget(&self, limit_bytes: u64) -> usize {
        let mut best = 0;
        for index in 0..N {
            let fits = |height| {
                let mut heights = [0; N];
                heights[index] = height;
                self.prover_peak_bytes(&heights).is_some_and(|bytes| bytes <= limit_bytes)
            };
            if fits(usize::MAX) {
                return usize::MAX;
            }
            let mut lo = 0;
            let mut hi = usize::MAX;
            while hi - lo > 1 {
                let mid = lo + (hi - lo) / 2;
                if fits(mid) {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            best = best.max(lo);
        }
        best
    }
}

/// A caller-selected byte limit and the relation model used to enforce it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvingBudget<const N: usize> {
    model: ProverMemoryModel<N>,
    limit_bytes: u64,
}

impl<const N: usize> ProvingBudget<N> {
    pub const fn new(model: ProverMemoryModel<N>, limit_bytes: u64) -> Self {
        Self { model, limit_bytes }
    }

    pub const fn model(&self) -> &ProverMemoryModel<N> {
        &self.model
    }

    pub const fn limit_bytes(&self) -> u64 {
        self.limit_bytes
    }

    pub fn prover_peak_bytes(&self, heights: &[usize; N]) -> Option<u64> {
        self.model.prover_peak_bytes(heights)
    }

    pub fn max_any_height(&self) -> usize {
        self.model.max_any_height_for_budget(self.limit_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_and_additional_shared_costs_round_once_with_the_trace_costs() {
        let model = ProverMemoryModel::new([1, 2], 2, 5, 4)
            .with_fixed_bytes(1)
            .with_additional_shared_bytes_per_max_row(1);
        assert_eq!(model.prover_peak_bytes(&[1, 2]), Some(15));
        assert_eq!(model.prover_peak_bytes(&[0, 0]), Some(2));
    }

    #[test]
    fn shared_components_are_multiplied_before_their_checked_sum() {
        let model =
            ProverMemoryModel::new([0], u64::MAX, 1, 1).with_additional_shared_bytes_per_max_row(1);
        assert_eq!(model.prover_peak_bytes(&[0]), Some(0));
        assert_eq!(model.prover_peak_bytes(&[1]), None);
        assert_eq!(
            ProverMemoryModel::new([1], 0, 1, 1)
                .with_fixed_bytes(u64::MAX)
                .prover_peak_bytes(&[1]),
            None
        );
    }

    #[test]
    fn safety_rounds_once_after_adding_shared_and_per_air_costs() {
        let model = ProverMemoryModel::new([1, 2], 2, 5, 4);
        assert_eq!(model.prover_peak_bytes(&[1, 2]), Some(12));
        assert_eq!(model.prover_peak_bytes(&[0, 0]), Some(0));
    }

    #[test]
    fn permissive_cap_accepts_every_height_in_a_fitting_shape() {
        let model = ProverMemoryModel::new([7, 2], 3, 5, 4);
        let heights = [8, 16];
        let bytes = model.prover_peak_bytes(&heights).unwrap();
        let budget = ProvingBudget::new(model, bytes);
        let cap = budget.max_any_height();
        assert!(heights.into_iter().all(|height| height <= cap));
        assert!(model.prover_peak_bytes(&[0, cap]).unwrap() <= bytes);
        assert!(model.prover_peak_bytes(&[0, cap + 1]).unwrap() > bytes);
    }

    #[test]
    fn overflow_is_rejected_before_safety_rounding() {
        assert_eq!(ProverMemoryModel::new([u64::MAX], 0, 1, 1).prover_peak_bytes(&[2]), None);
        assert_eq!(ProverMemoryModel::new([u64::MAX], 1, 1, 1).prover_peak_bytes(&[1]), None);
        assert_eq!(ProverMemoryModel::new([u64::MAX], 0, 2, 2).prover_peak_bytes(&[1]), None);
    }
}
