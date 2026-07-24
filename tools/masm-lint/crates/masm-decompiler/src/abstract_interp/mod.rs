//! Reusable abstract-interpretation primitives for MASM analyses.
//!
//! This module is intentionally small and explicit so analyses can share one fixpoint engine.

/// Join-based abstract state used by the fixpoint engine.
///
/// Implementations should model a monotone abstract domain where `join_assign` updates `self` to
/// include information from `other`. The return value indicates whether the join changed the state.
pub trait JoinSemiLattice: Clone {
    /// Join `other` into `self`, returning `true` when the state changed.
    fn join_assign(&mut self, other: &Self) -> bool;
}

/// Configuration controlling fixpoint iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixpointConfig {
    /// Maximum number of transfer evaluations before the engine stops.
    ///
    /// This is a hard cutoff. A stable final allowed evaluation still reports
    /// [`FixpointOutcome::Converged`]. If the last allowed evaluation changes the state, the
    /// engine reports [`FixpointOutcome::ReachedIterationLimitAfterChange`] instead of probing
    /// again. [`FixpointOutcome::ReachedIterationLimit`] is reserved for cases where the
    /// budget is exhausted without observing stability or a final changing step.
    pub max_iterations: usize,
}

impl FixpointConfig {
    /// Create a fixpoint configuration with an explicit iteration cap.
    pub fn new(max_iterations: usize) -> Self {
        Self { max_iterations }
    }
}

impl Default for FixpointConfig {
    fn default() -> Self {
        Self { max_iterations: 32 }
    }
}

/// Outcome of a fixpoint iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixpointOutcome {
    /// The state stopped changing within the configured evaluation budget.
    Converged,
    /// The configured evaluation budget was exhausted before the engine observed another change.
    ReachedIterationLimit,
    /// The last allowed evaluation still changed the state.
    ///
    /// This outcome is intentionally distinct from [`Self::ReachedIterationLimit`]. At a hard
    /// cutoff, the engine does not probe again, so callers can distinguish "budget exhausted after
    /// a change" from cases where the budget was exhausted before any progress was made.
    ReachedIterationLimitAfterChange,
}

/// Result returned by the fixpoint engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixpointResult<S> {
    state: S,
    iterations: usize,
    outcome: FixpointOutcome,
}

impl<S> FixpointResult<S> {
    /// Create a fixpoint result from its final state, iteration count, and outcome.
    pub fn new(state: S, iterations: usize, outcome: FixpointOutcome) -> Self {
        Self { state, iterations, outcome }
    }

    /// Consume the result and return the final abstract state.
    pub fn into_state(self) -> S {
        self.state
    }

    /// Borrow the final abstract state.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Number of transfer evaluations performed by the engine.
    pub fn iterations(&self) -> usize {
        self.iterations
    }

    /// Outcome reported by the engine.
    pub fn outcome(&self) -> FixpointOutcome {
        self.outcome
    }
}

/// Iterate `step` until joining the candidate state no longer changes the current state.
///
/// The loop is:
/// 1. Start from the current abstract state.
/// 2. Apply a transfer function to produce a candidate next state.
/// 3. Join the candidate into the current state.
/// 4. Repeat until the join stops changing the state or a hard cutoff is reached.
pub fn iterate_to_fixpoint<S, F>(
    initial_state: S,
    config: FixpointConfig,
    mut step: F,
) -> FixpointResult<S>
where
    S: JoinSemiLattice,
    F: FnMut(&S) -> S,
{
    let mut state = initial_state;
    let mut steps = 0;
    let mut saw_change = false;

    for _iteration in 0..config.max_iterations {
        let candidate = step(&state);
        steps += 1;
        saw_change = state.join_assign(&candidate);
        if !saw_change {
            return FixpointResult::new(state, steps, FixpointOutcome::Converged);
        }
    }

    let outcome = if saw_change {
        FixpointOutcome::ReachedIterationLimitAfterChange
    } else {
        FixpointOutcome::ReachedIterationLimit
    };

    FixpointResult::new(state, steps, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Counter(u8);

    impl JoinSemiLattice for Counter {
        fn join_assign(&mut self, other: &Self) -> bool {
            let next = self.0.max(other.0);
            let changed = next != self.0;
            self.0 = next;
            changed
        }
    }

    #[test]
    fn fixpoint_reports_convergence_when_join_stabilizes() {
        let result = iterate_to_fixpoint(Counter(1), FixpointConfig::new(4), Clone::clone);

        assert_eq!(result.state(), &Counter(1));
        assert_eq!(result.iterations(), 1);
        assert_eq!(result.outcome(), FixpointOutcome::Converged);
    }

    #[test]
    fn fixpoint_reports_cutoff_after_final_change() {
        let result =
            iterate_to_fixpoint(Counter(0), FixpointConfig::new(2), |state| Counter(state.0 + 1));

        assert_eq!(result.state(), &Counter(2));
        assert_eq!(result.iterations(), 2);
        assert_eq!(result.outcome(), FixpointOutcome::ReachedIterationLimitAfterChange);
    }

    #[test]
    fn fixpoint_reports_empty_budget_cutoff() {
        let result =
            iterate_to_fixpoint(Counter(0), FixpointConfig::new(0), |state| Counter(state.0 + 1));

        assert_eq!(result.state(), &Counter(0));
        assert_eq!(result.iterations(), 0);
        assert_eq!(result.outcome(), FixpointOutcome::ReachedIterationLimit);
    }
}
