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

    /// Return the final abstract state.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Consume the result and return the final abstract state.
    pub fn into_state(self) -> S {
        self.state
    }

    /// Return the number of transfer rounds that were executed.
    pub fn iterations(&self) -> usize {
        self.iterations
    }

    /// Return the engine outcome.
    pub fn outcome(&self) -> FixpointOutcome {
        self.outcome
    }

    /// Return `true` when the last allowed transfer changed the state but the budget was exhausted.
    pub fn limit_exhausted_after_change(&self) -> bool {
        self.outcome == FixpointOutcome::ReachedIterationLimitAfterChange
    }

    /// Return `true` if the engine observed stability within the configured evaluation budget.
    pub fn converged(&self) -> bool {
        self.outcome == FixpointOutcome::Converged
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
