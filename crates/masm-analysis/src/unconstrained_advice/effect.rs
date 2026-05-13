//! Capability effects produced while walking advice statements.

use std::collections::BTreeSet;

use super::{shared::Env, summary::AdviceDiagnostic};

/// Capability-owned summary contribution accumulated by the shared walker.
pub(super) trait AdviceSummaryContribution: Default {
    /// Merge another contribution from the same capability into this one.
    fn merge(&mut self, other: Self);
}

impl AdviceSummaryContribution for () {
    fn merge(&mut self, _other: Self) {}
}

impl AdviceSummaryContribution for BTreeSet<usize> {
    fn merge(&mut self, other: Self) {
        self.extend(other);
    }
}

/// Effects contributed by an advice capability while walking one statement.
#[derive(Debug, Clone, Default)]
pub(super) struct AdviceEffect<S: AdviceSummaryContribution = ()> {
    /// Diagnostics detected by the capability.
    pub(super) diagnostics: Vec<AdviceDiagnostic>,
    /// Summary contribution detected by the capability.
    pub(super) summary: S,
}

impl<S: AdviceSummaryContribution> AdviceEffect<S> {
    /// Create an empty effect.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Create an effect containing diagnostics only.
    pub(super) fn diagnostics(diagnostics: Vec<AdviceDiagnostic>) -> Self {
        Self { diagnostics, summary: S::default() }
    }

    /// Add one diagnostic.
    pub(super) fn push_diagnostic(&mut self, diagnostic: AdviceDiagnostic) {
        self.diagnostics.push(diagnostic);
    }

    /// Merge capability-owned summary information into this effect.
    pub(super) fn merge_summary(&mut self, summary: S) {
        self.summary.merge(summary);
    }
}

/// Result of walking one procedure with an advice capability.
#[derive(Debug, Clone, Default)]
pub(super) struct AdviceWalkResult<S: AdviceSummaryContribution = ()> {
    /// Environment after walking the procedure body.
    pub(super) env: Env,
    /// Diagnostics emitted while walking the procedure.
    pub(super) diagnostics: Vec<AdviceDiagnostic>,
    /// Summary contribution accumulated by this capability.
    pub(super) summary: S,
    /// Whether the walk encountered an opaque construct.
    pub(super) opaque: bool,
}
