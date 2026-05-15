//! Internal analysis capability boundary.

use crate::prepared::PreparedAnalysis;

/// Scheduler-level analysis unit that consumes prepared analysis state.
pub(crate) trait AnalysisCapability {
    /// Result produced by this capability.
    type Output;

    /// Run this capability against prepared analysis state.
    fn analyze(&self, prepared: &PreparedAnalysis) -> Self::Output;
}
