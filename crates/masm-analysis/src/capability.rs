//! Internal analysis capability boundary.

use miden_assembly_syntax::ast::Module;

use crate::prepared::PreparedAnalysis;

/// Scheduler-level analysis unit that consumes prepared analysis state.
pub(crate) trait AnalysisCapability {
    /// Result produced by this capability.
    type Output;

    /// Run this capability against prepared analysis state.
    fn analyze(&self, prepared: &PreparedAnalysis) -> Self::Output;
}

/// Analysis unit that evaluates one MASM module at a time.
pub(crate) trait ModuleAnalysisCapability {
    /// Result produced for a module.
    type Output;

    /// Run this capability against one module.
    fn analyze_module(&self, module: &Module) -> Self::Output;
}
