//! Reusable analysis passes for MASM linting.

use std::{collections::HashMap, sync::Arc};

use masm_decompiler::{SymbolPath, Workspace};
use miden_debug_types::DefaultSourceManager;

mod abstract_interp;
mod capability;
pub mod lint;
mod lint_policy;
mod prepared;
mod signature_mismatch;
mod unconstrained_advice;

use capability::AnalysisCapability;
use prepared::PreparedAnalysis;
use signature_mismatch::{SignatureMismatch, SignatureMismatchCapability};
use unconstrained_advice::{AdviceDiagnostic, UnconstrainedAdviceCapability};

/// Results of running all analysis passes on a workspace.
#[derive(Debug)]
struct AnalysisSnapshot {
    /// Declared-vs-inferred signature mismatch diagnostics.
    signature_mismatches: Vec<SignatureMismatch>,
    /// Unconstrained advice flow diagnostics.
    advice_diagnostics: HashMap<SymbolPath, Vec<AdviceDiagnostic>>,
}

impl AnalysisSnapshot {
    /// Run all analysis passes on a workspace and return the combined results.
    fn from_workspace(
        workspace: &Workspace,
        sources: Arc<DefaultSourceManager>,
        include_signature_mismatches: bool,
    ) -> Self {
        let prepared = PreparedAnalysis::new(workspace);
        let signature_mismatches = if include_signature_mismatches {
            SignatureMismatchCapability::new(workspace, sources).analyze(&prepared)
        } else {
            Vec::new()
        };
        let advice_diagnostics = UnconstrainedAdviceCapability.analyze(&prepared);

        Self { signature_mismatches, advice_diagnostics }
    }
}
