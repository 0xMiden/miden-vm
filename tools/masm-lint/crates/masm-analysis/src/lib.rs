//! Reusable analysis passes for MASM linting.

use std::{collections::HashMap, sync::Arc};

use masm_decompiler::analysis::{SymbolPath, Workspace};
use miden_debug_types::DefaultSourceManager;

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
        run_capabilities(workspace, sources, &prepared, include_signature_mismatches)
    }
}

/// Run the static MASM analysis capability schedule.
///
/// Capabilities consume the same prepared analysis snapshot, so the schedule is
/// deliberately explicit instead of a dynamic registry:
///
/// 1. Signature mismatch diagnostics are optional lint output and need access to source
///    declarations in the workspace.
/// 2. Advice diagnostics consume only prepared lifted procedures, signatures, type summaries, and
///    callgraph order.
///
/// The capabilities currently have no data dependency on each other's outputs;
/// keeping the ordering here makes that invariant visible if a future pass does
/// start consuming diagnostics or summaries produced by another capability.
fn run_capabilities(
    workspace: &Workspace,
    sources: Arc<DefaultSourceManager>,
    prepared: &PreparedAnalysis,
    include_signature_mismatches: bool,
) -> AnalysisSnapshot {
    let signature_mismatches = if include_signature_mismatches {
        SignatureMismatchCapability::new(workspace, sources).analyze(prepared)
    } else {
        Vec::new()
    };
    let advice_diagnostics = UnconstrainedAdviceCapability.analyze(prepared);

    AnalysisSnapshot { signature_mismatches, advice_diagnostics }
}
