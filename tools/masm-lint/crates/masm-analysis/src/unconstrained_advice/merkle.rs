//! Diagnostics for unconstrained advice reaching Merkle tree root arguments.

use masm_decompiler::analysis::{Stmt, intrinsic_arg_requirements};

use super::{
    effect::AdviceEffect,
    shared::Env,
    sink::{joined_var_fact, push_fact_sink_diagnostic},
    summary::{AdviceDiagnosticContext, AdviceDiagnosticsMap, AdviceSummaryMap},
    walker::{self, AdviceCapability},
};
use crate::prepared::PreparedAnalysis;

/// Collect Merkle-root diagnostics for all procedures.
pub(super) fn collect_merkle_diagnostics(
    prepared: &PreparedAnalysis,
    provenance_summaries: &AdviceSummaryMap,
) -> AdviceDiagnosticsMap {
    walker::collect_diagnostics(prepared, provenance_summaries, |proc_path| MerkleCapability {
        diagnostics: AdviceDiagnosticContext::new(proc_path),
    })
}

/// Advice capability for unconstrained advice reaching Merkle tree root positions.
struct MerkleCapability {
    diagnostics: AdviceDiagnosticContext,
}

impl AdviceCapability for MerkleCapability {
    type Summary = ();

    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> AdviceEffect {
        let Stmt::Intrinsic { span, intrinsic } = stmt else {
            return AdviceEffect::new();
        };

        let requirements = intrinsic_arg_requirements(
            &intrinsic.name,
            intrinsic.args.len(),
            intrinsic.results.len(),
        );
        let Some(root_range) = requirements.merkle_root_args else {
            return AdviceEffect::new();
        };

        let root_fact = joined_var_fact(&intrinsic.args[root_range], env);
        let mut effect = AdviceEffect::new();
        push_fact_sink_diagnostic(
            &mut effect,
            &self.diagnostics,
            *span,
            "unconstrained advice used as Merkle tree root",
            &root_fact,
        );
        effect
    }
}
