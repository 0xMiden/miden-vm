//! Diagnostics for unconstrained advice reaching Merkle tree root arguments.

use masm_decompiler::Stmt;

use super::{
    domain::AdviceFact,
    shared::{Env, intrinsic_merkle_root_arg_range},
    summary::{AdviceDiagnosticContext, AdviceDiagnosticsMap, AdviceSummaryMap},
    walker::{self, AdviceCapability, AdviceEffect},
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
    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> AdviceEffect {
        let Stmt::Intrinsic { span, intrinsic } = stmt else {
            return AdviceEffect::new();
        };

        let Some(root_range) = intrinsic_merkle_root_arg_range(
            &intrinsic.name,
            intrinsic.args.len(),
            intrinsic.results.len(),
        ) else {
            return AdviceEffect::new();
        };

        let root_fact = AdviceFact::join_all(
            intrinsic.args[root_range].iter().map(|var| env.fact_for_var(var)),
        );

        if root_fact.has_concrete_sources() {
            AdviceEffect::diagnostics(vec![self.diagnostics.diagnostic_for_fact(
                *span,
                "unconstrained advice used as Merkle tree root",
                &root_fact,
            )])
        } else {
            AdviceEffect::new()
        }
    }
}
