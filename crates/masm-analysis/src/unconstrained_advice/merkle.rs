//! Diagnostics for unconstrained advice reaching Merkle tree root arguments.

use std::collections::HashMap;

use masm_decompiler::{Stmt, SymbolPath};

use super::{
    domain::AdviceFact,
    shared::{Env, intrinsic_merkle_root_arg_range},
    summary::{AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSummaryMap, diagnostic_from_fact},
    walker::{self, AdviceCapability, AdviceEffect},
};
use crate::prepared::PreparedProc;

/// Collect Merkle-root diagnostics for all procedures.
pub(super) fn collect_merkle_diagnostics(
    prepared: &HashMap<SymbolPath, PreparedProc>,
    provenance_summaries: &AdviceSummaryMap,
) -> AdviceDiagnosticsMap {
    walker::collect_diagnostics(prepared, provenance_summaries, |proc_path| MerkleCapability {
        proc_path,
    })
}

/// Advice capability for unconstrained advice reaching Merkle tree root positions.
struct MerkleCapability {
    proc_path: SymbolPath,
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
            AdviceEffect::diagnostics(vec![self.new_diagnostic(
                *span,
                "unconstrained advice used as Merkle tree root",
                &root_fact,
            )])
        } else {
            AdviceEffect::new()
        }
    }
}

impl MerkleCapability {
    /// Create a diagnostic for a Merkle root sink.
    fn new_diagnostic(
        &self,
        span: miden_debug_types::SourceSpan,
        message: impl Into<String>,
        fact: &AdviceFact,
    ) -> AdviceDiagnostic {
        diagnostic_from_fact(self.proc_path.clone(), span, message, fact)
    }
}
