//! Diagnostics for unconstrained advice reaching Merkle tree root arguments.

use std::collections::HashMap;

use masm_decompiler::{Stmt, SymbolPath};

use super::{
    domain::AdviceFact,
    shared::{Env, intrinsic_merkle_root_arg_range},
    summary::{AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSummaryMap, diagnostic_from_fact},
    walker::{self, SinkDetector},
};
use crate::prepared::PreparedProc;

/// Collect Merkle-root diagnostics for all procedures.
pub(super) fn collect_merkle_diagnostics(
    prepared: &HashMap<SymbolPath, PreparedProc>,
    provenance_summaries: &AdviceSummaryMap,
) -> AdviceDiagnosticsMap {
    walker::collect_diagnostics(prepared, provenance_summaries, |proc_path| MerkleDetector {
        proc_path,
    })
}

/// Sink detector for unconstrained advice reaching Merkle tree root positions.
struct MerkleDetector {
    proc_path: SymbolPath,
}

impl SinkDetector for MerkleDetector {
    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> Vec<AdviceDiagnostic> {
        let Stmt::Intrinsic { span, intrinsic } = stmt else {
            return Vec::new();
        };

        let Some(root_range) = intrinsic_merkle_root_arg_range(
            &intrinsic.name,
            intrinsic.args.len(),
            intrinsic.results.len(),
        ) else {
            return Vec::new();
        };

        let root_fact = AdviceFact::join_all(
            intrinsic.args[root_range].iter().map(|var| env.fact_for_var(var)),
        );

        if root_fact.has_concrete_sources() {
            vec![self.new_diagnostic(
                *span,
                "unconstrained advice used as Merkle tree root",
                &root_fact,
            )]
        } else {
            Vec::new()
        }
    }
}

impl MerkleDetector {
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
