//! Diagnostics for unconstrained advice reaching Merkle tree root arguments.

use std::collections::HashMap;

use masm_decompiler::{SymbolPath, ir::Stmt};

use super::{
    domain::AdviceFact,
    inter::PreparedProc,
    shared::{Env, intrinsic_base_name},
    summary::{AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSinkKind, AdviceSummaryMap},
    walker::{self, SinkDetector},
};

/// Collect Merkle-root diagnostics for all procedures.
pub(crate) fn collect_merkle_diagnostics(
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

        let base = intrinsic_base_name(&intrinsic.name);
        let root_range = match base {
            "mtree_get" if intrinsic.args.len() == 6 && intrinsic.results.len() == 4 => 2..6,
            "mtree_set" if intrinsic.args.len() == 10 && intrinsic.results.len() == 8 => 2..6,
            "mtree_verify" if intrinsic.args.len() == 10 && intrinsic.results.is_empty() => 6..10,
            _ => return Vec::new(),
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
        let mut diagnostic = AdviceDiagnostic::new(
            self.proc_path.clone(),
            span,
            AdviceSinkKind::MerkleRoot,
            message,
        );
        diagnostic.origins = fact.source_spans.iter().copied().collect();
        diagnostic
    }
}
