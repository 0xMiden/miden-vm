//! Diagnostics for unconstrained advice reaching memory address sinks.

use std::collections::HashMap;

use masm_decompiler::{SymbolPath, ir::Stmt};

use super::{
    domain::AdviceFact,
    inter::PreparedProc,
    shared::{Env, intrinsic_base_name},
    summary::{AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSinkKind, AdviceSummaryMap},
    walker::{self, SinkDetector},
};

/// Collect memory-address diagnostics for all procedures.
pub(crate) fn collect_address_diagnostics(
    prepared: &HashMap<SymbolPath, PreparedProc>,
    provenance_summaries: &AdviceSummaryMap,
) -> AdviceDiagnosticsMap {
    walker::collect_diagnostics(prepared, provenance_summaries, |proc_path| AddressDetector {
        proc_path,
    })
}

/// Sink detector for unconstrained advice reaching memory addresses.
struct AddressDetector {
    proc_path: SymbolPath,
}

impl SinkDetector for AddressDetector {
    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> Vec<AdviceDiagnostic> {
        let mut diagnostics = Vec::new();

        match stmt {
            Stmt::MemStore { span, store } => {
                if let Some(addr_var) = store.address.first() {
                    if env.u32_validity_for_var(addr_var).is_proven() {
                        return diagnostics;
                    }
                    let addr_fact = env.fact_for_var(addr_var);
                    if addr_fact.has_concrete_sources() {
                        diagnostics.push(self.new_diagnostic(
                            *span,
                            "unconstrained advice used as memory address",
                            &addr_fact,
                        ));
                    }
                }
            },
            Stmt::MemLoad { span, load } => {
                if let Some(addr_var) = load.address.first() {
                    if env.u32_validity_for_var(addr_var).is_proven() {
                        return diagnostics;
                    }
                    let addr_fact = env.fact_for_var(addr_var);
                    if addr_fact.has_concrete_sources() {
                        diagnostics.push(self.new_diagnostic(
                            *span,
                            "unconstrained advice used as memory address",
                            &addr_fact,
                        ));
                    }
                }
            },
            Stmt::Intrinsic { span, intrinsic } => {
                let base = intrinsic_base_name(&intrinsic.name);
                if (base == "adv_pipe" || base == "mem_stream")
                    && intrinsic.args.len() == 13
                    && intrinsic.results.len() == 13
                {
                    if env.u32_validity_for_var(&intrinsic.args[12]).is_proven() {
                        return diagnostics;
                    }
                    let addr_fact = env.fact_for_var(&intrinsic.args[12]);
                    if addr_fact.has_concrete_sources() {
                        diagnostics.push(self.new_diagnostic(
                            *span,
                            "unconstrained advice used as memory address",
                            &addr_fact,
                        ));
                    }
                }
            },
            _ => {},
        }

        diagnostics
    }
}

impl AddressDetector {
    /// Create a diagnostic for a memory address sink.
    fn new_diagnostic(
        &self,
        span: miden_debug_types::SourceSpan,
        message: impl Into<String>,
        fact: &AdviceFact,
    ) -> AdviceDiagnostic {
        let mut diagnostic = AdviceDiagnostic::new(
            self.proc_path.clone(),
            span,
            AdviceSinkKind::MemoryAddress,
            message,
        );
        diagnostic.origins = fact.source_spans.iter().copied().collect();
        diagnostic
    }
}
