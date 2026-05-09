//! Diagnostics for unconstrained advice reaching memory address sinks.

use std::collections::HashMap;

use masm_decompiler::{Stmt, SymbolPath};

use super::{
    domain::AdviceFact,
    shared::{Env, intrinsic_memory_address_arg_index},
    summary::{AdviceDiagnostic, AdviceDiagnosticsMap, AdviceSummaryMap, diagnostic_from_fact},
    walker::{self, AdviceCapability, AdviceEffect},
};
use crate::prepared::PreparedProc;

/// Collect memory-address diagnostics for all procedures.
pub(super) fn collect_address_diagnostics(
    prepared: &HashMap<SymbolPath, PreparedProc>,
    provenance_summaries: &AdviceSummaryMap,
) -> AdviceDiagnosticsMap {
    walker::collect_diagnostics(prepared, provenance_summaries, |proc_path| AddressCapability {
        proc_path,
    })
}

/// Advice capability for unconstrained advice reaching memory addresses.
struct AddressCapability {
    proc_path: SymbolPath,
}

impl AdviceCapability for AddressCapability {
    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> AdviceEffect {
        let mut effect = AdviceEffect::new();

        match stmt {
            Stmt::MemStore { span, store } => {
                if let Some(addr_var) = store.address.first() {
                    let addr_fact = env.fact_for_var(addr_var);
                    if addr_fact.has_concrete_sources() {
                        effect.push_diagnostic(self.new_diagnostic(
                            *span,
                            "unconstrained advice used as memory address",
                            &addr_fact,
                        ));
                    }
                }
            },
            Stmt::MemLoad { span, load } => {
                if let Some(addr_var) = load.address.first() {
                    let addr_fact = env.fact_for_var(addr_var);
                    if addr_fact.has_concrete_sources() {
                        effect.push_diagnostic(self.new_diagnostic(
                            *span,
                            "unconstrained advice used as memory address",
                            &addr_fact,
                        ));
                    }
                }
            },
            Stmt::Intrinsic { span, intrinsic } => {
                if intrinsic.args.len() == 13
                    && intrinsic.results.len() == 13
                    && let Some(addr_index) =
                        intrinsic_memory_address_arg_index(&intrinsic.name, intrinsic.args.len())
                {
                    let addr_fact = env.fact_for_var(&intrinsic.args[addr_index]);
                    if addr_fact.has_concrete_sources() {
                        effect.push_diagnostic(self.new_diagnostic(
                            *span,
                            "unconstrained advice used as memory address",
                            &addr_fact,
                        ));
                    }
                }
            },
            _ => {},
        }

        effect
    }
}

impl AddressCapability {
    /// Create a diagnostic for a memory address sink.
    fn new_diagnostic(
        &self,
        span: miden_debug_types::SourceSpan,
        message: impl Into<String>,
        fact: &AdviceFact,
    ) -> AdviceDiagnostic {
        diagnostic_from_fact(self.proc_path.clone(), span, message, fact)
    }
}
