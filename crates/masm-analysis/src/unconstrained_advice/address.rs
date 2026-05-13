//! Diagnostics for unconstrained advice reaching memory address sinks.

use masm_decompiler::{Stmt, intrinsic_memory_address_arg_index};

use super::{
    effect::AdviceEffect,
    shared::Env,
    summary::{AdviceDiagnosticContext, AdviceDiagnosticsMap, AdviceSummaryMap},
    walker::{self, AdviceCapability},
};
use crate::prepared::PreparedAnalysis;

/// Collect memory-address diagnostics for all procedures.
pub(super) fn collect_address_diagnostics(
    prepared: &PreparedAnalysis,
    provenance_summaries: &AdviceSummaryMap,
) -> AdviceDiagnosticsMap {
    walker::collect_diagnostics(prepared, provenance_summaries, |proc_path| AddressCapability {
        diagnostics: AdviceDiagnosticContext::new(proc_path),
    })
}

/// Advice capability for unconstrained advice reaching memory addresses.
struct AddressCapability {
    diagnostics: AdviceDiagnosticContext,
}

impl AdviceCapability for AddressCapability {
    type Summary = ();

    fn check_stmt(&self, stmt: &Stmt, env: &Env) -> AdviceEffect {
        let mut effect = AdviceEffect::new();

        match stmt {
            Stmt::MemStore { span, store } => {
                if let Some(addr_var) = store.address.first() {
                    let addr_fact = env.fact_for_var(addr_var);
                    if addr_fact.has_concrete_sources() {
                        effect.push_diagnostic(self.diagnostics.diagnostic_for_fact(
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
                        effect.push_diagnostic(self.diagnostics.diagnostic_for_fact(
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
                        effect.push_diagnostic(self.diagnostics.diagnostic_for_fact(
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
