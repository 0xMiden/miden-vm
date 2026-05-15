//! Diagnostics for unconstrained advice reaching memory address sinks.

use masm_decompiler::analysis::{Stmt, intrinsic_arg_requirements};

use super::{
    effect::AdviceEffect,
    shared::Env,
    sink::push_var_sink_diagnostic,
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
                    push_var_sink_diagnostic(
                        &mut effect,
                        &self.diagnostics,
                        *span,
                        "unconstrained advice used as memory address",
                        addr_var,
                        env,
                    );
                }
            },
            Stmt::MemLoad { span, load } => {
                if let Some(addr_var) = load.address.first() {
                    push_var_sink_diagnostic(
                        &mut effect,
                        &self.diagnostics,
                        *span,
                        "unconstrained advice used as memory address",
                        addr_var,
                        env,
                    );
                }
            },
            Stmt::Intrinsic { span, intrinsic } => {
                let requirements = intrinsic_arg_requirements(
                    &intrinsic.name,
                    intrinsic.args.len(),
                    intrinsic.results.len(),
                );
                if let Some(addr_index) = requirements.memory_address_arg {
                    push_var_sink_diagnostic(
                        &mut effect,
                        &self.diagnostics,
                        *span,
                        "unconstrained advice used as memory address",
                        &intrinsic.args[addr_index],
                        env,
                    );
                }
            },
            _ => {},
        }

        effect
    }
}
