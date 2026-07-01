//! Shared sink diagnostic helpers for advice capabilities.

use masm_decompiler::analysis::Var;
use miden_debug_types::SourceSpan;

use super::{
    domain::AdviceFact,
    effect::{AdviceEffect, AdviceSummaryContribution},
    shared::Env,
    summary::AdviceDiagnosticContext,
};

/// Join the advice facts for a set of variables.
pub(super) fn joined_var_fact<'a>(
    vars: impl IntoIterator<Item = &'a Var>,
    env: &Env,
) -> AdviceFact {
    AdviceFact::join_all(vars.into_iter().map(|var| env.fact_for_var(var)))
}

/// Add a diagnostic for a concrete advice fact.
pub(super) fn push_fact_sink_diagnostic<S: AdviceSummaryContribution>(
    effect: &mut AdviceEffect<S>,
    diagnostics: &AdviceDiagnosticContext,
    span: SourceSpan,
    message: impl Into<String>,
    fact: &AdviceFact,
) {
    if fact.has_concrete_sources() {
        effect.push_diagnostic(diagnostics.diagnostic_for_fact(span, message, fact));
    }
}

/// Add a diagnostic for a variable sink when the variable has concrete advice provenance.
pub(super) fn push_var_sink_diagnostic<S: AdviceSummaryContribution>(
    effect: &mut AdviceEffect<S>,
    diagnostics: &AdviceDiagnosticContext,
    span: SourceSpan,
    message: impl Into<String>,
    var: &Var,
    env: &Env,
) {
    let fact = env.fact_for_var(var);
    push_fact_sink_diagnostic(effect, diagnostics, span, message, &fact);
}
