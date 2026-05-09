//! Interprocedural driver for unconstrained-advice analysis.

use masm_decompiler::{CallGraph, SymbolPath};

use super::{
    address::collect_address_diagnostics,
    merkle::collect_merkle_diagnostics,
    nonzero::infer_nonzero_summaries_and_diagnostics,
    provenance::analyze_proc_provenance,
    summary::{AdviceDiagnosticsMap, AdviceSummary, AdviceSummaryMap},
    u32::collect_u32_diagnostics,
};
use crate::prepared::{PreparedAnalysis, PreparedProc};

/// Infer unconstrained-advice summaries and diagnostics using precomputed analysis inputs.
pub(super) fn infer_unconstrained_advice(
    prepared: &PreparedAnalysis,
) -> (AdviceSummaryMap, AdviceDiagnosticsMap) {
    let mut advice_summaries =
        infer_provenance_summaries(&prepared.callgraph, &prepared.lifted_procs);
    let mut diagnostics = collect_u32_diagnostics(
        &prepared.lifted_procs,
        &advice_summaries,
        &prepared.type_summaries,
    );
    let address_diagnostics =
        collect_address_diagnostics(&prepared.lifted_procs, &advice_summaries);
    merge_diagnostics(&mut diagnostics, address_diagnostics);
    let merkle_diagnostics = collect_merkle_diagnostics(&prepared.lifted_procs, &advice_summaries);
    merge_diagnostics(&mut diagnostics, merkle_diagnostics);
    let nonzero_diagnostics = infer_nonzero_summaries_and_diagnostics(
        &prepared.callgraph,
        &prepared.lifted_procs,
        &mut advice_summaries,
    );
    merge_diagnostics(&mut diagnostics, nonzero_diagnostics);

    (advice_summaries, diagnostics)
}

/// Infer bottom-up provenance summaries for all procedures.
fn infer_provenance_summaries(
    callgraph: &CallGraph,
    prepared: &std::collections::HashMap<SymbolPath, PreparedProc>,
) -> AdviceSummaryMap {
    let mut summaries = AdviceSummaryMap::default();

    for node in callgraph.iter() {
        let Some(proc) = prepared.get(node.name()) else {
            summaries.insert(node.name().clone(), AdviceSummary::unknown());
            continue;
        };
        let summary = match proc.stmts.as_deref() {
            Some(stmts) => analyze_proc_provenance(proc.inputs, proc.outputs, stmts, &summaries),
            None => AdviceSummary::unknown_with_arity(proc.outputs),
        };
        summaries.insert(node.name().clone(), summary);
    }

    summaries
}

/// Merge diagnostics from one pass into the combined diagnostic map.
fn merge_diagnostics(combined: &mut AdviceDiagnosticsMap, next: AdviceDiagnosticsMap) {
    for (proc, mut proc_diags) in next {
        combined.entry(proc).or_default().append(&mut proc_diags);
    }
}
