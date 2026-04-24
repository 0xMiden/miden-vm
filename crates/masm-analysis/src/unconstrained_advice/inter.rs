//! Interprocedural driver for unconstrained-advice analysis.

use std::collections::HashMap;

use masm_decompiler::{
    callgraph::CallGraph,
    frontend::Workspace,
    lift::lift_proc,
    signature::{ProcSignature, SignatureMap},
    symbol::resolution::create_resolver,
    types::TypeSummaryMap,
};

use super::{
    address::collect_address_diagnostics,
    merkle::collect_merkle_diagnostics,
    nonzero::infer_nonzero_summaries_and_diagnostics,
    provenance::analyze_proc_provenance,
    summary::{AdviceDiagnosticsMap, AdviceSummary, AdviceSummaryMap},
    u32::collect_u32_diagnostics,
};
use crate::analysis_inputs;

/// Prepared lifting result for one procedure.
#[derive(Debug, Clone)]
pub(crate) struct PreparedProc {
    /// Input arity inferred from the procedure signature.
    pub(crate) inputs: usize,
    /// Output arity inferred from the procedure signature.
    pub(crate) outputs: usize,
    /// Lifted SSA statements, when the procedure is analyzable.
    pub(crate) stmts: Option<Vec<masm_decompiler::ir::Stmt>>,
}

/// Infer unconstrained-advice summaries and diagnostics using precomputed analysis inputs.
pub fn infer_unconstrained_advice(
    workspace: &Workspace,
    callgraph: &CallGraph,
    signatures: &SignatureMap,
    type_summaries: &TypeSummaryMap,
) -> (AdviceSummaryMap, AdviceDiagnosticsMap) {
    let prepared = prepare_procs(workspace, callgraph, signatures);
    let provenance_summaries = infer_provenance_summaries(callgraph, &prepared);
    let mut diagnostics = collect_u32_diagnostics(&prepared, &provenance_summaries, type_summaries);
    let address_diagnostics = collect_address_diagnostics(&prepared, &provenance_summaries);
    merge_diagnostics(&mut diagnostics, address_diagnostics);
    let merkle_diagnostics = collect_merkle_diagnostics(&prepared, &provenance_summaries);
    merge_diagnostics(&mut diagnostics, merkle_diagnostics);
    let (_, nonzero_diagnostics) =
        infer_nonzero_summaries_and_diagnostics(callgraph, &prepared, &provenance_summaries);
    merge_diagnostics(&mut diagnostics, nonzero_diagnostics);

    (provenance_summaries, diagnostics)
}

/// Prepare and lift all procedures once for the downstream analyses.
fn prepare_procs(
    workspace: &Workspace,
    callgraph: &CallGraph,
    signatures: &SignatureMap,
) -> HashMap<crate::SymbolPath, PreparedProc> {
    let mut prepared = HashMap::new();

    for node in callgraph.iter() {
        let proc_path = node.name.clone();
        let Some(signature) = signatures.get(&proc_path) else {
            prepared.insert(proc_path, PreparedProc { inputs: 0, outputs: 0, stmts: None });
            continue;
        };

        let (inputs, outputs) = match signature {
            ProcSignature::Known { inputs, outputs, .. } => (*inputs, *outputs),
            ProcSignature::Unknown => {
                prepared.insert(proc_path, PreparedProc { inputs: 0, outputs: 0, stmts: None });
                continue;
            },
        };

        let Some((program, proc)) = workspace.lookup_proc_entry(&proc_path) else {
            prepared.insert(proc_path, PreparedProc { inputs, outputs, stmts: None });
            continue;
        };

        let resolver = create_resolver(program.module(), workspace.source_manager());
        let stmts = match lift_proc(proc, &proc_path, &resolver, signatures) {
            Ok(stmts) => Some(stmts),
            Err(_) => {
                prepared.insert(proc_path, PreparedProc { inputs, outputs, stmts: None });
                continue;
            },
        };
        prepared.insert(proc_path, PreparedProc { inputs, outputs, stmts });
    }

    prepared
}

/// Infer unconstrained-advice summaries and diagnostics by building analysis inputs locally.
pub fn infer_unconstrained_advice_in_workspace(
    workspace: &Workspace,
) -> (AdviceSummaryMap, AdviceDiagnosticsMap) {
    let (callgraph, signatures, type_summaries) = analysis_inputs(workspace);
    infer_unconstrained_advice(workspace, &callgraph, &signatures, &type_summaries)
}

/// Infer bottom-up provenance summaries for all procedures.
fn infer_provenance_summaries(
    callgraph: &CallGraph,
    prepared: &HashMap<crate::SymbolPath, PreparedProc>,
) -> AdviceSummaryMap {
    let mut summaries = AdviceSummaryMap::default();

    for node in callgraph.iter() {
        let Some(proc) = prepared.get(&node.name) else {
            summaries.insert(node.name.clone(), AdviceSummary::unknown());
            continue;
        };
        let summary = match proc.stmts.as_deref() {
            Some(stmts) => analyze_proc_provenance(proc.inputs, proc.outputs, stmts, &summaries),
            None => AdviceSummary::unknown_with_arity(proc.outputs),
        };
        summaries.insert(node.name.clone(), summary);
    }

    summaries
}

/// Merge diagnostics from one pass into the combined diagnostic map.
fn merge_diagnostics(combined: &mut AdviceDiagnosticsMap, next: AdviceDiagnosticsMap) {
    for (proc, mut proc_diags) in next {
        combined.entry(proc).or_default().append(&mut proc_diags);
    }
}
