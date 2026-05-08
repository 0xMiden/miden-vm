//! Interprocedural analysis for unconstrained advice reaching U32 and non-zero sinks.

mod address;
mod domain;
mod grouping;
mod inter;
mod merkle;
mod nonzero;
mod provenance;
mod shared;
mod summary;
mod u32;
mod u32_domain;
mod walker;

pub use grouping::{AdviceRootCauseGroup, group_advice_diagnostics_by_origin};
use masm_decompiler::{CallGraph, SignatureMap, TypeSummaryMap, Workspace};
pub use summary::AdviceDiagnostic;
use summary::AdviceDiagnosticsMap;

pub(super) fn infer_unconstrained_advice(
    workspace: &Workspace,
    callgraph: &CallGraph,
    signatures: &SignatureMap,
    type_summaries: &TypeSummaryMap,
) -> AdviceDiagnosticsMap {
    inter::infer_unconstrained_advice(workspace, callgraph, signatures, type_summaries).1
}
