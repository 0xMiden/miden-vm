//! Internal prepared state shared by MASM lint analyses.

use std::collections::HashMap;

use masm_decompiler::{
    CallGraph, ProcSignature, SignatureMap, Stmt, SymbolPath, TypeSummaryMap, Workspace,
    create_resolver, infer_signatures, infer_type_summaries_from_lifted, lift_proc,
    refine_public_signature_inputs,
};

/// Prepared lifting result for one procedure.
#[derive(Debug, Clone)]
pub(crate) struct PreparedProc {
    /// Input arity inferred from the procedure signature.
    pub(crate) inputs: usize,
    /// Output arity inferred from the procedure signature.
    pub(crate) outputs: usize,
    /// Lifted SSA statements, when the procedure is analyzable.
    pub(crate) stmts: Option<Vec<Stmt>>,
}

/// Shared analysis products derived from a workspace.
#[derive(Debug)]
pub(crate) struct PreparedAnalysis {
    pub(crate) callgraph: CallGraph,
    pub(crate) signatures: SignatureMap,
    pub(crate) type_summaries: TypeSummaryMap,
    pub(crate) lifted_procs: HashMap<SymbolPath, PreparedProc>,
}

impl PreparedAnalysis {
    /// Run the common analysis setup for a workspace.
    pub(crate) fn new(workspace: &Workspace) -> Self {
        let callgraph = CallGraph::from(workspace);
        let mut signatures = infer_signatures(workspace, &callgraph);
        refine_public_signature_inputs(workspace, &mut signatures);
        let lifted_procs = prepare_procs(workspace, &callgraph, &signatures);
        let type_summaries =
            infer_type_summaries_from_lifted(workspace, &callgraph, &signatures, |proc_path| {
                lifted_procs.get(proc_path).and_then(|proc| proc.stmts.as_deref())
            });

        Self {
            callgraph,
            signatures,
            type_summaries,
            lifted_procs,
        }
    }
}

/// Prepare and lift all procedures once for downstream analyses.
fn prepare_procs(
    workspace: &Workspace,
    callgraph: &CallGraph,
    signatures: &SignatureMap,
) -> HashMap<SymbolPath, PreparedProc> {
    let mut prepared = HashMap::new();

    for node in callgraph.iter() {
        let proc_path = node.name().clone();
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
