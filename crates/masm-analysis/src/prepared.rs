//! Internal prepared state shared by MASM lint analyses.

use std::collections::HashMap;

use masm_decompiler::{
    CallGraph, ProcSignature, SignatureMap, Stmt, SymbolPath, TypeSummary, TypeSummaryMap,
    Workspace, create_resolver, infer_signatures, infer_type_summaries_from_lifted, lift_proc,
    refine_public_signature_inputs,
};

/// Prepared lifting result for one procedure.
#[derive(Debug, Clone)]
pub(crate) struct PreparedProc {
    /// Input arity inferred from the procedure signature.
    inputs: usize,
    /// Output arity inferred from the procedure signature.
    outputs: usize,
    /// Lifted SSA statements, when the procedure is analyzable.
    stmts: Option<Vec<Stmt>>,
}

impl PreparedProc {
    /// Input arity inferred from the procedure signature.
    pub(crate) fn inputs(&self) -> usize {
        self.inputs
    }

    /// Output arity inferred from the procedure signature.
    pub(crate) fn outputs(&self) -> usize {
        self.outputs
    }

    /// Lifted SSA statements, when the procedure is analyzable.
    pub(crate) fn stmts(&self) -> Option<&[Stmt]> {
        self.stmts.as_deref()
    }
}

/// Shared analysis products derived from a workspace.
#[derive(Debug)]
pub(crate) struct PreparedAnalysis {
    callgraph: CallGraph,
    signatures: SignatureMap,
    type_summaries: TypeSummaryMap,
    lifted_procs: HashMap<SymbolPath, PreparedProc>,
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

    /// Inferred procedure signatures keyed by fully qualified procedure path.
    pub(crate) fn signatures(&self) -> &SignatureMap {
        &self.signatures
    }

    /// Bottom-up callgraph used by interprocedural analyses.
    pub(crate) fn callgraph(&self) -> &CallGraph {
        &self.callgraph
    }

    /// Prepared procedure data for a procedure path.
    pub(crate) fn proc(&self, proc_path: &SymbolPath) -> Option<&PreparedProc> {
        self.lifted_procs.get(proc_path)
    }

    /// Prepared procedure data for all procedures.
    pub(crate) fn procs(&self) -> impl Iterator<Item = (&SymbolPath, &PreparedProc)> {
        self.lifted_procs.iter()
    }

    /// Type summary for one procedure path.
    pub(crate) fn type_summary(&self, proc_path: &SymbolPath) -> Option<&TypeSummary> {
        self.type_summaries.get(proc_path)
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
