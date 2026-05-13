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
    /// Procedure body prepared for analysis.
    body: PreparedProcBody,
}

/// Prepared body state for one procedure.
#[derive(Debug, Clone)]
enum PreparedProcBody {
    /// Lifted SSA statements for an analyzable procedure.
    Lifted(Vec<Stmt>),
    /// Procedure was unavailable or could not be lifted.
    Opaque,
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
        match &self.body {
            PreparedProcBody::Lifted(stmts) => Some(stmts),
            PreparedProcBody::Opaque => None,
        }
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
                lifted_procs.get(proc_path).and_then(PreparedProc::stmts)
            });

        Self {
            callgraph,
            signatures,
            type_summaries,
            lifted_procs,
        }
    }

    /// Inferred signature for one procedure path.
    pub(crate) fn signature(&self, proc_path: &SymbolPath) -> Option<&ProcSignature> {
        self.signatures.get(proc_path)
    }

    /// Prepared procedure data for a procedure path.
    pub(crate) fn proc(&self, proc_path: &SymbolPath) -> Option<&PreparedProc> {
        self.lifted_procs.get(proc_path)
    }

    /// Prepared procedure data for all procedures.
    pub(crate) fn procs(&self) -> impl Iterator<Item = (&SymbolPath, &PreparedProc)> {
        self.lifted_procs.iter()
    }

    /// Prepared procedures in bottom-up callgraph order.
    pub(crate) fn callgraph_procs(
        &self,
    ) -> impl Iterator<Item = (&SymbolPath, Option<&PreparedProc>)> {
        self.callgraph.iter().map(|node| {
            let proc_path = node.name();
            (proc_path, self.proc(proc_path))
        })
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
            prepared.insert(proc_path, PreparedProc::opaque(0, 0));
            continue;
        };

        let (inputs, outputs) = match signature {
            ProcSignature::Known { inputs, outputs, .. } => (*inputs, *outputs),
            ProcSignature::Unknown => {
                prepared.insert(proc_path, PreparedProc::opaque(0, 0));
                continue;
            },
        };

        let Some((program, proc)) = workspace.lookup_proc_entry(&proc_path) else {
            prepared.insert(proc_path, PreparedProc::opaque(inputs, outputs));
            continue;
        };

        let resolver = create_resolver(program.module(), workspace.source_manager());
        let stmts = match lift_proc(proc, &proc_path, &resolver, signatures) {
            Ok(stmts) => stmts,
            Err(_) => {
                prepared.insert(proc_path, PreparedProc::opaque(inputs, outputs));
                continue;
            },
        };
        prepared.insert(proc_path, PreparedProc::lifted(inputs, outputs, stmts));
    }

    prepared
}

impl PreparedProc {
    /// Construct an analyzable prepared procedure.
    fn lifted(inputs: usize, outputs: usize, stmts: Vec<Stmt>) -> Self {
        Self {
            inputs,
            outputs,
            body: PreparedProcBody::Lifted(stmts),
        }
    }

    /// Construct an opaque prepared procedure.
    fn opaque(inputs: usize, outputs: usize) -> Self {
        Self {
            inputs,
            outputs,
            body: PreparedProcBody::Opaque,
        }
    }
}
