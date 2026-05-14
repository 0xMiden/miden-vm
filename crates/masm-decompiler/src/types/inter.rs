//! Interprocedural type-summary inference.

use super::{
    declared_summary_for_proc_with_arity,
    intra::analyze_proc_types,
    stdlib,
    summary::{TypeSummary, TypeSummaryMap},
};
use crate::{
    callgraph::CallGraph,
    frontend::{Program, Workspace},
    ir::Stmt,
    signature::{ProcSignature, SignatureMap},
    symbol::path::SymbolPath,
};

/// Infer type summaries using procedures that have already been lifted.
///
/// Procedures are processed in callgraph bottom-up order. Unknown signatures or
/// missing lifted bodies produce opaque summaries.
pub fn infer_type_summaries_from_lifted<'a>(
    workspace: &Workspace,
    callgraph: &CallGraph,
    signatures: &SignatureMap,
    mut lifted_body: impl FnMut(&SymbolPath) -> Option<&'a [Stmt]>,
) -> TypeSummaryMap {
    let mut summaries = TypeSummaryMap::default();

    for node in callgraph.iter() {
        let proc_path = node.name();
        let summary = infer_summary_for_lifted_node(
            workspace,
            proc_path,
            signatures,
            &summaries,
            &mut lifted_body,
        );
        summaries.insert(proc_path.clone(), summary);
    }

    summaries
}

/// Infer a summary for one already-lifted procedure.
fn infer_summary_for_lifted_node<'a>(
    workspace: &Workspace,
    proc_path: &SymbolPath,
    signatures: &SignatureMap,
    callee_summaries: &TypeSummaryMap,
    lifted_body: &mut impl FnMut(&SymbolPath) -> Option<&'a [Stmt]>,
) -> TypeSummary {
    let Some(signature) = signatures.get(proc_path) else {
        return TypeSummary::opaque();
    };

    let (inputs, outputs) = match signature {
        ProcSignature::Known { public_inputs, outputs, .. } => (*public_inputs, *outputs),
        ProcSignature::Unknown => return TypeSummary::opaque(),
    };

    let Some((program, proc)) = workspace.lookup_proc_entry(proc_path) else {
        return TypeSummary::opaque_with_arity(inputs, outputs);
    };
    let declared_summary = declared_summary_for_proc_with_arity(program, proc, inputs, outputs);
    let Some(stmts) = lifted_body(proc_path) else {
        return declared_summary.unwrap_or_else(|| TypeSummary::opaque_with_arity(inputs, outputs));
    };

    infer_summary_from_stmts(
        workspace,
        program,
        proc_path,
        inputs,
        outputs,
        stmts,
        callee_summaries,
        declared_summary,
    )
}

/// Infer and refine a summary from a lifted procedure body.
fn infer_summary_from_stmts(
    workspace: &Workspace,
    program: &Program,
    proc_path: &SymbolPath,
    inputs: usize,
    outputs: usize,
    stmts: &[Stmt],
    callee_summaries: &TypeSummaryMap,
    declared_summary: Option<TypeSummary>,
) -> TypeSummary {
    let analysis = analyze_proc_types(inputs, outputs, stmts, callee_summaries);
    let raw_outputs = analysis.outputs.clone();
    let summary = stdlib::refine_known_outputs(workspace, program, proc_path, analysis);
    let summary = stdlib::refine_declared_inputs_when_outputs_exact(
        workspace,
        program,
        proc_path,
        summary,
        &raw_outputs,
        declared_summary.as_ref(),
    );
    stdlib::refine_known_inputs(workspace, program, proc_path, summary, declared_summary.as_ref())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, path::PathBuf, sync::Arc};

    use miden_assembly_syntax::debuginfo::{DefaultSourceManager, SourceManager};

    use super::*;
    use crate::{
        frontend::LibraryRoot,
        lift::lift_proc,
        signature::{infer_signatures, refine_public_signature_inputs},
        symbol::resolution::create_resolver,
        types::{InferredType, TypeRequirement},
    };

    fn temp_dir(test_name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("masm_decompiler_types_{test_name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp module dir");
        dir
    }

    fn summaries_for_source(test_name: &str, source: &str) -> TypeSummaryMap {
        let dir = temp_dir(test_name);
        let module_path = dir.join("test.masm");
        fs::write(&module_path, source).expect("write MASM module");

        let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
        let mut workspace =
            Workspace::with_source_manager(vec![LibraryRoot::new("", dir.clone())], source_manager);
        workspace.load_entry(&module_path).expect("load test module");
        workspace.load_dependencies();
        assert!(workspace.unresolved_module_paths().is_empty());

        let callgraph = CallGraph::from(&workspace);
        let mut signatures = infer_signatures(&workspace, &callgraph);
        refine_public_signature_inputs(&workspace, &mut signatures);

        let mut lifted = HashMap::new();
        for node in callgraph.iter() {
            let Some((program, proc)) = workspace.lookup_proc_entry(node.name()) else {
                continue;
            };
            let resolver = create_resolver(program.module(), workspace.source_manager());
            let stmts = lift_proc(proc, node.name(), &resolver, &signatures)
                .expect("test procedure should lift");
            lifted.insert(node.name().clone(), stmts);
        }

        let summaries =
            infer_type_summaries_from_lifted(&workspace, &callgraph, &signatures, |proc_path| {
                lifted.get(proc_path).map(Vec::as_slice)
            });

        fs::remove_dir_all(dir).expect("remove temp module dir");
        summaries
    }

    fn summary_by_name<'a>(summaries: &'a TypeSummaryMap, name: &str) -> &'a TypeSummary {
        summaries
            .iter()
            .find_map(|(path, summary)| (path.name() == name).then_some(summary))
            .expect("summary should exist")
    }

    #[test]
    fn type_summaries_track_passthrough_outputs_and_u32_requirements() {
        let summaries = summaries_for_source(
            "passthrough_and_u32",
            "\
pub proc passthrough(x: felt) -> felt
    dup.0
    drop
end

pub proc add_u32(x: felt, y: felt) -> felt
    u32wrapping_add
end
",
        );

        let passthrough = summary_by_name(&summaries, "passthrough");
        assert_eq!(passthrough.inputs, vec![TypeRequirement::Felt]);
        assert_eq!(passthrough.outputs, vec![InferredType::Felt]);
        assert_eq!(passthrough.output_input_map, vec![Some(0)]);

        let add_u32 = summary_by_name(&summaries, "add_u32");
        assert_eq!(add_u32.inputs, vec![TypeRequirement::U32, TypeRequirement::U32]);
        assert_eq!(add_u32.outputs, vec![InferredType::U32]);
        assert_eq!(add_u32.output_input_map, vec![None]);
    }

    #[test]
    fn type_summaries_propagate_requirements_through_local_slots() {
        let summaries = summaries_for_source(
            "local_slot_requirements",
            "\
@locals(1)
pub proc local_required_by_u32(x: felt) -> felt
    loc_store.0
    loc_load.0
    push.1
    u32wrapping_add
end
",
        );

        let summary = summary_by_name(&summaries, "local_required_by_u32");
        assert_eq!(summary.inputs, vec![TypeRequirement::U32]);
        assert_eq!(summary.outputs, vec![InferredType::U32]);
        assert_eq!(summary.output_input_map, vec![None]);
    }

    #[test]
    fn type_summaries_propagate_requirements_through_memory_slots() {
        let summaries = summaries_for_source(
            "memory_slot_requirements",
            "\
pub proc memory_required_by_u32(x: felt) -> felt
    push.0
    mem_store
    push.0
    mem_load
    push.1
    u32wrapping_add
end
",
        );

        let summary = summary_by_name(&summaries, "memory_required_by_u32");
        assert_eq!(summary.inputs, vec![TypeRequirement::U32]);
        assert_eq!(summary.outputs, vec![InferredType::U32]);
        assert_eq!(summary.output_input_map, vec![None]);
    }

    #[test]
    fn type_summaries_propagate_requirements_through_selectors() {
        let summaries = summaries_for_source(
            "selector_requirements",
            "\
pub proc selector_required_by_u32(x: felt, flag: felt) -> felt
    push.1
    swap.1
    cdrop
    push.1
    u32wrapping_add
end
",
        );

        let summary = summary_by_name(&summaries, "selector_required_by_u32");
        assert_eq!(summary.inputs, vec![TypeRequirement::Bool, TypeRequirement::U32]);
        assert_eq!(summary.outputs, vec![InferredType::U32]);
        assert_eq!(summary.output_input_map, vec![None]);
    }
}
