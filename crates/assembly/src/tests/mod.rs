use {
    alloc::boxed::Box,
    alloc::collections::BTreeSet,
    alloc::string::String,
    alloc::string::ToString,
    alloc::vec::Vec,
};
use {
    core::assert_matches,
    core::fmt::Write,
    core::str::FromStr,
};
use {
    std::eprintln,
    std::sync::Arc,
};

use {
    miden_assembly_syntax::MAX_CONTROL_FLOW_NESTING,
    miden_assembly_syntax::MAX_REPEAT_COUNT,
    crate::ast::Ident,
    crate::Path,
    crate::diagnostics::WrapErr,
};
use {
    miden_core::Felt,
    miden_core::Word,
    miden_core::events::EventId,
    miden_core::field::PrimeField64,
    crate::mast::MastNode,
    crate::mast::MastNodeExt,
    miden_core::operations::AssemblyOp,
    miden_core::operations::Operation,
    miden_core::program::Program,
    crate::serde::Deserializable,
    crate::serde::Serializable,
};
use {
    crate::mast::MastForest,
    crate::package::Package,
    crate::package::PackageExport,
    crate::package::PackageModule,
    crate::package::PackageSubmodule,
    crate::package::ProcedureExport,
    crate::package::TargetType,
};
use miden_project::Linkage;

use {
    crate::Assembler,
    crate::PathBuf,
    crate::debuginfo::SourceSpan,
    crate::debuginfo::Span,
    crate::assembler::MAX_PROC_LOCALS,
    crate::ast::Block,
    crate::ast::Instruction,
    crate::ast::Module,
    crate::ast::Op,
    crate::ast::Procedure,
    crate::ast::ProcedureName,
    crate::ast::QualifiedProcedureName,
    crate::ast::Visibility,
    crate::diagnostics::IntoDiagnostic,
    crate::diagnostics::Report,
    crate::fmp::fmp_initialization_sequence,
    crate::mast_forest_builder::MastForestBuilder,
    crate::diagnostics::report,
    crate::testing::TestContext,
    crate::testing::assert_diagnostic,
    crate::testing::assert_diagnostic_lines,
    crate::testing::parse_module,
    crate::testing::regex,
    crate::testing::source_file,
};

type TestResult = Result<(), Report>;

fn assert_all_nodes_reachable_from_roots(forest: &MastForest) {
    let mut reachable = BTreeSet::new();
    let mut worklist = forest.procedure_roots().to_vec();

    while let Some(node_id) = worklist.pop() {
        if reachable.insert(node_id) {
            forest[node_id].append_children_to(&mut worklist);
        }
    }

    assert_eq!(
        reachable.len(),
        forest.num_nodes() as usize,
        "finalized MAST forest contains nodes unreachable from any procedure root",
    );
}

fn assert_package_has_source_asm_ops(package: &Package, message: &str) {
    let debug_info = package
        .debug_info()
        .expect("package debug info should decode")
        .expect("package should contain debug info");
    let has_source_asm_ops = debug_info.nodes().iter().any(|node| !node.asm_ops.is_empty());
    assert!(has_source_asm_ops, "{message}");
}

mod package;

// Note: where possible, prefer insta to pretty_assertions for snapshot testing.
//
// - For tests against expected values that can't be expressed as a string literal, we still use
//   pretty-assertions' assert_eq for backward compatibility.
// - For new tests using string literals, or when you need auto-updating snapshots, use [insta](https://insta.rs/):
//
// Example:
// insta::assert_snapshot!(actual_output)
//
// To update snapshots on a per-test basis automatically:
// cargo insta review (after `cargo install cargo-insta`)

macro_rules! assert_assembler_diagnostic {
    ($context:ident, $source:expr, $($expected:literal),+) => {{
        let error = $context
            .assemble($source)
            .expect_err("expected diagnostic to be raised, but compilation succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};

    ($context:ident, $source:expr, $($expected:expr),+) => {{
        let error = $context
            .assemble($source)
            .expect_err("expected diagnostic to be raised, but compilation succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};
}

mod assertions;
mod comments;
mod compiled_libraries;
mod constants;
mod cross_module_constants;
mod cycle_costs;
mod debug_info;
mod dynamic_code_blocks;
mod errors;
mod event_syntax;
mod forest_merge;
mod import_regressions;
mod imports;
mod kernels;
mod libraries;
mod link_cycles;
mod link_diagnostics;
mod link_expansion;
mod linking_imports;
mod main_call;
mod mast;
mod mast_builder_corpus;
mod mast_root_calls;
mod misc_regressions;
mod nested_control_blocks;
mod num_locals;
mod package_surface;
mod procedures;
mod procref;
mod serialization;
mod simple_programs;
mod symbol_resolution;
mod type_resolution;
