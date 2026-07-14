use alloc::{
    boxed::Box,
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};
use core::{assert_matches, fmt::Write, str::FromStr};
use std::{eprintln, sync::Arc};

use miden_assembly_syntax::{
    MAX_REPEAT_COUNT,
    ast::{Ident, Path},
    diagnostics::WrapErr,
};
use miden_core::{
    Felt, Word,
    events::EventId,
    field::PrimeField64,
    mast::{MastNode, MastNodeExt},
    operations::{AssemblyOp, Operation},
    program::Program,
    serde::{Deserializable, Serializable},
};
use miden_mast_package::{
    MastForest, Package, PackageExport, PackageModule, PackageSubmodule, ProcedureExport,
    TargetType,
};
use miden_project::Linkage;

use crate::{
    Assembler, PathBuf,
    assembler::{MAX_CONTROL_FLOW_NESTING, MAX_PROC_LOCALS},
    ast::{Module, ProcedureName, QualifiedProcedureName},
    diagnostics::{IntoDiagnostic, Report},
    fmp::fmp_initialization_sequence,
    mast_forest_builder::MastForestBuilder,
    report,
    testing::{
        TestContext, assert_diagnostic, assert_diagnostic_lines, parse_module, regex, source_file,
    },
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
    let has_source_asm_ops = debug_info
        .source_map()
        .is_some_and(|source_map| !source_map.asm_ops().is_empty());
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
mod dynamic_code_blocks;
mod emit_event;
mod errors;
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
