use alloc::{sync::Arc, vec, vec::Vec};
use std::{fs, path::Path, println};

use miden_assembly_syntax::{
    ast::{
        Path as AstPath, PathBuf,
        types::{CallConv, FunctionType, Type},
    },
    semver::Version,
};
use miden_core::{
    mast::{BasicBlockNodeBuilder, DenseMastForestBuilder, MastForest, MastNodeExt, MastNodeId},
    operations::Operation,
    serde::Serializable,
};

use super::{PackageId, TargetType};
use crate::{
    Package, PackageExport, ProcedureExport, Section, SectionId,
    debug_info::{DebugSourceAsmOp, DebugSourceNode, PackageDebugInfoBuilder},
};

fn build_forest() -> (MastForest, MastNodeId) {
    let mut builder = DenseMastForestBuilder::new();
    let node_id = builder
        .push_node(BasicBlockNodeBuilder::new(vec![Operation::Add]))
        .expect("failed to build basic block");
    builder.mark_root(node_id);

    let (forest, remapping) = builder.build_with_id_map().expect("failed to build forest");
    let node_id = remapping.get(node_id).expect("root should be retained");
    (forest, node_id)
}

fn absolute_path(name: &str) -> Arc<AstPath> {
    let path = PathBuf::new(name).expect("invalid path");
    let path = path.as_path().to_absolute().unwrap().into_owned();
    Arc::from(path.into_boxed_path())
}

fn build_package_exports(signature: Option<FunctionType>) -> (Arc<MastForest>, Vec<PackageExport>) {
    let (forest, node_id) = build_forest();
    let root = forest[node_id].digest();
    let path = absolute_path("test::proc");
    let export = ProcedureExport::new(Arc::clone(&path), Some(node_id), root, signature);

    (Arc::new(forest), vec![PackageExport::Procedure(export)])
}

fn build_package(signature: Option<FunctionType>) -> Package {
    let (mast, exports) = build_package_exports(signature);
    Package::create(
        PackageId::from("test_pkg"),
        Version::new(0, 0, 0),
        TargetType::Library,
        mast,
        exports,
        None,
    )
    .expect("seed package should be valid")
}

fn build_package_with_debug_info() -> (Package, Vec<u8>) {
    let mut package = build_package(None);
    let exec_node = *package.mast.procedure_roots().first().expect("seed package has a root");

    let mut debug_info = PackageDebugInfoBuilder::default();
    let context_name = debug_info.add_string("seed::test");
    let op_name = debug_info.add_string("add");
    let source_node = debug_info
        .add_node(DebugSourceNode {
            exec_node,
            children: Vec::new(),
            op_start: 0,
            op_end: 1,
            asm_ops: vec![DebugSourceAsmOp::new(0, None, context_name, op_name, 1)],
            debug_vars: Vec::new(),
            inline_calls: Vec::new(),
        })
        .expect("seed debug info has one source node");
    debug_info.add_root(source_node);

    let debug_info_bytes = debug_info.build().to_bytes();
    package
        .sections
        .push(Section::new(SectionId::DEBUG_INFO, debug_info_bytes.clone()));

    (package, debug_info_bytes)
}

#[test]
#[ignore = "run manually to generate fuzz seeds"]
fn generate_fuzz_seeds() {
    fn write_seed(target: &str, name: &str, bytes: &[u8]) {
        let corpus_root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/miden-core-fuzz/corpus");
        let corpus_dir = corpus_root.join(target);
        fs::create_dir_all(&corpus_dir).expect("failed to create corpus directory");
        fs::write(corpus_dir.join(name), bytes).expect("failed to write seed");
        println!("Generated {}/{} ({} bytes)", target, name, bytes.len());
    }

    let package = build_package(None);
    write_seed("package_deserialize", "minimal_package.bin", &package.to_bytes());
    write_seed("package_semantic_deserialize", "minimal_package.bin", &package.to_bytes());

    let signature = FunctionType::new(CallConv::Fast, [Type::Felt], [Type::Felt]);
    let package_with_signature = build_package(Some(signature));
    write_seed(
        "package_deserialize",
        "package_with_signature.bin",
        &package_with_signature.to_bytes(),
    );

    let (package_with_debug_info, debug_info_bytes) = build_package_with_debug_info();
    write_seed("debug_info", "valid_debug_info.bin", &debug_info_bytes);
    write_seed("debug_info", "package_with_debug_info.bin", &package_with_debug_info.to_bytes());
    write_seed(
        "package_deserialize",
        "package_with_debug_info.bin",
        &package_with_debug_info.to_bytes(),
    );
    write_seed(
        "package_semantic_deserialize",
        "package_with_debug_info.bin",
        &package_with_debug_info.to_bytes(),
    );

    println!("\nSeed corpus generated in ../../tools/miden-core-fuzz/corpus");
}
