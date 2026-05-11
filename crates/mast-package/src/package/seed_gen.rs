use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use std::{fs, path::Path, println};

use miden_assembly_syntax::{
    Library,
    ast::{
        AttributeSet, Path as AstPath, PathBuf,
        types::{CallConv, FunctionType, Type},
    },
    library::{LibraryExport, ProcedureExport as LibraryProcedureExport},
    semver::Version,
};
use miden_core::{
    advice::AdviceMap,
    mast::{
        BasicBlockNodeBuilder, DebugInfo, MastForest, MastForestParts, MastNodeBuilder,
        MastNodeExt, MastNodeId,
    },
    operations::Operation,
    serde::Serializable,
    utils::IndexVec,
};

use super::{PackageId, TargetType};
use crate::{Package, PackageExport, PackageManifest, ProcedureExport as PackageProcedureExport};

fn build_forest() -> (MastForest, MastNodeId) {
    let node_id = MastNodeId::new_unchecked(0);
    let node =
        MastNodeBuilder::BasicBlock(BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new()))
            .build_linked(node_id)
            .expect("failed to build basic block");
    let mut nodes = IndexVec::new();
    nodes.push(node).expect("failed to add MAST node");
    let forest = MastForest::from_parts(MastForestParts {
        nodes,
        roots: vec![node_id],
        advice_map: AdviceMap::default(),
        debug_info: DebugInfo::new(),
    })
    .expect("failed to build MAST forest");
    (forest, node_id)
}

fn absolute_path(name: &str) -> Arc<AstPath> {
    let path = PathBuf::new(name).expect("invalid path");
    let path = path.as_path().to_absolute().into_owned();
    Arc::from(path.into_boxed_path())
}

fn build_library(signature: Option<FunctionType>) -> Arc<Library> {
    let (forest, node_id) = build_forest();
    let path = absolute_path("test::proc");
    let mut export = LibraryProcedureExport::new(node_id, Arc::clone(&path));
    if let Some(signature) = signature {
        export = export.with_signature(signature);
    }

    let mut exports = BTreeMap::new();
    exports.insert(path, LibraryExport::Procedure(export));

    Arc::new(Library::new(Arc::new(forest), exports).expect("failed to build library"))
}

fn build_package(library: Arc<Library>, signature: Option<FunctionType>) -> Package {
    let path = absolute_path("test::proc");
    let node_id = library.get_export_node_id(path.as_ref());
    let digest = library.mast_forest()[node_id].digest();

    let export = PackageExport::Procedure(PackageProcedureExport {
        path: Arc::clone(&path),
        digest,
        signature,
        attributes: AttributeSet::default(),
    });

    let manifest = PackageManifest::new([export]).expect("seed package manifest should be valid");

    Package {
        name: PackageId::from("test_pkg"),
        version: Version::new(0, 0, 0),
        description: None,
        kind: TargetType::Library,
        mast: library,
        manifest,
        sections: Vec::new(),
    }
}

#[test]
#[ignore = "run manually to generate fuzz seeds"]
fn generate_fuzz_seeds() {
    fn write_seed(target: &str, name: &str, bytes: &[u8]) {
        let corpus_root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../miden-core-fuzz/corpus");
        let corpus_dir = corpus_root.join(target);
        fs::create_dir_all(&corpus_dir).expect("failed to create corpus directory");
        fs::write(corpus_dir.join(name), bytes).expect("failed to write seed");
        println!("Generated {}/{} ({} bytes)", target, name, bytes.len());
    }

    let library = build_library(None);
    write_seed("library_deserialize", "minimal_library.bin", &library.to_bytes());

    let signature = FunctionType::new(CallConv::Fast, [Type::Felt], [Type::Felt]);
    let library_with_signature = build_library(Some(signature.clone()));
    write_seed(
        "library_deserialize",
        "library_with_signature.bin",
        &library_with_signature.to_bytes(),
    );

    let package = build_package(Arc::clone(&library), None);
    write_seed("package_deserialize", "minimal_package.bin", &package.to_bytes());
    write_seed("package_semantic_deserialize", "minimal_package.bin", &package.to_bytes());

    let package_with_signature = build_package(library_with_signature, Some(signature));
    write_seed(
        "package_deserialize",
        "package_with_signature.bin",
        &package_with_signature.to_bytes(),
    );

    println!("\nSeed corpus generated in ../../miden-core-fuzz/corpus");
}
