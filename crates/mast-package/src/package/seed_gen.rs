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
use crate::{Package, PackageExport, ProcedureExport};

fn build_forest() -> (MastForest, MastNodeId) {
    let mut builder = DenseMastForestBuilder::new();
    let node_id = builder
        .push_node(BasicBlockNodeBuilder::new(vec![Operation::Add]))
        .expect("failed to build basic block");
    builder.mark_root(node_id);

    let (forest, remapping) = builder.finish_with_id_map().expect("failed to build forest");
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

    println!("\nSeed corpus generated in ../../miden-core-fuzz/corpus");
}
