use alloc::{sync::Arc, vec, vec::Vec};
use std::{fs, path::Path, println};

use miden_assembly_syntax::{
    ast::{
        Path as AstPath, PathBuf,
        types::{CallConv, EnumType, FunctionType, StructType, Type, TypeRepr, Variant},
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

fn build_package_with_debug_info(signature: Option<FunctionType>) -> (Package, Vec<u8>) {
    let mut package = build_package(signature);
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
    debug_info.add_error_message(0x0123_4567_89ab_cdef, Arc::from("seed error"));

    let debug_info_bytes = debug_info.build().to_bytes();
    package
        .sections
        .push(Section::new(SectionId::DEBUG_INFO, debug_info_bytes.clone()));

    (package, debug_info_bytes)
}

fn build_packages_with_invalid_struct_types() -> Vec<(&'static str, Vec<u8>)> {
    let struct_type = StructType::new_with_repr(TypeRepr::align(8), [Type::Felt]);
    let signature = FunctionType::new(CallConv::Fast, [Type::from(struct_type)], []);
    let signature_bytes = signature.to_bytes();
    let (package, _) = build_package_with_debug_info(Some(signature));
    let package_bytes = package.to_bytes();

    let signature_offset = package_bytes
        .windows(signature_bytes.len())
        .position(|window| window == signature_bytes)
        .expect("seed package should contain its procedure signature");
    let repr_offset = signature_bytes
        .windows(5)
        .position(|window| window == [17, 0, 1, 8, 0])
        .expect("seed signature should contain the aligned struct type");
    let repr_offset = signature_offset + repr_offset + 2;
    let field_type_offset = signature_offset
        + signature_bytes
            .windows(8)
            .position(|window| window == [17, 0, 1, 8, 0, 1, 0, 15])
            .expect("seed signature should contain the struct field type")
        + 7;

    let mut non_power_of_two = package_bytes.clone();
    non_power_of_two[repr_offset + 1..repr_offset + 3].copy_from_slice(&3u16.to_le_bytes());

    let mut zero_packed = package_bytes.clone();
    zero_packed[repr_offset] = 2;
    zero_packed[repr_offset + 1..repr_offset + 3].copy_from_slice(&0u16.to_le_bytes());

    let mut list_field = package_bytes;
    list_field[field_type_offset] = 19;
    list_field.insert(field_type_offset + 1, 15);

    let mut packages = vec![
        ("non_power_of_two_struct_align.bin", non_power_of_two),
        ("zero_packed_struct_align.bin", zero_packed),
        ("list_struct_field.bin", list_field),
    ];

    let enum_type =
        EnumType::new(Arc::from("E"), Type::U8, [Variant::new(Arc::from("V"), Type::Felt, None)])
            .expect("seed enum should be valid");
    let signature = FunctionType::new(CallConv::Fast, [Type::Enum(Arc::new(enum_type))], []);
    let signature_bytes = signature.to_bytes();
    let (package, _) = build_package_with_debug_info(Some(signature));
    let mut package_bytes = package.to_bytes();
    let signature_offset = package_bytes
        .windows(signature_bytes.len())
        .position(|window| window == signature_bytes)
        .expect("seed package should contain its enum procedure signature");
    let variant_type_offset = signature_offset
        + signature_bytes
            .windows(4)
            .position(|window| window == [b'V', 1, 15, 0])
            .expect("seed signature should contain the enum variant type")
        + 2;
    package_bytes[variant_type_offset] = 19;
    package_bytes.insert(variant_type_offset + 1, 15);
    packages.push(("list_enum_variant.bin", package_bytes));

    packages
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

    let (package_with_debug_info, debug_info_bytes) = build_package_with_debug_info(None);
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

    let mut dangling_error_debug_info = debug_info_bytes;
    let error_code = 0x0123_4567_89ab_cdef_u64.to_le_bytes();
    let error_message_offset = dangling_error_debug_info
        .windows(error_code.len())
        .position(|window| window == error_code)
        .expect("seed debug info should contain its error code")
        + error_code.len();
    dangling_error_debug_info[error_message_offset..error_message_offset + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    write_seed("debug_info", "dangling_error_message_string.bin", &dangling_error_debug_info);

    let mut dangling_error_package = package_with_debug_info.to_bytes();
    let error_message_offset = dangling_error_package
        .windows(error_code.len())
        .position(|window| window == error_code)
        .expect("seed package should contain its debug error code")
        + error_code.len();
    dangling_error_package[error_message_offset..error_message_offset + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    write_seed(
        "debug_info",
        "package_with_dangling_error_message_string.bin",
        &dangling_error_package,
    );
    write_seed(
        "package_deserialize",
        "package_with_dangling_error_message_string.bin",
        &dangling_error_package,
    );
    write_seed(
        "package_semantic_deserialize",
        "package_with_dangling_error_message_string.bin",
        &dangling_error_package,
    );

    for (name, bytes) in build_packages_with_invalid_struct_types() {
        write_seed("debug_info", name, &bytes);
        write_seed("package_deserialize", name, &bytes);
        write_seed("package_semantic_deserialize", name, &bytes);
    }

    println!("\nSeed corpus generated in ../../tools/miden-core-fuzz/corpus");
}
