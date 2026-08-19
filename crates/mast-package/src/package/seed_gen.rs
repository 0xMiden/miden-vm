use alloc::{string::ToString, sync::Arc, vec, vec::Vec};
use std::{fs, path::Path, println};

use miden_assembly_syntax::{
    ast::{
        DebugVarLocation, Path as AstPath, PathBuf,
        types::{ArrayType, CallConv, EnumType, FunctionType, StructType, Type, TypeRepr, Variant},
    },
    semver::Version,
};
use miden_core::{
    mast::{BasicBlockNodeBuilder, DenseMastForestBuilder, MastForest, MastNodeExt, MastNodeId},
    operations::Operation,
    serde::{ByteReader, ByteWriter, Deserializable, Serializable, SliceReader},
};
use miden_debug_types::{ByteIndex, Uri};
use zerocopy::IntoBytes;

use super::{PackageId, TargetType};
use crate::{
    Package, PackageExport, ProcedureExport, Section, SectionId,
    debug_info::{
        DebugSourceAsmOp, DebugSourceNode, DebugSourceVar, DebugTypeInfo,
        MAX_DEBUG_INFO_STRING_ROWS, MAX_DEBUG_INFO_STRING_SIZE, MAX_DEBUG_INFO_TYPE_ROWS,
        PackageDebugInfo, PackageDebugInfoBuilder,
    },
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

fn build_package_with_debug_info(
    signature: Option<FunctionType>,
) -> (Package, Vec<u8>, DebugSourceAsmOp, DebugSourceVar) {
    build_package_with_debug_options(signature, Arc::from("seed error"), 1)
}

fn build_package_with_debug_options(
    signature: Option<FunctionType>,
    error_message: Arc<str>,
    asm_op_repetitions: usize,
) -> (Package, Vec<u8>, DebugSourceAsmOp, DebugSourceVar) {
    let mut package = build_package(signature);
    let exec_node = *package.mast.procedure_roots().first().expect("seed package has a root");

    let mut debug_info = PackageDebugInfoBuilder::default();
    let context_name = debug_info.add_string("seed::test");
    let op_name = debug_info.add_string("add");
    let var_name = debug_info.add_string("seed_var");
    let file_idx = debug_info.add_file(Uri::new("file:///seed/source.masm"), Some([0xa5; 32]));
    let location_idx = debug_info.add_location_info(crate::debug_info::DebugLoc {
        file_idx,
        start: ByteIndex::new(0),
        end: ByteIndex::new(1),
    });
    let asm_op = DebugSourceAsmOp::new(0, Some(location_idx), context_name, op_name, 1);
    let debug_var = DebugSourceVar {
        op_idx: 0,
        name_idx: var_name,
        type_id: None,
        arg_idx: None,
        location_idx: Some(location_idx),
        value_location: DebugVarLocation::Stack(0),
    };
    let source_node = debug_info
        .add_node(DebugSourceNode {
            exec_node,
            children: Vec::new(),
            op_start: 0,
            op_end: 1,
            asm_ops: vec![asm_op; asm_op_repetitions],
            debug_vars: vec![debug_var.clone()],
            inline_calls: Vec::new(),
        })
        .expect("seed debug info has one source node");
    debug_info.add_root(source_node);
    debug_info.add_error_message(0x0123_4567_89ab_cdef, error_message);

    let debug_info_bytes = debug_info.build().to_bytes();
    package
        .sections
        .push(Section::new(SectionId::DEBUG_INFO, debug_info_bytes.clone()));

    (package, debug_info_bytes, asm_op, debug_var)
}

fn build_packages_with_invalid_struct_types() -> Vec<(&'static str, Vec<u8>)> {
    let struct_type = StructType::new_with_repr(TypeRepr::align(8), [Type::Felt]);
    let signature = FunctionType::new(CallConv::Fast, [Type::from(struct_type)], []);
    let signature_bytes = signature.to_bytes();
    let (package, ..) = build_package_with_debug_info(Some(signature));
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
    let (package, ..) = build_package_with_debug_info(Some(signature));
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

    let struct_type = StructType::new([Type::Felt, Type::Felt]);
    let signature = FunctionType::new(CallConv::Fast, [Type::from(struct_type)], []);
    let signature_bytes = signature.to_bytes();
    let (package, ..) = build_package_with_debug_info(Some(signature));
    let mut package_bytes = package.to_bytes();
    let signature_offset = package_bytes
        .windows(signature_bytes.len())
        .position(|window| window == signature_bytes)
        .expect("seed package should contain its two-field struct signature");
    let repr_offset = signature_bytes
        .windows(8)
        .position(|window| window == [17, 0, 0, 2, 0, 15, 0, 15])
        .expect("seed signature should contain its default two-field struct")
        + 2;
    package_bytes[signature_offset + repr_offset] = 3;
    packages.push(("multi_field_transparent_struct.bin", package_bytes));

    let struct_type = StructType::new([Type::from(ArrayType::new(Type::Felt, 1))]);
    let signature = FunctionType::new(CallConv::Fast, [Type::from(struct_type)], []);
    let signature_bytes = signature.to_bytes();
    let (package, ..) = build_package_with_debug_info(Some(signature));
    let mut package_bytes = package.to_bytes();
    let signature_offset = package_bytes
        .windows(signature_bytes.len())
        .position(|window| window == signature_bytes)
        .expect("seed package should contain its array-field struct signature");
    let array_len_offset = signature_bytes
        .windows(3)
        .position(|window| window == [18, 3, 15])
        .expect("seed signature should contain its single-Felt array")
        + 1;
    let mut overflowing_package_bytes = package_bytes.clone();
    package_bytes.splice(
        signature_offset + array_len_offset..signature_offset + array_len_offset + 1,
        (u32::MAX as usize).to_bytes(),
    );
    packages.push(("oversized_struct_field.bin", package_bytes));
    overflowing_package_bytes.splice(
        signature_offset + array_len_offset..signature_offset + array_len_offset + 1,
        usize::MAX.to_bytes(),
    );
    packages.push(("overflowing_struct_field.bin", overflowing_package_bytes));

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

    let (package_with_debug_info, debug_info_bytes, asm_op, debug_var) =
        build_package_with_debug_info(None);
    write_seed("debug_info", "valid_debug_info.bin", &debug_info_bytes);
    let empty_debug_info = PackageDebugInfoBuilder::default().build().to_bytes();
    let mut empty_reader = SliceReader::new(&empty_debug_info);
    assert_eq!(empty_reader.read_u8().unwrap(), crate::debug_info::DEBUG_INFO_VERSION);
    let empty_payload_len = empty_reader.read_usize().unwrap();
    let empty_payload_offset = 1 + empty_payload_len.to_bytes().len();
    let debug_info_with_empty_strings = |rows: usize| {
        let mut payload = empty_debug_info[empty_payload_offset..].to_vec();
        let encoded_rows = rows.to_bytes();
        payload.splice(0..1, encoded_rows.iter().copied());
        payload.splice(encoded_rows.len()..encoded_rows.len(), 0usize.to_bytes().repeat(rows));

        let mut encoded = Vec::new();
        encoded.write_u8(crate::debug_info::DEBUG_INFO_VERSION);
        encoded.write_usize(payload.len());
        encoded.write_bytes(&payload);
        encoded
    };
    let mut max_string_table = PackageDebugInfoBuilder::default();
    for index in 0..MAX_DEBUG_INFO_STRING_ROWS {
        max_string_table.add_string(index.to_string());
    }
    let max_string_table = max_string_table.build().to_bytes();
    let decoded = PackageDebugInfo::read_from_bytes(&max_string_table).unwrap();
    assert_eq!(decoded.strings().len(), MAX_DEBUG_INFO_STRING_ROWS);
    write_seed("debug_info", "max_debug_string_table.bin", &max_string_table);
    let oversized_string_table = debug_info_with_empty_strings(MAX_DEBUG_INFO_STRING_ROWS + 1);
    assert!(PackageDebugInfo::read_from_bytes(&oversized_string_table).is_err());
    write_seed("debug_info", "oversized_debug_string_table.bin", &oversized_string_table);
    let mut max_sized_string = PackageDebugInfoBuilder::default();
    max_sized_string.add_string("x".repeat(MAX_DEBUG_INFO_STRING_SIZE));
    let max_sized_string = max_sized_string.build().to_bytes();
    let decoded = PackageDebugInfo::read_from_bytes(&max_sized_string).unwrap();
    assert_eq!(decoded.strings().iter().next().unwrap().len(), MAX_DEBUG_INFO_STRING_SIZE);
    write_seed("debug_info", "max_sized_debug_string.bin", &max_sized_string);
    let mut oversized_debug_info = PackageDebugInfoBuilder::default();
    oversized_debug_info.add_string("x".repeat(MAX_DEBUG_INFO_STRING_SIZE + 1));
    let oversized_debug_info = oversized_debug_info.build().to_bytes();
    assert!(PackageDebugInfo::read_from_bytes(&oversized_debug_info).is_err());
    write_seed("debug_info", "oversized_debug_info.bin", &oversized_debug_info);
    let mut boundary_type_table = PackageDebugInfoBuilder::default();
    for _ in 0..MAX_DEBUG_INFO_TYPE_ROWS {
        boundary_type_table.push_type(DebugTypeInfo::Unknown);
    }
    let max_type_table = boundary_type_table.debug_info().to_bytes();
    let decoded = PackageDebugInfo::read_from_bytes(&max_type_table).unwrap();
    assert_eq!(decoded.types().len(), MAX_DEBUG_INFO_TYPE_ROWS);
    write_seed("debug_info", "max_debug_type_table.bin", &max_type_table);
    boundary_type_table.push_type(DebugTypeInfo::Unknown);
    let oversized_type_table = boundary_type_table.build().to_bytes();
    assert!(PackageDebugInfo::read_from_bytes(&oversized_type_table).is_err());
    write_seed("debug_info", "oversized_debug_type_table.bin", &oversized_type_table);
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

    let mut kernel_with_debug_info = package_with_debug_info.clone();
    kernel_with_debug_info.name = PackageId::from("seed_kernel");
    kernel_with_debug_info.kind = TargetType::Kernel;
    let kernel_dependency = kernel_with_debug_info.to_dependency();
    let mut package_with_nested_debug_info = build_package(None);
    package_with_nested_debug_info
        .manifest
        .add_dependency(kernel_dependency.clone())
        .expect("seed package should accept its kernel dependency");
    package_with_nested_debug_info
        .sections
        .push(Section::new(SectionId::KERNEL, kernel_with_debug_info.to_bytes()));
    let nested_package_bytes = package_with_nested_debug_info.to_bytes();
    let admitted_nested_package = Package::read_from_bytes(&nested_package_bytes)
        .expect("valid nested debug seed should pass outer admission");
    let admitted_kernel = admitted_nested_package
        .try_embedded_kernel_package()
        .expect("valid nested debug seed should pass kernel extraction")
        .expect("valid nested debug seed should contain a kernel");
    assert_eq!(
        admitted_kernel.debug_info().unwrap(),
        kernel_with_debug_info.debug_info().unwrap()
    );
    write_seed(
        "package_semantic_deserialize",
        "package_with_nested_debug_info.bin",
        &nested_package_bytes,
    );

    let file_checksum = [0xa5; 32];
    let location_pattern = [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];
    let mut inverted_location_package = package_with_debug_info.to_bytes();
    let checksum_offset = inverted_location_package
        .windows(file_checksum.len())
        .position(|window| window == file_checksum)
        .expect("seed package should contain its debug file checksum");
    let location_offset = checksum_offset
        + file_checksum.len()
        + inverted_location_package[checksum_offset + file_checksum.len()..]
            .windows(location_pattern.len())
            .position(|window| window == location_pattern)
            .expect("seed package should contain its debug location");
    inverted_location_package[location_offset + 4..location_offset + 8]
        .copy_from_slice(&2u32.to_le_bytes());
    write_seed("debug_info", "package_with_inverted_location.bin", &inverted_location_package);

    let mut control_character_package = package_with_debug_info.to_bytes();
    let error_message_offset = control_character_package
        .windows(b"seed error".len())
        .position(|window| window == b"seed error")
        .expect("seed package should contain its debug error message");
    control_character_package[error_message_offset] = b'\n';
    write_seed("debug_info", "package_with_control_character.bin", &control_character_package);

    let oversized_string: Arc<str> = "x".repeat(MAX_DEBUG_INFO_STRING_SIZE + 1).into();
    let (oversized_string_package, ..) =
        build_package_with_debug_options(None, oversized_string, 1);
    write_seed(
        "debug_info",
        "package_with_oversized_string.bin",
        &oversized_string_package.to_bytes(),
    );

    let (duplicate_asm_op_package, ..) =
        build_package_with_debug_options(None, Arc::from("seed error"), 2);
    write_seed(
        "debug_info",
        "package_with_duplicate_assembly_op.bin",
        &duplicate_asm_op_package.to_bytes(),
    );

    let file_path_offset = debug_info_bytes
        .windows(file_checksum.len())
        .position(|window| window == file_checksum)
        .expect("seed debug info should contain its file checksum")
        - 4;
    let mut dangling_file_debug_info = debug_info_bytes.clone();
    dangling_file_debug_info[file_path_offset..file_path_offset + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    write_seed("debug_info", "dangling_file_path_string.bin", &dangling_file_debug_info);

    let mut dangling_file_package = package_with_debug_info.to_bytes();
    let file_path_offset = dangling_file_package
        .windows(file_checksum.len())
        .position(|window| window == file_checksum)
        .expect("seed package should contain its debug file checksum")
        - 4;
    dangling_file_package[file_path_offset..file_path_offset + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    write_seed(
        "debug_info",
        "package_with_dangling_file_path_string.bin",
        &dangling_file_package,
    );
    write_seed(
        "package_deserialize",
        "package_with_dangling_file_path_string.bin",
        &dangling_file_package,
    );
    write_seed(
        "package_semantic_deserialize",
        "package_with_dangling_file_path_string.bin",
        &dangling_file_package,
    );

    let error_code = 0x0123_4567_89ab_cdef_u64.to_le_bytes();
    let error_code_offset = debug_info_bytes
        .windows(error_code.len())
        .position(|window| window == error_code)
        .expect("seed debug info should contain its error code");
    let mut root_section = [0u8; 12];
    root_section[..4].copy_from_slice(&1u32.to_le_bytes());
    root_section[8..].copy_from_slice(&1u32.to_le_bytes());
    let root_offset = debug_info_bytes[..error_code_offset]
        .windows(root_section.len())
        .rposition(|window| window == root_section)
        .expect("seed debug info should contain one root before one error message")
        + 4;
    let mut dangling_root_debug_info = debug_info_bytes.clone();
    assert_eq!(&dangling_root_debug_info[root_offset..root_offset + 4], &0u32.to_le_bytes());
    dangling_root_debug_info[root_offset..root_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    write_seed("debug_info", "dangling_source_root.bin", &dangling_root_debug_info);

    let mut dangling_root_package = package_with_debug_info.to_bytes();
    let error_code_offset = dangling_root_package
        .windows(error_code.len())
        .position(|window| window == error_code)
        .expect("seed package should contain its debug error code");
    let root_offset = dangling_root_package[..error_code_offset]
        .windows(root_section.len())
        .rposition(|window| window == root_section)
        .expect("seed package should contain one debug root before one error message")
        + 4;
    assert_eq!(&dangling_root_package[root_offset..root_offset + 4], &0u32.to_le_bytes());
    dangling_root_package[root_offset..root_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    write_seed("debug_info", "package_with_dangling_source_root.bin", &dangling_root_package);
    write_seed(
        "package_deserialize",
        "package_with_dangling_source_root.bin",
        &dangling_root_package,
    );
    write_seed(
        "package_semantic_deserialize",
        "package_with_dangling_source_root.bin",
        &dangling_root_package,
    );

    let asm_op_offset = debug_info_bytes
        .windows(asm_op.as_bytes().len())
        .position(|window| window == asm_op.as_bytes())
        .expect("seed debug info should contain its assembly operation");
    let mut invalid_asm_location_debug_info = debug_info_bytes.clone();
    assert_eq!(
        &invalid_asm_location_debug_info[asm_op_offset + 4..asm_op_offset + 8],
        &1u32.to_le_bytes(),
    );
    invalid_asm_location_debug_info[asm_op_offset + 4..asm_op_offset + 8]
        .copy_from_slice(&2u32.to_le_bytes());
    write_seed(
        "debug_info",
        "invalid_assembly_location_option.bin",
        &invalid_asm_location_debug_info,
    );
    for (name, field_offset, expected) in [
        ("dangling_assembly_context_string.bin", 12, 0u32),
        ("dangling_assembly_op_string.bin", 16, 1u32),
    ] {
        let mut bytes = debug_info_bytes.clone();
        assert_eq!(
            &bytes[asm_op_offset + field_offset..asm_op_offset + field_offset + 4],
            &expected.to_le_bytes(),
        );
        bytes[asm_op_offset + field_offset..asm_op_offset + field_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        write_seed("debug_info", name, &bytes);
    }

    let mut invalid_asm_location_package = package_with_debug_info.to_bytes();
    let asm_op_offset = invalid_asm_location_package
        .windows(asm_op.as_bytes().len())
        .position(|window| window == asm_op.as_bytes())
        .expect("seed package should contain its debug assembly operation");
    assert_eq!(
        &invalid_asm_location_package[asm_op_offset + 4..asm_op_offset + 8],
        &1u32.to_le_bytes(),
    );
    invalid_asm_location_package[asm_op_offset + 4..asm_op_offset + 8]
        .copy_from_slice(&2u32.to_le_bytes());
    write_seed(
        "debug_info",
        "package_with_invalid_assembly_location_option.bin",
        &invalid_asm_location_package,
    );
    write_seed(
        "package_deserialize",
        "package_with_invalid_assembly_location_option.bin",
        &invalid_asm_location_package,
    );
    write_seed(
        "package_semantic_deserialize",
        "package_with_invalid_assembly_location_option.bin",
        &invalid_asm_location_package,
    );

    let mut invalid_nested_kernel = kernel_with_debug_info.to_bytes();
    let nested_asm_op_offset = invalid_nested_kernel
        .windows(asm_op.as_bytes().len())
        .position(|window| window == asm_op.as_bytes())
        .expect("nested seed kernel should contain its debug assembly operation");
    assert_eq!(
        &invalid_nested_kernel[nested_asm_op_offset + 4..nested_asm_op_offset + 8],
        &1u32.to_le_bytes(),
    );
    invalid_nested_kernel[nested_asm_op_offset + 4..nested_asm_op_offset + 8]
        .copy_from_slice(&2u32.to_le_bytes());
    let mut package_with_invalid_nested_debug_info = build_package(None);
    package_with_invalid_nested_debug_info
        .manifest
        .add_dependency(kernel_dependency)
        .expect("seed package should accept its kernel dependency");
    package_with_invalid_nested_debug_info
        .sections
        .push(Section::new(SectionId::KERNEL, invalid_nested_kernel));
    let invalid_nested_package_bytes = package_with_invalid_nested_debug_info.to_bytes();
    let admitted_outer = Package::read_from_bytes(&invalid_nested_package_bytes)
        .expect("opaque hostile nested debug should not fail outer admission");
    assert!(
        admitted_outer.try_embedded_kernel_package().is_err(),
        "hostile nested debug seed should fail untrusted kernel extraction"
    );
    write_seed(
        "package_semantic_deserialize",
        "package_with_invalid_nested_debug_info.bin",
        &invalid_nested_package_bytes,
    );
    for (name, field_offset, expected) in [
        ("package_with_dangling_assembly_context_string.bin", 12, 0u32),
        ("package_with_dangling_assembly_op_string.bin", 16, 1u32),
    ] {
        let mut bytes = package_with_debug_info.to_bytes();
        assert_eq!(
            &bytes[asm_op_offset + field_offset..asm_op_offset + field_offset + 4],
            &expected.to_le_bytes(),
        );
        bytes[asm_op_offset + field_offset..asm_op_offset + field_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        write_seed("debug_info", name, &bytes);
        write_seed("package_deserialize", name, &bytes);
        write_seed("package_semantic_deserialize", name, &bytes);
    }

    let debug_var_bytes = debug_var.to_bytes();
    let debug_var_offset = debug_info_bytes
        .windows(debug_var_bytes.len())
        .position(|window| window == debug_var_bytes)
        .expect("seed debug info should contain its debug variable");
    for (name, field_offset, expected) in [
        ("dangling_debug_var_name.bin", 4, 2u32),
        ("dangling_debug_var_location.bin", 14, 0u32),
    ] {
        let mut bytes = debug_info_bytes.clone();
        assert_eq!(
            &bytes[debug_var_offset + field_offset..debug_var_offset + field_offset + 4],
            &expected.to_le_bytes(),
        );
        bytes[debug_var_offset + field_offset..debug_var_offset + field_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        write_seed("debug_info", name, &bytes);
    }

    let debug_var_offset = package_with_debug_info
        .to_bytes()
        .windows(debug_var_bytes.len())
        .position(|window| window == debug_var_bytes)
        .expect("seed package should contain its debug variable");
    for (name, field_offset, expected) in [
        ("package_with_dangling_debug_var_name.bin", 4, 2u32),
        ("package_with_dangling_debug_var_location.bin", 14, 0u32),
    ] {
        let mut bytes = package_with_debug_info.to_bytes();
        assert_eq!(
            &bytes[debug_var_offset + field_offset..debug_var_offset + field_offset + 4],
            &expected.to_le_bytes(),
        );
        bytes[debug_var_offset + field_offset..debug_var_offset + field_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        write_seed("debug_info", name, &bytes);
        write_seed("package_deserialize", name, &bytes);
        write_seed("package_semantic_deserialize", name, &bytes);
    }

    let mut dangling_error_debug_info = debug_info_bytes;
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
