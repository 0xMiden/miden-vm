//! Fuzz target for package debug info deserialization.
//!
//! Package-owned debug info contains source/type/function sections and source-keyed MAST
//! occurrence metadata.
//!
//! Run with: cargo +nightly fuzz run debug_info --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_assembly_syntax::ast::types::Type;
use miden_core::serde::{ByteReader, Deserializable, SliceReader};
use miden_mast_package::{
    Package,
    debug_info::{
        MAX_DEBUG_INFO_PAYLOAD_SIZE, MAX_DEBUG_INFO_STRING_ROWS, MAX_DEBUG_INFO_STRING_SIZE,
        MAX_DEBUG_INFO_TYPE_ROWS, PackageDebugInfo,
    },
};

fn exercise_debug_info(debug_info: &PackageDebugInfo) {
    for (index, _) in debug_info.locations().iter().enumerate() {
        let _ = debug_info.get_location((index as u32).into());
    }
    for message in debug_info.error_messages() {
        let _ = debug_info.error_message(message.err_code);
    }
    for node in debug_info.nodes() {
        for asm_op in &node.asm_ops {
            let _ = asm_op.to_assembly_op(debug_info);
        }
        for debug_var in &node.debug_vars {
            let _ = node.debug_infos_for_operation(debug_var.op_idx, debug_info).count();
        }
    }

    let _ = debug_info
        .source_roots_for_exec_node(miden_core::mast::MastNodeId::new_unchecked(0))
        .count();
    let mut cloned = debug_info.clone();
    cloned.trim_file_paths(|_| None);
}

fn assert_valid_type_alignments(ty: &Type) {
    assert!(ty.min_alignment().is_power_of_two());

    match ty {
        Type::Ptr(pointer) => assert_valid_type_alignments(pointer.pointee()),
        Type::Struct(structure) => {
            let structure = structure.get();
            for field in structure.fields() {
                assert_valid_type_alignments(&field.ty);
            }
        },
        Type::Enum(enumeration) => {
            let enumeration = enumeration.get();
            assert_valid_type_alignments(enumeration.discriminant());
            for variant in enumeration.variants() {
                if let Some(value) = variant.value.as_ref() {
                    assert_valid_type_alignments(value);
                }
            }
        },
        Type::Array(array) => assert_valid_type_alignments(array.element_type()),
        Type::List(element) => assert_valid_type_alignments(element),
        Type::Function(function) => {
            for ty in function.params().iter().chain(function.results()) {
                assert_valid_type_alignments(ty);
            }
        },
        _ => {},
    }
}

fn assert_valid_package_type_alignments(package: &Package) {
    for procedure in package.manifest.exports().filter_map(|export| export.as_procedure()) {
        if let Some(signature) = procedure.signature.as_ref() {
            for ty in signature.params().iter().chain(signature.results()) {
                assert_valid_type_alignments(ty);
            }
        }
    }
}

fn assert_valid_debug_policy(debug_info: &PackageDebugInfo) {
    for string in debug_info.strings() {
        assert!(string.len() <= MAX_DEBUG_INFO_STRING_SIZE);
        assert!(!string.chars().any(char::is_control));
    }
    for location in debug_info.locations() {
        assert!(location.start.to_usize() <= location.end.to_usize());
    }
    for source_node in debug_info.nodes() {
        assert!(source_node.asm_ops.windows(2).all(|rows| rows[0].op_idx < rows[1].op_idx));
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(package) = Package::read_from_bytes(data) {
        assert_valid_package_type_alignments(&package);
        let _ = package.debug_info();
    }
    if let Ok(package) = Package::read_from_bytes_trusted(data) {
        assert_valid_package_type_alignments(&package);
        if let Ok(Some(debug_info)) = package.debug_info() {
            assert_valid_debug_policy(&debug_info);
        }
    }

    let mut framing_reader = SliceReader::new(data);
    let declared_payload_len =
        framing_reader.read_u8().and_then(|_| framing_reader.read_usize()).ok();
    let mut reader = SliceReader::new(data);
    let debug_info = PackageDebugInfo::read_from(&mut reader);
    if declared_payload_len.is_some_and(|len| len > MAX_DEBUG_INFO_PAYLOAD_SIZE) {
        assert!(debug_info.is_err());
    } else if let Ok(debug_info) = debug_info {
        assert!(debug_info.strings().len() <= MAX_DEBUG_INFO_STRING_ROWS);
        assert!(debug_info.types().len() <= MAX_DEBUG_INFO_TYPE_ROWS);
        for source_node in debug_info.nodes() {
            assert!(source_node.asm_ops.windows(2).all(|rows| rows[0].op_idx < rows[1].op_idx));
        }
        exercise_debug_info(&debug_info);
    }
});
