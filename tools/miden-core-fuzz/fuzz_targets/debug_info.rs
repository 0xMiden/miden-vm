//! Fuzz target for package debug info deserialization.
//!
//! Package-owned debug info contains source/type/function sections and source-keyed MAST
//! occurrence metadata.
//!
//! Run with: cargo +nightly fuzz run debug_info --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_assembly_syntax::ast::types::Type;
use miden_core::serde::{Deserializable, SliceReader};
use miden_mast_package::{Package, debug_info::PackageDebugInfo};

fn assert_valid_type_alignments(ty: &Type) {
    assert!(ty.min_alignment().is_power_of_two());

    match ty {
        Type::Ptr(pointer) => assert_valid_type_alignments(pointer.pointee()),
        Type::Struct(structure) => {
            for field in structure.fields() {
                assert_valid_type_alignments(&field.ty);
            }
        },
        Type::Enum(enumeration) => {
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

fuzz_target!(|data: &[u8]| {
    if let Ok(package) = Package::read_from_bytes(data) {
        assert_valid_package_type_alignments(&package);
        let _ = package.debug_info();
    }
    if let Ok(package) = Package::read_from_bytes_trusted(data) {
        assert_valid_package_type_alignments(&package);
        let _ = package.debug_info();
    }

    let mut reader = SliceReader::new(data);
    let _ = PackageDebugInfo::read_from(&mut reader);
});
