//! Fuzz target for semantic Package deserialization checks.
//!
//! This target starts from binary `Package` deserialization, then exercises package APIs that
//! interpret decoded sections, runtime dependencies, and package kind.
//!
//! Run with: cargo +nightly fuzz run package_semantic_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::serde::{Deserializable, Serializable, SliceReader};
use miden_mast_package::{
    Package, SectionId, TargetType,
    debug_info::{DebugSourceNodeId, PackageDebugInfo},
};
use miden_processor::{
    DefaultHost, PackageSourceDebugContext,
    operation::OperationError,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(package) = Package::read_from_bytes_trusted(data) {
        validate_debug_sections(&package);
        match package.debug_info() {
            Ok(Some(expected_debug_info)) => {
                let untrusted_package = Package::read_from_bytes(data)
                    .expect("a package with valid debug info should pass untrusted admission");
                let actual_debug_info = untrusted_package
                    .debug_info()
                    .expect("admitted debug info should remain accessible")
                    .expect("admitted debug info should remain present");
                assert_eq!(actual_debug_info, expected_debug_info);
            },
            Err(_) => assert!(Package::read_from_bytes(data).is_err()),
            Ok(None) => {},
        }
    }

    let Ok(package) = Package::read_from_bytes(data) else {
        return;
    };

    validate_debug_sections(&package);

    let expected_debug_info = package
        .debug_info()
        .expect("untrusted admission should leave no deferred debug validation errors");
    let encoded = package.to_bytes();
    let round_tripped = Package::read_from_bytes(&encoded)
        .expect("an admitted package should survive serialization and re-admission");
    let actual_debug_info = round_tripped
        .debug_info()
        .expect("round-tripped debug info should remain valid");
    assert_eq!(actual_debug_info, expected_debug_info);

    if let Some(debug_info) = expected_debug_info.as_ref() {
        exercise_execution_diagnostics(debug_info);
    }

    let _ = package.kernel_runtime_dependency();
    exercise_embedded_kernel(&package);

    // These conversion helpers borrow the package, despite the `try_into_*` names.
    match package.kind {
        TargetType::Executable => {
            let _ = package.try_into_program();
        },
        TargetType::Kernel => {
            let _ = package.kernel_module_descriptor();
            let _ = package.to_kernel_descriptor();
        },
        _ => (),
    }
});

fn exercise_embedded_kernel(package: &Package) {
    let mut kernel_sections =
        package.sections.iter().filter(|section| section.id == SectionId::KERNEL);
    let Some(kernel_section) = kernel_sections.next() else {
        return;
    };
    if kernel_sections.next().is_some() {
        return;
    }

    let Ok(trusted_kernel) = Package::read_from_bytes_trusted(kernel_section.data.as_ref()) else {
        return;
    };

    let expected_debug_info = match trusted_kernel.debug_info() {
        Ok(debug_info) => debug_info,
        Err(_) => {
            assert!(
                package.try_embedded_kernel_package().is_err(),
                "nested debug info rejected on use must not pass untrusted kernel extraction"
            );
            return;
        },
    };

    let Ok(Some(kernel)) = package.try_embedded_kernel_package() else {
        return;
    };
    let actual_debug_info = kernel
        .debug_info()
        .expect("untrusted kernel extraction should leave no deferred debug validation errors");
    assert_eq!(actual_debug_info, expected_debug_info);

    let encoded = kernel.to_bytes();
    let round_tripped = Package::read_from_bytes(&encoded)
        .expect("an admitted embedded kernel should survive serialization and re-admission");
    assert_eq!(
        round_tripped.debug_info().expect("round-tripped kernel debug info should remain valid"),
        actual_debug_info
    );
}

fn validate_debug_sections(package: &Package) {
    for section in &package.sections {
        if section.id == SectionId::DEBUG_INFO {
            let mut reader = SliceReader::new(section.data.as_ref());
            let _ = PackageDebugInfo::read_from(&mut reader);
        }
    }
}

fn exercise_execution_diagnostics(debug_info: &PackageDebugInfo) {
    let host = DefaultHost::default();

    for (source_node_idx, source_node) in debug_info.nodes().iter().enumerate() {
        let Ok(source_node_idx) = u32::try_from(source_node_idx) else {
            break;
        };
        let context = PackageSourceDebugContext::new(
            debug_info,
            DebugSourceNodeId::from(source_node_idx),
        );

        let _ = context.assembly_location(None);
        for asm_op in &source_node.asm_ops {
            let _ = OperationError::DivideByZero.with_package_source_context(
                context,
                &host,
                Some(asm_op.op_idx as usize),
            );
        }
    }
}
