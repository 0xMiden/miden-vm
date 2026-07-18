//! Fuzz target for semantic Package deserialization checks.
//!
//! This target starts from binary `Package` deserialization, then exercises package APIs that
//! interpret decoded sections, runtime dependencies, and package kind.
//!
//! Run with: cargo +nightly fuzz run package_semantic_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::serde::{Deserializable, SliceReader};
use miden_mast_package::{Package, SectionId, TargetType, debug_info::PackageDebugInfo};

fuzz_target!(|data: &[u8]| {
    if let Ok(package) = Package::read_from_bytes_trusted(data) {
        validate_debug_sections(&package);
        let _ = package.debug_info();
    }

    let Ok(package) = Package::read_from_bytes(data) else {
        return;
    };

    validate_debug_sections(&package);

    let _ = package.kernel_runtime_dependency();
    let _ = package.try_embedded_kernel_package();

    // These conversion helpers borrow the package, despite the `try_into_*` names.
    match package.kind {
        TargetType::Executable => {
            let _ = package.try_into_program();
        },
        TargetType::Kernel => {
            let _ = package.kernel_module_info();
            let _ = package.to_kernel();
        },
        _ => (),
    }
});

fn validate_debug_sections(package: &Package) {
    for section in &package.sections {
        if section.id == SectionId::DEBUG_INFO {
            let mut reader = SliceReader::new(section.data.as_ref());
            let _ = PackageDebugInfo::read_from(&mut reader);
        }
    }
}
