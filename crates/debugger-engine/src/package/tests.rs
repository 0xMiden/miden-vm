use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::serde::Serializable;
use miden_mast_package::SectionId;

use super::*;

#[test]
fn current_package_with_debug_info_loads() {
    let package = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program("test", "begin push.1 drop end")
        .unwrap();

    let uri = Uri::new("current.masp");
    let restored = read_package_from_bytes(&package.to_bytes(), &uri).unwrap();

    assert_eq!(restored.to_bytes(), package.to_bytes());
    assert!(restored.debug_info().unwrap().is_some());
}

#[test]
fn incompatible_package_format_recommends_matching_toolchain() {
    let bytes = b"MASP\0\x06\x00\x00";

    let uri = Uri::new("old.masp");
    let report = read_package_from_bytes(bytes, &uri).unwrap_err();
    let error = report
        .downcast_ref::<PackageLoadError>()
        .expect("expected a classified package load error");

    let PackageLoadError::IncompatiblePackageFormat { version, help, .. } = error else {
        panic!("expected an incompatible package format error, got {error:?}");
    };
    assert_eq!(*version, PackageFormatVersion([6, 0, 0]));
    assert!(help.contains("miden +0.16.0 debug"));
}

#[test]
fn incompatible_debug_info_recommends_matching_toolchain() {
    let mut package = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program("test", "begin push.1 drop end")
        .unwrap();
    let debug_info = package
        .sections
        .iter_mut()
        .find(|section| section.id == SectionId::DEBUG_INFO)
        .expect("assembled package should contain debug info");
    debug_info.data.to_mut()[0] = u8::MAX;

    let uri = Uri::new("old-debug.masp");
    let report = read_package_from_bytes(&package.to_bytes(), &uri).unwrap_err();
    let error = report
        .downcast_ref::<PackageLoadError>()
        .expect("expected a classified package load error");

    let PackageLoadError::IncompatibleDebugInfoFormat { help, .. } = error else {
        panic!("expected an incompatible debug-info format error, got {error:?}");
    };
    assert!(help.contains("miden +0.16.0 debug"));
}

#[test]
fn malformed_package_does_not_get_a_version_hint() {
    let uri = Uri::new("broken.masp");
    let report = read_package_from_bytes(b"not a package", &uri).unwrap_err();
    let error = report
        .downcast_ref::<PackageLoadError>()
        .expect("expected a classified package load error");

    assert!(matches!(error, PackageLoadError::DecodePackage { .. }));
}
