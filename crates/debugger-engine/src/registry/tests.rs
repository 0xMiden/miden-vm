use std::string::ToString;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::serde::Serializable;

use super::*;

fn package(source: &str) -> Arc<Package> {
    Arc::new(
        *Assembler::new(Arc::new(DefaultSourceManager::default()))
            .assemble_program("registry-test", source)
            .unwrap(),
    )
}

#[test]
fn cache_publish_and_load_preserve_versions_and_digests() {
    let original = package("begin push.1 end");
    let mut registry = HybridPackageRegistry::empty();
    let version = registry.cache_package(original.clone()).unwrap();
    assert_eq!(registry.available_versions(&original.name).unwrap().len(), 1);
    assert_eq!(registry.publish_package(original.clone()).unwrap(), version);
    assert!(Arc::ptr_eq(
        &registry.load_package(&original.name, &version).unwrap(),
        &original
    ));
    assert_eq!(registry.all().into_iter().count(), 1);

    let conflicting = package("begin push.2 end");
    assert_ne!(original.dependency_commitment(), conflicting.dependency_commitment());
    let error = registry.cache_package(conflicting.clone()).unwrap_err();
    assert!(error.to_string().contains("different digest"));
    let conflicting_version = miden_package_registry::Version::new(
        conflicting.version.clone(),
        conflicting.dependency_commitment(),
    );
    assert!(
        registry
            .load_package(&original.name, &conflicting_version)
            .unwrap_err()
            .to_string()
            .contains("specific digest")
    );
    assert!(Arc::ptr_eq(
        &registry.load_package(&original.name, &version).unwrap(),
        &original
    ));

    let mut newer = (*original).clone();
    newer.version = "1.0.0".parse().unwrap();
    let newer = Arc::new(newer);
    let newer_version = registry.publish_package(newer.clone()).unwrap();
    assert_eq!(registry.available_versions(&original.name).unwrap().len(), 2);
    assert!(Arc::ptr_eq(
        &registry.load_package(&original.name, &newer_version).unwrap(),
        &newer
    ));
    assert_eq!(registry.all().into_iter().count(), 2);

    let absent: PackageId = "missing".into();
    assert!(registry.available_versions(&absent).is_none());
    assert!(
        registry
            .load_package(&absent, &version)
            .unwrap_err()
            .to_string()
            .contains("no such package")
    );
}

#[test]
fn registration_rejects_duplicates_without_replacing_records() {
    let original = package("begin push.1 end");
    let version = miden_package_registry::Version::new(
        original.version.clone(),
        original.dependency_commitment(),
    );
    let record = PackageRecord::new(version.clone(), []);
    let mut registry = HybridPackageRegistry::empty();
    registry.register(original.name.clone(), record.clone()).unwrap();
    let error = registry.register(original.name.clone(), record).unwrap_err();
    assert!(error.to_string().contains("already registered"));
    assert_eq!(registry.available_versions(&original.name).unwrap().len(), 1);
    assert_eq!(registry.cache_package(original.clone()).unwrap(), version);
    assert_eq!(registry.all().into_iter().count(), 1);
}

#[test]
fn local_registry_loads_only_packages_and_reports_invalid_inputs() {
    let directory = tempfile::tempdir().unwrap();
    assert!(HybridPackageRegistry::from_local_registry(directory.path()).is_err());
    let lib = directory.path().join("lib");
    std::fs::create_dir(&lib).unwrap();
    std::fs::write(lib.join("ignored.txt"), b"not a package").unwrap();
    std::fs::write(lib.join("no-extension"), b"not a package").unwrap();
    let original = package("begin push.1 end");
    std::fs::write(lib.join("library.MASP"), original.to_bytes()).unwrap();
    let registry = HybridPackageRegistry::from_local_registry(directory.path()).unwrap();
    assert_eq!(registry.all().into_iter().count(), 1);
    assert!(registry.available_versions(&original.name).is_some());
    std::fs::write(lib.join("broken.masp"), b"not a package").unwrap();
    assert!(HybridPackageRegistry::from_local_registry(directory.path()).is_err());
}

#[test]
fn explicit_libraries_do_not_replace_conflicting_sysroot_packages() {
    use crate::Linkage;

    let directory = tempfile::tempdir().unwrap();
    let lib = directory.path().join("lib");
    std::fs::create_dir(&lib).unwrap();
    let original = package("begin push.1 end");
    let conflicting = package("begin push.2 end");
    std::fs::write(lib.join("original.masp"), original.to_bytes()).unwrap();
    let path = directory.path().join("conflicting.masp");
    std::fs::write(&path, conflicting.to_bytes()).unwrap();
    let library = LinkLibrary {
        name: original.name.to_string().into(),
        path: Some(path),
        linkage: Linkage::Dynamic,
    };
    let registry =
        HybridPackageRegistry::new(Some(directory.path()), &[], core::slice::from_ref(&library))
            .unwrap();
    let loaded = registry.all().into_iter().next().unwrap();
    assert_eq!(loaded.dependency_commitment(), original.dependency_commitment());
    let registry = HybridPackageRegistry::new(None, &[], &[library]).unwrap();
    let loaded = registry.all().into_iter().next().unwrap();
    assert_eq!(loaded.dependency_commitment(), conflicting.dependency_commitment());
}
