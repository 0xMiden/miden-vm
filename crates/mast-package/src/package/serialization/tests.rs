#[cfg(feature = "std")]
use alloc::format;
use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::assert_matches;
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::fs;

use miden_assembly_syntax::ast::{Ident, Path as AstPath, PathBuf, ProcedureName};
use miden_core::{
    Felt, Word,
    advice::AdviceMap,
    mast::{
        BasicBlockNodeBuilder, DenseMastForestBuilder, MastForest, MastNode, MastNodeExt,
        MastNodeId,
    },
    operations::Operation,
    serde::{
        BudgetedReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
    },
    utils::IndexVec,
};

use super::{
    MAGIC_PACKAGE, PACKAGE_BYTE_READ_BUDGET_MULTIPLIER, Package, PackageManifest, Section, VERSION,
};
use crate::{
    Dependency, ManifestValidationError, PackageExport, PackageId, PackageModule, PackageSubmodule,
    ProcedureExport, SectionId, TargetType,
    debug_info::{
        DebugSourceAsmOp, DebugSourceGraphSection, DebugSourceMapSection, DebugSourceNode,
        DebugSourceNodeId,
    },
};

fn build_single_node_forest(
    operations: Vec<Operation>,
    make_root: bool,
) -> (MastForest, MastNodeId) {
    let mut builder = DenseMastForestBuilder::new();
    let node_id = builder
        .push_node(BasicBlockNodeBuilder::new(operations))
        .expect("failed to build basic block");
    if make_root {
        builder.mark_root(node_id);
    }
    let (forest, remapping) = builder.build_with_id_map().expect("forest should be valid");
    let node_id = remapping.get(node_id).expect("node should be retained");
    (forest, node_id)
}

fn build_forest() -> (MastForest, MastNodeId) {
    build_single_node_forest(vec![Operation::Add], true)
}

fn absolute_path(name: &str) -> Arc<AstPath> {
    let path = PathBuf::new(name).expect("invalid path");
    let path = path.as_path().to_absolute().unwrap().into_owned();
    Arc::from(path.into_boxed_path())
}

fn build_package_exports() -> (Arc<MastForest>, Vec<PackageExport>) {
    let (forest, node_id) = build_forest();
    let path = absolute_path("test::proc");
    let export =
        ProcedureExport::new(Arc::clone(&path), Some(node_id), forest[node_id].digest(), None);

    (Arc::new(forest), vec![PackageExport::Procedure(export)])
}

fn build_package() -> Package {
    let (mast, exports) = build_package_exports();

    Package::create(
        PackageId::from("test_pkg"),
        crate::Version::new(0, 0, 0),
        TargetType::Library,
        mast,
        exports,
        None,
    )
    .expect("test package should be valid")
}

fn build_package_with_debug_info() -> Package {
    let mut nodes = IndexVec::<MastNodeId, MastNode>::new();
    let node = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .build()
        .expect("failed to build basic block");
    let digest = node.digest();
    let node_id = nodes.push(node.into()).expect("failed to add basic block");
    let source_node = DebugSourceNodeId::from(0);

    let mast = Arc::new(
        MastForest::from_raw_parts(nodes, vec![node_id], AdviceMap::default())
            .expect("forest should be valid"),
    );
    let path = absolute_path("test::proc");
    let exports = vec![PackageExport::Procedure(
        ProcedureExport::new(path, Some(node_id), digest, None).with_source_node(Some(source_node)),
    )];
    let mut package = Package::create(
        PackageId::from("test_pkg"),
        crate::Version::new(0, 0, 0),
        TargetType::Library,
        mast,
        exports,
        None,
    )
    .expect("test package should be valid");
    let source_graph = DebugSourceGraphSection::from_parts(
        vec![DebugSourceNode::new(node_id, Vec::new(), 0, 1)],
        vec![source_node],
    );
    let source_map = DebugSourceMapSection::from_parts(
        vec![DebugSourceAsmOp::new(source_node, 0, None, "trusted".into(), "add".into(), 1)],
        Vec::new(),
    );
    package
        .sections
        .push(Section::new(SectionId::DEBUG_SOURCE_GRAPH, source_graph.to_bytes()));
    package
        .sections
        .push(Section::new(SectionId::DEBUG_SOURCE_MAP, source_map.to_bytes()));
    package
}

fn build_dependency() -> Dependency {
    Dependency {
        name: PackageId::from("dep"),
        kind: TargetType::Library,
        version: crate::Version::new(1, 0, 0),
        digest: Default::default(),
    }
}

fn package_bytes_with_sections_count(count: usize) -> Vec<u8> {
    let package = build_package();
    let mut bytes = Vec::new();

    bytes.write_bytes(MAGIC_PACKAGE);
    bytes.write_bytes(&VERSION);
    package.name.write_into(&mut bytes);
    package.version.to_string().write_into(&mut bytes);
    package.description.write_into(&mut bytes);
    bytes.write_u8(package.kind.into());
    package.mast.write_into(&mut bytes);
    package.manifest.write_into(&mut bytes);
    bytes.write_usize(count);

    bytes
}

#[test]
fn package_serialization_roundtrip() {
    use proptest::{
        prelude::*,
        test_runner::{Config, TestRunner},
    };

    // since the test is quite expensive, 128 cases should be enough to cover all edge cases
    // (default is 256)
    let cases = 128;
    TestRunner::new(Config::with_cases(cases))
        .run(&any::<Package>(), move |package| {
            let bytes = package.to_bytes();
            let deserialized = Package::read_from_bytes(&bytes).unwrap();
            let mut expected = package;
            expected.sections.retain(|section| !section.id.is_debug());
            prop_assert_eq!(expected.to_bytes(), deserialized.to_bytes());
            Ok(())
        })
        .unwrap_or_else(|err| {
            panic!("{err}");
        });
}

#[test]
fn executable_package_entrypoint_roundtrips() {
    let (forest, node_id) = build_forest();
    let entrypoint =
        Arc::from(AstPath::exec_path().join(ProcedureName::MAIN_PROC_NAME).into_boxed_path());
    let export = ProcedureExport::new(
        Arc::clone(&entrypoint),
        Some(node_id),
        forest[node_id].digest(),
        None,
    );
    let package = Package::create(
        PackageId::from("test_pkg"),
        crate::Version::new(0, 0, 0),
        TargetType::Executable,
        Arc::new(forest),
        [PackageExport::Procedure(export)],
        None,
    )
    .expect("executable package should be valid");

    let deserialized = Package::read_from_bytes(&package.to_bytes())
        .expect("executable package should deserialize without duplicate entrypoint errors");

    assert_eq!(deserialized.manifest.entrypoint(), Some(entrypoint));
}

#[test]
fn package_checked_deserialization_discards_untrusted_debug_sections() {
    let package = build_package_with_debug_info();
    let bytes = package.to_bytes();

    let deserialized = Package::read_from_bytes(&bytes).unwrap();

    assert!(
        !deserialized.sections.iter().any(|section| section.id.is_debug()),
        "untrusted package reads should discard debug sections"
    );
    assert!(deserialized.debug_info().unwrap().is_none());
    let debug_source_map_id = SectionId::DEBUG_SOURCE_MAP.as_str().as_bytes();
    assert!(
        !deserialized
            .to_bytes()
            .windows(debug_source_map_id.len())
            .any(|window| window == debug_source_map_id),
        "discarded debug sections should not be reserialized"
    );
}

#[test]
fn package_trusted_deserialization_preserves_trusted_debug_sections() {
    let package = build_package_with_debug_info();
    let bytes = package.to_bytes();

    let deserialized = Package::read_from_bytes_trusted(&bytes).unwrap();

    assert!(
        deserialized
            .sections
            .iter()
            .any(|section| section.id == SectionId::DEBUG_SOURCE_MAP)
    );
    assert!(deserialized.debug_info().unwrap().is_some());
}

#[test]
fn package_unchecked_deserialization_preserves_trusted_debug_sections() {
    let package = build_package_with_debug_info();
    let bytes = package.to_bytes();

    let deserialized = Package::read_from_bytes_unchecked(&bytes).unwrap();

    assert!(
        deserialized
            .sections
            .iter()
            .any(|section| section.id == SectionId::DEBUG_SOURCE_MAP)
    );
    assert!(deserialized.debug_info().unwrap().is_some());
}

#[cfg(feature = "std")]
#[test]
fn package_deserialize_from_file_discards_untrusted_debug_sections() {
    let package = build_package_with_debug_info();
    let path = std::env::temp_dir().join(format!(
        "miden-package-deserialize-{}-{}.masp",
        std::process::id(),
        "debug-sections"
    ));
    package.write_to_file(&path).unwrap();

    let deserialized = Package::deserialize_from_file(&path).unwrap();
    fs::remove_file(&path).unwrap();

    assert!(
        !deserialized.sections.iter().any(|section| section.id.is_debug()),
        "untrusted package file reads should discard debug sections"
    );
    assert!(deserialized.debug_info().unwrap().is_none());
}

#[cfg(feature = "std")]
#[test]
fn package_deserialize_from_file_trusted_preserves_trusted_debug_sections() {
    let package = build_package_with_debug_info();
    let path = std::env::temp_dir().join(format!(
        "miden-package-deserialize-{}-{}.masp",
        std::process::id(),
        "trusted-debug-sections"
    ));
    package.write_to_file(&path).unwrap();

    let deserialized = Package::deserialize_from_file_trusted(&path).unwrap();
    fs::remove_file(&path).unwrap();

    assert!(
        deserialized
            .sections
            .iter()
            .any(|section| section.id == SectionId::DEBUG_SOURCE_MAP)
    );
    assert!(deserialized.debug_info().unwrap().is_some());
}

#[test]
fn package_content_digest_changes_when_identity_fields_change() {
    let package = build_package();
    let digest = package.content_digest();

    let renamed = Package {
        name: PackageId::from("renamed_pkg"),
        ..package.clone()
    };
    assert_ne!(digest, renamed.content_digest());

    let versioned = Package {
        version: crate::Version::new(1, 2, 3),
        ..package.clone()
    };
    assert_ne!(digest, versioned.content_digest());

    let executable = Package { kind: TargetType::Executable, ..package };
    assert_ne!(digest, executable.content_digest());
}

#[test]
fn package_content_digest_changes_when_manifest_changes() {
    let package = build_package();
    let digest = package.content_digest();

    let mut with_dependency = package;
    with_dependency
        .manifest
        .add_dependency(Dependency {
            name: PackageId::from("dep_pkg"),
            kind: TargetType::Library,
            version: crate::Version::new(1, 0, 0),
            digest: Word::from([1_u32, 2, 3, 4]),
        })
        .expect("test dependency should be unique");
    assert_ne!(digest, with_dependency.content_digest());
}

#[test]
fn package_content_digest_changes_when_account_component_metadata_changes() {
    let package = build_package();
    let digest = package.content_digest();

    let with_metadata = Package {
        sections: vec![Section::new(SectionId::ACCOUNT_COMPONENT_METADATA, vec![1, 2, 3, 4])],
        ..package.clone()
    };
    assert_ne!(digest, with_metadata.content_digest());

    let with_different_metadata = Package {
        sections: vec![Section::new(SectionId::ACCOUNT_COMPONENT_METADATA, vec![4, 3, 2, 1])],
        ..package
    };
    assert_ne!(with_metadata.content_digest(), with_different_metadata.content_digest());
}

#[test]
fn package_content_digest_ignores_description_and_opaque_custom_sections_for_now() {
    let package = build_package();
    let digest = package.content_digest();

    let described = Package {
        description: Some(String::from("human-facing package description")),
        ..package.clone()
    };
    assert_eq!(digest, described.content_digest());

    let with_section = Package {
        sections: vec![Section::new(
            SectionId::custom("opaque").expect("valid custom section id"),
            vec![1, 2, 3, 4],
        )],
        ..package
    };
    assert_eq!(digest, with_section.content_digest());
}

#[test]
fn package_manifest_rejects_over_budget_dependencies() {
    let mut bytes = Vec::new();
    bytes.write_usize(0);
    bytes.write_usize(0);
    bytes.write_usize(2);

    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), 2);
    let err = PackageManifest::read_from(&mut reader).unwrap_err();
    assert!(matches!(err, DeserializationError::InvalidValue(_)));
}

#[test]
fn package_rejects_over_budget_sections() {
    let bytes = package_bytes_with_sections_count(2);
    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), bytes.len());
    let err = Package::read_from(&mut reader).unwrap_err();
    assert!(matches!(err, DeserializationError::InvalidValue(_)));
}

#[test]
fn package_read_from_bytes_rejects_fuzzed_oom_payload() {
    // This fuzz payload encodes counts large enough to cause excessive allocation or read work.
    // If this starts succeeding, package byte-slice deserialization is no longer budgeted.
    let payload = [
        0x4d, 0x41, 0x53, 0x50, 0x00, 0x04, 0x00, 0x00, 0x11, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x70,
        0x6b, 0x67, 0x0b, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00, 0x4d, 0x41, 0x53, 0x54, 0x00,
        0x00, 0x00, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x17, 0x03, 0x22, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x2f,
        0x08, 0x0a, 0x21, 0xa9, 0xb6, 0xf6, 0x1a, 0x52, 0x30, 0xc5, 0x64, 0xc7, 0xdb, 0x4d, 0x83,
        0x0b, 0x32, 0x58, 0x89, 0x88, 0xb2, 0x78, 0x69, 0xbb, 0x23, 0xa6, 0x18, 0x9c, 0xc9, 0x35,
        0x2d, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x00, 0x0c,
        0x00, 0x3a, 0x3a, 0x74, 0x65, 0x73, 0x74, 0x3a, 0x3a, 0x70, 0x72, 0x6f, 0x63, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x03, 0x0f, 0x03, 0x0f, 0x01, 0x00, 0x00, 0x17, 0x03, 0x22, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9c, 0xc9, 0x35, 0x2d, 0x01, 0x00,
        0x03, 0x0f, 0x03, 0x0f, 0x01, 0x01, 0x01,
    ];

    let result = Package::read_from_bytes(&payload);
    assert!(result.is_err());

    // Wrapped fuzz inputs must use the generic budgeted entry point; otherwise the outer
    // collection length can drive unbounded work before the inner package fails.
    let mut vec_payload = vec![0];
    vec_payload.extend_from_slice(&1000u64.to_le_bytes());
    let budget = vec_payload.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
    let result = Vec::<Package>::read_from_bytes_with_budget(&vec_payload, budget);
    assert!(result.is_err());

    let mut option_payload = vec![1];
    option_payload.extend_from_slice(&payload);
    let budget = option_payload.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
    let result = Option::<Package>::read_from_bytes_with_budget(&option_payload, budget);
    assert!(result.is_err());
}

/// Verifies that deserializing a library rejects procedure exports whose `MastNodeId` is not a
/// procedure root in the underlying MAST forest (issue #2831).
#[test]
fn package_rejects_non_root_export() {
    let (forest, node_id) = build_single_node_forest(vec![Operation::Add], false);
    let digest = forest[node_id].digest();

    let path = absolute_path("test::proc");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("test_pkg"),
        version: crate::Version::new(0, 0, 0),
        digest,
        description: None,
        kind: TargetType::Library,
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    // Manually serialize the tampered package: forest + one export referencing a non-root node.
    let mut tampered_bytes = Vec::new();
    package.write_into(&mut tampered_bytes);

    // Deserializing should fail because the export references a non-root node.
    let result = Package::read_from_bytes(&tampered_bytes);
    assert!(
        result.is_err(),
        "deserialization should reject exports referencing non-root nodes"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("node id and digest do not correspond to a procedure root"),
        "error should mention missing procedure root, got: {err_msg}"
    );
}

#[test]
fn package_manifest_new_rejects_duplicate_export_paths() {
    let path = absolute_path("test::proc");
    let exports = vec![
        PackageExport::Procedure(ProcedureExport::new(path.clone(), None, Word::default(), None)),
        PackageExport::Procedure(ProcedureExport::new(path.clone(), None, Word::default(), None)),
    ];

    let err = PackageManifest::new(exports)
        .expect_err("duplicate export paths should be rejected by constructors");
    assert_matches!(err, ManifestValidationError::DuplicateExport(err_path) if err_path == path);
}

#[test]
fn package_manifest_roundtrips_module_surfaces() {
    let export = PackageExport::Procedure(ProcedureExport::new(
        absolute_path("test::api::foo"),
        None,
        Word::default(),
        None,
    ));
    let module = PackageModule::new(
        absolute_path("test"),
        [PackageSubmodule::new(Ident::new("api").unwrap())],
    );
    let child = PackageModule::new(absolute_path("test::api"), []);

    let manifest = PackageManifest::new([export])
        .and_then(|manifest| manifest.with_modules([module, child]))
        .expect("manifest should be valid");
    let bytes = manifest.to_bytes();
    let decoded = PackageManifest::read_from_bytes(&bytes).expect("manifest should roundtrip");

    let root = decoded
        .get_module(absolute_path("test").as_ref())
        .expect("root module surface should be present");
    assert_eq!(root.submodules().len(), 1);
    assert_eq!(root.submodules()[0].name.as_str(), "api");
    assert!(decoded.get_module(absolute_path("test::api").as_ref()).is_some());
}

#[test]
fn package_manifest_add_dependency_rejects_duplicate_dependencies() {
    let mut manifest = PackageManifest {
        exports: Default::default(),
        modules: Default::default(),
        dependencies: Default::default(),
        entrypoint: None,
    };
    let dependency = build_dependency();

    manifest
        .add_dependency(dependency.clone())
        .expect("first dependency should be accepted");
    let err = manifest
        .add_dependency(dependency)
        .expect_err("duplicate dependencies should be rejected by helpers");
    assert_matches!(err, ManifestValidationError::DuplicateDependency(pkgid) if pkgid == "dep");
}

#[test]
fn package_manifest_rejects_duplicate_export_paths() {
    let path = absolute_path("test::proc");
    let export = PackageExport::Procedure(ProcedureExport::new(path, None, Word::default(), None));

    let mut bytes = Vec::new();
    bytes.write_usize(2);
    export.write_into(&mut bytes);
    export.write_into(&mut bytes);
    bytes.write_usize(0);
    bytes.write_usize(0);
    bytes.write_bool(false);

    let mut reader = SliceReader::new(&bytes);
    let err = PackageManifest::read_from(&mut reader)
        .expect_err("duplicate export paths should be rejected during deserialization");
    assert!(matches!(err, DeserializationError::InvalidValue(_)));
}

#[test]
fn package_manifest_rejects_duplicate_dependencies() {
    let dependency = build_dependency();

    let mut bytes = Vec::new();
    bytes.write_usize(0);
    bytes.write_usize(0);
    bytes.write_usize(2);
    dependency.write_into(&mut bytes);
    dependency.write_into(&mut bytes);
    bytes.write_bool(false);

    let mut reader = SliceReader::new(&bytes);
    let err = PackageManifest::read_from(&mut reader)
        .expect_err("duplicate dependencies should be rejected during deserialization");
    assert!(matches!(err, DeserializationError::InvalidValue(_)));
}

#[test]
fn package_manifest_deserialization_rejects_malformed_quoted_procedure_leaf() {
    let bad = Arc::<AstPath>::from(AstPath::validate(r#"::foo::"bad name""#).unwrap());
    let exports = BTreeMap::from_iter([(
        bad.clone(),
        PackageExport::Procedure(ProcedureExport::new(bad, None, Default::default(), None)),
    )]);

    let manifest = PackageManifest {
        exports,
        modules: Default::default(),
        dependencies: Default::default(),
        entrypoint: None,
    };

    let bytes = manifest.to_bytes();

    let err = PackageManifest::read_from_bytes(&bytes).expect_err(
        "expected malformed procedure export leaf name rejection during deserialization",
    );
    let message = alloc::format!("{err}");
    assert_matches!(
        message,
        msg if msg.contains("invalid export path '::foo::\"bad name\"': invalid item path component"),
    );
}

#[test]
fn package_manifest_deserialization_rejects_malformed_quoted_constant_leaf() {
    let bad = Arc::<AstPath>::from(AstPath::validate(r#"::foo::"bad name""#).unwrap());
    let exports = BTreeMap::from_iter([(
        bad.clone(),
        PackageExport::Constant(crate::ConstantExport {
            path: bad,
            value: miden_assembly_syntax::ast::ConstantValue::Int(
                miden_debug_types::Span::unknown(1u32.into()),
            ),
        }),
    )]);

    let manifest = PackageManifest {
        exports,
        modules: Default::default(),
        dependencies: Default::default(),
        entrypoint: None,
    };

    let bytes = manifest.to_bytes();

    let err = PackageManifest::read_from_bytes(&bytes).expect_err(
        "expected malformed constant export leaf name rejection during deserialization",
    );
    let message = alloc::format!("{err}");
    assert_matches!(
        message,
        msg if msg.contains("invalid export path '::foo::\"bad name\"': invalid item path component"),
    );
}

#[test]
fn package_manifest_deserialization_rejects_malformed_quoted_type_leaf() {
    let bad = Arc::<AstPath>::from(AstPath::validate(r#"::foo::"bad name""#).unwrap());
    let exports = BTreeMap::from_iter([(
        bad.clone(),
        PackageExport::Type(crate::TypeExport {
            path: bad,
            ty: miden_assembly_syntax::ast::types::Type::Felt,
        }),
    )]);

    let manifest = PackageManifest {
        exports,
        modules: Default::default(),
        dependencies: Default::default(),
        entrypoint: None,
    };

    let bytes = manifest.to_bytes();

    let err = PackageManifest::read_from_bytes(&bytes)
        .expect_err("expected malformed type export leaf name rejection during deserialization");
    let message = alloc::format!("{err}");
    assert_matches!(
        message,
        msg if msg.contains("invalid export path '::foo::\"bad name\"': invalid item path component"),
    );
}

#[test]
fn regression_package_deserialisation_rejects_spoofed_mast_node_digests() {
    // Build mast for:
    //
    // pub proc p
    //     push.1
    // end
    let (forest, node_id) =
        build_single_node_forest(vec![Operation::Push(Felt::from_u32(1))], false);
    let digest = forest[node_id].digest();

    let path = absolute_path("lib::p");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("lib"),
        version: crate::Version::new(0, 0, 0),
        digest,
        description: None,
        kind: TargetType::Library,
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    let (bytes, _) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-library-digest");
    let err = Package::read_from_bytes(&bytes)
        .expect_err("expected package deserialization to reject inconsistent node digests");
    assert!(
        err.to_string().contains("invalid untrusted MAST forest"),
        "expected untrusted-MAST validation failure, got: {err}"
    );
    assert!(
        err.to_string().contains("hash mismatch for node"),
        "expected digest mismatch failure, got: {err}"
    );
}

#[test]
fn unchecked_package_deserialisation_rejects_spoofed_mast_node_digests() {
    // Build mast for:
    //
    // pub proc p
    //     push.1
    // end
    let (forest, node_id) =
        build_single_node_forest(vec![Operation::Push(Felt::from_u32(1))], false);
    let digest = forest[node_id].digest();

    let path = absolute_path("lib::p");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("lib"),
        version: crate::Version::new(0, 0, 0),
        digest,
        description: None,
        kind: TargetType::Library,
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    let (bytes, _spoofed_digest) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-library-digest");
    let err = Package::read_from_bytes_unchecked(&bytes)
        .expect_err("expected package deserialization to reject inconsistent node digests");
    assert!(
        err.to_string()
            .contains("declared node id and digest do not correspond to a procedure root"),
        "expected package manifest validation failure, got: {err}"
    );
}

#[test]
fn regression_kernel_package_deserialisation_rejects_spoofed_mast_node_digests() {
    // Build mast for:
    //
    // pub proc k1
    //     push.1
    // end
    let (forest, node_id) =
        build_single_node_forest(vec![Operation::Push(Felt::from_u32(1))], false);
    let digest = forest[node_id].digest();

    let path = absolute_path("$kernel::k1");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("kernel"),
        version: crate::Version::new(0, 0, 0),
        digest,
        description: None,
        kind: TargetType::Kernel,
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    let (bytes, _) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-kernel-digest");
    let err = Package::read_from_bytes(&bytes)
        .expect_err("expected kernel package deserialization to reject inconsistent node digests");
    assert!(
        err.to_string().contains("invalid untrusted MAST forest"),
        "expected untrusted-MAST validation failure, got: {err}"
    );
    assert!(
        err.to_string().contains("hash mismatch for node"),
        "expected digest mismatch failure, got: {err}"
    );
}

#[cfg(feature = "std")]
#[test]
fn package_deserialize_from_file_rejects_spoofed_kernel_mast_node_digests() {
    // Build mast for:
    //
    // pub proc k1
    //     push.1
    // end
    let (forest, node_id) =
        build_single_node_forest(vec![Operation::Push(Felt::from_u32(1))], false);
    let digest = forest[node_id].digest();

    let path = absolute_path("$kernel::k1");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("kernel"),
        version: crate::Version::new(0, 0, 0),
        digest,
        description: None,
        kind: TargetType::Kernel,
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    let (bytes, _) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-kernel-digest");
    let file_path = std::env::temp_dir().join(format!(
        "miden-package-deserialize-{}-{}.masp",
        std::process::id(),
        "spoofed-kernel-digest"
    ));
    fs::write(&file_path, bytes).expect("failed to write tampered package file");

    let err = Package::deserialize_from_file(&file_path)
        .expect_err("expected file deserialization to reject inconsistent node digests");
    fs::remove_file(&file_path).unwrap();

    assert!(
        err.to_string().contains("invalid untrusted MAST forest"),
        "expected untrusted-MAST validation failure, got: {err}"
    );
    assert!(
        err.to_string().contains("hash mismatch for node"),
        "expected digest mismatch failure, got: {err}"
    );
}

#[test]
fn unchecked_kernel_package_deserialisation_accepts_spoofed_mast_node_digests() {
    // Build mast for:
    //
    // pub proc k1
    //     push.1
    // end
    let (forest, node_id) =
        build_single_node_forest(vec![Operation::Push(Felt::from_u32(1))], false);
    let digest = forest[node_id].digest();

    let path = absolute_path("$kernel::k1");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("kernel"),
        version: crate::Version::new(0, 0, 0),
        digest,
        description: None,
        kind: TargetType::Kernel,
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    let (bytes, _spoofed_digest) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-kernel-digest");
    let err = Package::read_from_bytes_unchecked(&bytes).expect_err(
        "expected unchecked kernel deserialization to reject inconsistent node digests",
    );
    assert!(
        err.to_string()
            .contains("declared node id and digest do not correspond to a procedure root"),
        "expected package manifest validation failure, got: {err}"
    );
}

fn read_usize_vint64(bytes: &[u8], offset: &mut usize) -> usize {
    // This test patches raw bytes in place, so it needs byte offsets that
    // ByteReader::read_usize does not expose.
    let first_byte = bytes.get(*offset).copied().expect("out-of-bounds vint64 peek");
    let length = first_byte.trailing_zeros() as usize + 1;

    if length == 9 {
        *offset += 1;
        let end = (*offset).checked_add(8).expect("offset overflow while reading vint64");
        let chunk: [u8; 8] = bytes[*offset..end].try_into().expect("out-of-bounds vint64");
        *offset = end;
        let value = u64::from_le_bytes(chunk);
        usize::try_from(value).expect("encoded usize does not fit host usize")
    } else {
        let end = (*offset).checked_add(length).expect("offset overflow while reading vint64");
        let mut encoded = [0u8; 8];
        encoded[..length].copy_from_slice(&bytes[*offset..end]);
        *offset = end;
        let value = u64::from_le_bytes(encoded) >> length;
        usize::try_from(value).expect("encoded usize does not fit host usize")
    }
}

fn locate_first_node_hash(bytes: &[u8]) -> (usize, usize) {
    // Header: magic[4] + flags[1] + version[3]
    let mut offset = 0usize;
    offset += 4;
    offset += 1;
    offset += 3;

    let internal_node_count = read_usize_vint64(bytes, &mut offset);
    let external_node_count = read_usize_vint64(bytes, &mut offset);
    let node_count = internal_node_count
        .checked_add(external_node_count)
        .expect("node count overflow");

    // Roots: len (usize) + elements (u32 LE)
    let roots_len = read_usize_vint64(bytes, &mut offset);
    offset += roots_len * 4;

    // Basic block data: len (usize) + bytes
    let bb_len = read_usize_vint64(bytes, &mut offset);
    offset += bb_len;

    offset += node_count * 8;
    offset += external_node_count * 32;

    (offset, internal_node_count)
}

fn build_package_bytes_with_spoofed_first_node_digest(
    lib: &Package,
    spoof_seed: &str,
) -> (Vec<u8>, Word) {
    use miden_core::serde::Serializable;

    // Serialize the MastForest normally so the byte layout is stable.
    let forest = lib.mast_forest().as_ref();
    let original_digest = forest[MastNodeId::new_unchecked(0)].digest();
    let mut output_bytes = Vec::new();
    lib.write_header_into(&mut output_bytes);
    let forest_offset = output_bytes.len();
    forest.write_into(&mut output_bytes);

    let (node_hashes_start, node_count) = locate_first_node_hash(&output_bytes[forest_offset..]);
    assert!(node_count > 0, "expected at least one node info entry");

    // Patch node 0 digest in-place.
    let spoofed_digest = miden_core::utils::hash_string_to_word(spoof_seed);
    assert_ne!(spoofed_digest, original_digest, "spoofed digest must differ");

    let mut spoofed_digest_bytes = Vec::new();
    spoofed_digest.write_into(&mut spoofed_digest_bytes);
    assert_eq!(spoofed_digest_bytes.len(), 32, "Word must serialize to 32 bytes");

    let node0_digest_offset = forest_offset + node_hashes_start;
    output_bytes[node0_digest_offset..node0_digest_offset + 32]
        .copy_from_slice(&spoofed_digest_bytes);

    lib.write_trailer_into(&mut output_bytes);

    (output_bytes, spoofed_digest)
}
