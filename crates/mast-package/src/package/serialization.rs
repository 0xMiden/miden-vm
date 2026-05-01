//! The serialization format of `Package` is as follows:
//!
//! #### Header
//! - `MAGIC_PACKAGE`, a 4-byte tag, followed by a NUL-byte, i.e. `b"\0"`
//! - `VERSION`, a 3-byte semantic version number, 1 byte for each component, i.e. MAJ.MIN.PATCH
//!
//! #### Metadata
//! - `name` (`String`)
//! - `version` ([`miden_assembly_syntax::Version`] serialized as a `String`)
//! - `description` (optional, `String`)
//! - `kind` (`u8`, see [`crate::TargetType`])
//!
//! #### Code
//! - `mast` (see [`miden_assembly_syntax::Library`])
//!
//! #### Manifest
//! - `manifest` (see [`crate::PackageManifest`])
//!
//! #### Custom Sections
//! - `sections` (a vector of zero or more [`crate::Section`])

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{
    Library,
    ast::{AttributeSet, PathBuf},
};
use miden_core::{
    Word,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

use super::{ConstantExport, PackageId, ProcedureExport, TargetType, TypeExport};
use crate::{Dependency, Package, PackageExport, PackageManifest, Section};

// CONSTANTS
// ================================================================================================

/// Magic string for detecting that a file is serialized [`Package`]
const MAGIC_PACKAGE: &[u8; 5] = b"MASP\0";

/// The format version.
///
/// If future modifications are made to this format, the version should be incremented by 1.
const VERSION: [u8; 3] = [4, 0, 0];

/// Byte-read budget multiplier for package deserialization from a byte slice.
///
/// The budget is intentionally finite to reject malicious length prefixes, but larger than the
/// source length because collection deserialization uses conservative per-element size estimates.
const PACKAGE_BYTE_READ_BUDGET_MULTIPLIER: usize = 64;

// PACKAGE SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for Package {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write magic & version
        target.write_bytes(MAGIC_PACKAGE);
        target.write_bytes(&VERSION);

        // Write package name
        self.name.write_into(target);

        // Write package version
        self.version.to_string().write_into(target);

        // Write package description
        self.description.write_into(target);

        // Write package kind
        target.write_u8(self.kind.into());

        // Write MAST artifact
        self.mast.write_into(target);

        // Write manifest
        self.manifest.write_into(target);

        // Write custom sections
        target.write_usize(self.sections.len());
        for section in self.sections.iter() {
            section.write_into(target);
        }
    }
}

impl Deserializable for Package {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read and validate magic & version
        let magic: [u8; 5] = source.read_array()?;
        if magic != *MAGIC_PACKAGE {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid magic bytes. Expected '{MAGIC_PACKAGE:?}', got '{magic:?}'"
            )));
        }

        let version: [u8; 3] = source.read_array()?;
        if version != VERSION {
            return Err(DeserializationError::InvalidValue(format!(
                "unsupported version. Got '{version:?}', but only '{VERSION:?}' is supported"
            )));
        }

        // Read package name
        let name = PackageId::read_from(source)?;

        // Read package version
        let version = String::read_from(source)?
            .parse::<crate::Version>()
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

        // Read package description
        let description = Option::<String>::read_from(source)?;

        // Read package kind
        let kind_tag = source.read_u8()?;
        let kind = TargetType::try_from(kind_tag)
            .map_err(|e| DeserializationError::InvalidValue(e.to_string()))?;

        // Read MAST artifact
        let mast = Arc::new(Library::read_from(source)?);

        // Read manifest
        let manifest = PackageManifest::read_from(source)?;

        // Read custom sections
        let sections = Vec::<Section>::read_from(source)?;

        Ok(Self {
            name,
            version,
            description,
            kind,
            mast,
            manifest,
            sections,
        })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let budget = bytes.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        Self::read_from(&mut reader)
    }
}

// PACKAGE MANIFEST SERIALIZATION/DESERIALIZATION
// ================================================================================================

#[cfg(feature = "serde")]
impl serde::Serialize for PackageManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use alloc::collections::BTreeMap;

        use miden_assembly_syntax::Path;
        use serde::ser::SerializeStruct;

        struct PackageExports<'a>(&'a BTreeMap<Arc<Path>, PackageExport>);

        impl serde::Serialize for PackageExports<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;

                let mut serializer = serializer.serialize_seq(Some(self.0.len()))?;
                for value in self.0.values() {
                    serializer.serialize_element(value)?;
                }
                serializer.end()
            }
        }

        let mut serializer = serializer.serialize_struct("PackageManifest", 2)?;
        serializer.serialize_field("exports", &PackageExports(&self.exports))?;
        serializer.serialize_field("dependencies", &self.dependencies)?;
        serializer.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PackageManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Exports,
            Dependencies,
        }

        struct PackageManifestVisitor;

        impl<'de> serde::de::Visitor<'de> for PackageManifestVisitor {
            type Value = PackageManifest;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct PackageManifest")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let exports = seq
                    .next_element::<Vec<PackageExport>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let dependencies = seq
                    .next_element::<Vec<Dependency>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                PackageManifest::new(exports)
                    .and_then(|manifest| manifest.with_dependencies(dependencies))
                    .map_err(serde::de::Error::custom)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut exports = None;
                let mut dependencies = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Exports => {
                            if exports.is_some() {
                                return Err(serde::de::Error::duplicate_field("exports"));
                            }
                            exports = Some(map.next_value::<Vec<PackageExport>>()?);
                        },
                        Field::Dependencies => {
                            if dependencies.is_some() {
                                return Err(serde::de::Error::duplicate_field("dependencies"));
                            }
                            dependencies = Some(map.next_value::<Vec<Dependency>>()?);
                        },
                    }
                }
                let exports = exports.ok_or_else(|| serde::de::Error::missing_field("exports"))?;
                let dependencies =
                    dependencies.ok_or_else(|| serde::de::Error::missing_field("dependencies"))?;
                PackageManifest::new(exports)
                    .and_then(|manifest| manifest.with_dependencies(dependencies))
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_struct(
            "PackageManifest",
            &["exports", "dependencies"],
            PackageManifestVisitor,
        )
    }
}

impl Serializable for PackageManifest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write exports
        target.write_usize(self.num_exports());
        for export in self.exports() {
            export.write_into(target);
        }

        // Write dependencies
        target.write_usize(self.num_dependencies());
        for dep in self.dependencies() {
            dep.write_into(target);
        }
    }
}

impl Deserializable for PackageManifest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read exports
        let exports_len = source.read_usize()?;
        let exports = source.read_many_iter(exports_len)?.collect::<Result<Vec<_>, _>>()?;

        // Read dependencies
        let dependencies = Vec::<Dependency>::read_from(source)?;

        PackageManifest::new(exports)
            .and_then(|manifest| manifest.with_dependencies(dependencies))
            .map_err(|error| DeserializationError::InvalidValue(error.to_string()))
    }
}

// PACKAGE EXPORT SERIALIZATION/DESERIALIZATION
// ================================================================================================
impl Serializable for PackageExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.tag());
        match self {
            Self::Procedure(export) => export.write_into(target),
            Self::Constant(export) => export.write_into(target),
            Self::Type(export) => export.write_into(target),
        }
    }
}

impl Deserializable for PackageExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            1 => ProcedureExport::read_from(source).map(Self::Procedure),
            2 => ConstantExport::read_from(source).map(Self::Constant),
            3 => TypeExport::read_from(source).map(Self::Type),
            invalid => Err(DeserializationError::InvalidValue(format!(
                "unexpected PackageExport tag: '{invalid}'"
            ))),
        }
    }
}

impl Serializable for ProcedureExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.path.write_into(target);
        self.digest.write_into(target);
        match self.signature.as_ref() {
            Some(sig) => {
                target.write_bool(true);
                sig.write_into(target);
            },
            None => {
                target.write_bool(false);
            },
        }
        self.attributes.write_into(target);
    }
}

impl Deserializable for ProcedureExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use miden_assembly_syntax::ast::types::FunctionType;
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let digest = Word::read_from(source)?;
        let signature = if source.read_bool()? {
            Some(FunctionType::read_from(source)?)
        } else {
            None
        };
        let attributes = AttributeSet::read_from(source)?;
        Ok(Self { path, digest, signature, attributes })
    }
}

impl Serializable for ConstantExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.path.write_into(target);
        self.value.write_into(target);
    }
}

impl Deserializable for ConstantExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let value = miden_assembly_syntax::ast::ConstantValue::read_from(source)?;
        Ok(Self { path, value })
    }
}

impl Serializable for TypeExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.path.write_into(target);
        self.ty.write_into(target);
    }
}

impl Deserializable for TypeExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use miden_assembly_syntax::ast::types::Type;
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let ty = Type::read_from(source)?;
        Ok(Self { path, ty })
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        collections::BTreeMap,
        string::{String, ToString},
        sync::Arc,
        vec,
        vec::Vec,
    };

    use miden_assembly_syntax::{
        Library,
        ast::{AttributeSet, Path as AstPath, PathBuf},
        library::{LibraryExport, ProcedureExport as LibraryProcedureExport},
    };
    use miden_core::{
        Word,
        mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, MastNodeExt, MastNodeId},
        operations::Operation,
        serde::{
            BudgetedReader, ByteWriter, Deserializable, DeserializationError, Serializable,
            SliceReader,
        },
    };
    #[cfg(feature = "serde")]
    use serde_json::{json, to_value};

    use super::{
        MAGIC_PACKAGE, PACKAGE_BYTE_READ_BUDGET_MULTIPLIER, Package, PackageExport,
        PackageManifest, Section, VERSION,
    };
    use crate::{
        Dependency, ManifestValidationError, PackageId, SectionId, TargetType,
        package::manifest::ProcedureExport as PackageProcedureExport,
    };

    fn build_forest() -> (MastForest, MastNodeId) {
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        forest.make_root(node_id);
        (forest, node_id)
    }

    fn absolute_path(name: &str) -> Arc<AstPath> {
        let path = PathBuf::new(name).expect("invalid path");
        let path = path.as_path().to_absolute().into_owned();
        Arc::from(path.into_boxed_path())
    }

    fn build_library() -> Arc<Library> {
        let (forest, node_id) = build_forest();
        let path = absolute_path("test::proc");
        let export = LibraryProcedureExport::new(node_id, Arc::clone(&path));

        let mut exports = BTreeMap::new();
        exports.insert(path, LibraryExport::Procedure(export));

        Arc::new(Library::new(Arc::new(forest), exports).expect("failed to build library"))
    }

    fn build_package() -> Package {
        let library = build_library();
        let path = absolute_path("test::proc");
        let node_id = library.get_export_node_id(path.as_ref());
        let digest = library.mast_forest()[node_id].digest();

        let export = PackageExport::Procedure(PackageProcedureExport {
            path: Arc::clone(&path),
            digest,
            signature: None,
            attributes: AttributeSet::default(),
        });

        let manifest =
            PackageManifest::new([export]).expect("test package manifest should be valid");

        Package {
            name: PackageId::from("test_pkg"),
            version: crate::Version::new(0, 0, 0),
            description: None,
            kind: TargetType::Library,
            mast: library,
            manifest,
            sections: Vec::new(),
        }
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
        let payload = [
            0x4d, 0x41, 0x53, 0x50, 0x00, 0x04, 0x00, 0x00, 0x11, 0x74, 0x65, 0x73, 0x74, 0x5f,
            0x70, 0x6b, 0x67, 0x0b, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00, 0x4d, 0x41, 0x53,
            0x54, 0x00, 0x00, 0x00, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x17, 0x03, 0x22,
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x30, 0x2f, 0x08, 0x0a, 0x21, 0xa9, 0xb6, 0xf6, 0x1a, 0x52, 0x30, 0xc5,
            0x64, 0xc7, 0xdb, 0x4d, 0x83, 0x0b, 0x32, 0x58, 0x89, 0x88, 0xb2, 0x78, 0x69, 0xbb,
            0x23, 0xa6, 0x18, 0x9c, 0xc9, 0x35, 0x2d, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x00, 0x0c, 0x00, 0x3a, 0x3a, 0x74, 0x65, 0x73,
            0x74, 0x3a, 0x3a, 0x70, 0x72, 0x6f, 0x63, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03,
            0x0f, 0x03, 0x0f, 0x01, 0x00, 0x00, 0x17, 0x03, 0x22, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x9c, 0xc9, 0x35, 0x2d, 0x01, 0x00, 0x03, 0x0f, 0x03,
            0x0f, 0x01, 0x01, 0x01,
        ];

        let result = Package::read_from_bytes(&payload);
        assert!(result.is_err());

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

    #[test]
    fn package_manifest_new_rejects_duplicate_export_paths() {
        let library = build_library();
        let path = absolute_path("test::proc");
        let node_id = library.get_export_node_id(path.as_ref());
        let digest = library.mast_forest()[node_id].digest();
        let export = PackageExport::Procedure(PackageProcedureExport {
            path: path.clone(),
            digest,
            signature: None,
            attributes: AttributeSet::default(),
        });

        let err = PackageManifest::new([export.clone(), export])
            .expect_err("duplicate export paths should be rejected by constructors");
        assert_eq!(err, ManifestValidationError::DuplicateExport(path));
    }

    #[test]
    fn package_manifest_add_dependency_rejects_duplicate_dependencies() {
        let mut manifest =
            PackageManifest::new([]).expect("empty package manifest should be valid");
        let dependency = build_dependency();

        manifest
            .add_dependency(dependency.clone())
            .expect("first dependency should be accepted");
        let err = manifest
            .add_dependency(dependency)
            .expect_err("duplicate dependencies should be rejected by helpers");
        assert_eq!(err, ManifestValidationError::DuplicateDependency(PackageId::from("dep")));
    }

    #[test]
    fn package_manifest_rejects_duplicate_export_paths() {
        let library = build_library();
        let path = absolute_path("test::proc");
        let node_id = library.get_export_node_id(path.as_ref());
        let digest = library.mast_forest()[node_id].digest();
        let export = PackageExport::Procedure(PackageProcedureExport {
            path,
            digest,
            signature: None,
            attributes: AttributeSet::default(),
        });

        let mut bytes = Vec::new();
        bytes.write_usize(2);
        export.write_into(&mut bytes);
        export.write_into(&mut bytes);
        bytes.write_usize(0);

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
        bytes.write_usize(2);
        dependency.write_into(&mut bytes);
        dependency.write_into(&mut bytes);

        let mut reader = SliceReader::new(&bytes);
        let err = PackageManifest::read_from(&mut reader)
            .expect_err("duplicate dependencies should be rejected during deserialization");
        assert!(matches!(err, DeserializationError::InvalidValue(_)));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_package_manifest_rejects_duplicate_export_paths() {
        let library = build_library();
        let path = absolute_path("test::proc");
        let node_id = library.get_export_node_id(path.as_ref());
        let digest = library.mast_forest()[node_id].digest();
        let export = PackageExport::Procedure(PackageProcedureExport {
            path,
            digest,
            signature: None,
            attributes: AttributeSet::default(),
        });
        let export = to_value(&export).expect("export should serialize");

        let manifest = serde_json::to_string(&json!({
            "exports": [export.clone(), export],
            "dependencies": [],
        }))
        .expect("manifest should serialize to JSON");
        let err = serde_json::from_str::<PackageManifest>(&manifest)
            .expect_err("serde deserialization should reject duplicate export paths");
        let message = err.to_string();
        assert!(message.contains("duplicate export path"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_package_manifest_rejects_duplicate_dependencies() {
        let dependency = to_value(build_dependency()).expect("dependency should serialize");

        let manifest = serde_json::to_string(&json!({
            "exports": [],
            "dependencies": [dependency.clone(), dependency],
        }))
        .expect("manifest should serialize to JSON");
        let err = serde_json::from_str::<PackageManifest>(&manifest)
            .expect_err("serde deserialization should reject duplicate dependencies");
        let message = err.to_string();
        assert!(message.contains("duplicate dependency"));
    }
}
