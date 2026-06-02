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

use miden_assembly_syntax::ast::{AttributeSet, PathBuf};
use miden_core::{
    Word,
    mast::{MastForest, MastNodeExt, MastNodeId, UntrustedMastForest},
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

use super::{ConstantExport, PackageId, ProcedureExport, TargetType, TypeExport};
use crate::{
    Dependency, ManifestValidationError, Package, PackageExport, PackageManifest, Section,
    debug_info::DebugSourceMastNodeId,
};

// CONSTANTS
// ================================================================================================

/// Magic string for detecting that a file is serialized [`Package`]
const MAGIC_PACKAGE: &[u8; 5] = b"MASP\0";

/// The format version.
///
/// If future modifications are made to this format, the version should be incremented by 1.
const VERSION: [u8; 3] = [5, 0, 0];

/// Byte-read budget multiplier for package deserialization from a byte slice.
///
/// The budget is intentionally finite to reject malicious length prefixes, but larger than the
/// source length because collection deserialization uses conservative per-element size estimates.
const PACKAGE_BYTE_READ_BUDGET_MULTIPLIER: usize = 64;

// PACKAGE SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Package {
    #[doc(hidden)]
    pub fn write_header_into<W: ByteWriter>(&self, target: &mut W) {
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
    }

    #[doc(hidden)]
    pub fn write_trailer_into<W: ByteWriter>(&self, target: &mut W) {
        // Write manifest
        self.manifest.write_into(target);

        // Write custom sections
        target.write_usize(self.sections.len());
        for section in self.sections.iter() {
            section.write_into(target);
        }
    }

    /// Reads a package from `source` without validating the embedded MAST forest.
    ///
    /// This is only correct when serialization and deserialization happen within the same trust
    /// domain. A typical use case is reloading bytes that were already validated before being
    /// persisted to local storage controlled by the same trusted system.
    ///
    /// Do not use this for inbound artifact processing across a trust boundary, including bytes
    /// received over the network or from another party. Authenticating the outer byte stream does
    /// not prove that embedded MAST node digests are semantically valid.
    pub fn read_from_unchecked<R: ByteReader>(
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let header = Self::read_header_from(source)?;
        let mast_forest = Self::read_mast_forest(source, false)?;
        Self::read_from_with_header_and_mast(source, header, mast_forest, true)
    }

    /// Reads a package from `bytes` without validating the embedded MAST forest.
    ///
    /// See [`Package::read_from_unchecked`].
    pub fn read_from_bytes_unchecked(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut source = SliceReader::new(bytes);
        Self::read_from_unchecked(&mut source)
    }

    fn read_mast_forest<R: ByteReader>(
        source: &mut R,
        validate_mast_forest: bool,
    ) -> Result<Arc<MastForest>, DeserializationError> {
        if validate_mast_forest {
            UntrustedMastForest::read_from(source)?.validate().map_err(|err| {
                DeserializationError::InvalidValue(format!(
                    "library contains an invalid untrusted MAST forest: {err}"
                ))
            })
        } else {
            MastForest::read_from(source)
        }
        .map(Arc::new)
    }
}

impl Serializable for Package {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.write_header_into(target);

        // Write MAST artifact
        self.mast.write_into(target);

        self.write_trailer_into(target);
    }
}

struct PackageHeader {
    name: PackageId,
    version: crate::Version,
    description: Option<String>,
    kind: TargetType,
}

impl Package {
    fn read_header_from<R: ByteReader>(
        source: &mut R,
    ) -> Result<PackageHeader, DeserializationError> {
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

        Ok(PackageHeader { name, version, description, kind })
    }

    fn read_from_with_header_and_mast<R: ByteReader>(
        source: &mut R,
        header: PackageHeader,
        mast: Arc<MastForest>,
        debug_sections_trusted: bool,
    ) -> Result<Self, DeserializationError> {
        let PackageHeader { name, version, description, kind } = header;

        // Read manifest
        let manifest = PackageManifest::read_from_safe(source, &mast)?;

        // Read custom sections
        let sections = Vec::<Section>::read_from(source)?;
        if !debug_sections_trusted && sections.iter().any(|section| section.id.is_debug()) {
            log::warn!(
                "Package read preserved debug sections from an untrusted artifact; Package::debug_info() will not expose them as trusted debug info"
            );
        }

        let mut package = Self {
            name,
            version,
            digest: Default::default(),
            description,
            kind,
            mast,
            manifest,
            sections,
            debug_sections_trusted,
        };

        package
            .recompute_mast_commitment()
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;

        Ok(package)
    }
}

impl Deserializable for Package {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = Self::read_header_from(source)?;

        // Read MAST artifact
        let mast = Self::read_mast_forest(source, true)?;

        Self::read_from_with_header_and_mast(source, header, mast, false)
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

impl PackageManifest {
    pub fn read_from_safe<R: ByteReader>(
        source: &mut R,
        mast: &MastForest,
    ) -> Result<Self, DeserializationError> {
        // Read exports
        let exports_len = source.read_usize()?;
        let max_exports = source.max_alloc(PackageExport::min_serialized_size());
        if exports_len > max_exports {
            return Err(DeserializationError::InvalidValue(format!(
                "requested {exports_len} elements but reader can provide at most {max_exports}"
            )));
        }
        let mut exports = Vec::with_capacity(exports_len);
        for _ in 0..exports_len {
            exports.push(PackageExport::read_from_safe(source, mast)?);
        }

        // Read dependencies
        let dependencies = Vec::<Dependency>::read_from(source)?;

        PackageManifest::new(exports)
            .and_then(|manifest| manifest.with_dependencies(dependencies))
            .map_err(|error| DeserializationError::InvalidValue(error.to_string()))
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

impl PackageExport {
    pub fn read_from_safe<R: ByteReader>(
        source: &mut R,
        mast: &MastForest,
    ) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            1 => ProcedureExport::read_from_safe(source, mast).map(Self::Procedure),
            2 => ConstantExport::read_from(source).map(Self::Constant),
            3 => TypeExport::read_from(source).map(Self::Type),
            invalid => Err(DeserializationError::InvalidValue(format!(
                "unexpected PackageExport tag: '{invalid}'"
            ))),
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
        if let Some(node_id) = self.node {
            target.write_bool(true);
            target.write_u32(node_id.into());
        } else {
            target.write_bool(false);
        }
        if let Some(source_node) = self.source_node {
            target.write_bool(true);
            source_node.write_into(target);
        } else {
            target.write_bool(false);
        }
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

impl ProcedureExport {
    pub fn read_from_safe<R: ByteReader>(
        source: &mut R,
        mast: &MastForest,
    ) -> Result<Self, DeserializationError> {
        use miden_assembly_syntax::ast::types::FunctionType;
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let node = if source.read_bool()? {
            let node_id = MastNodeId::from_u32_safe(source.read_u32()?, mast)?;
            if !mast.is_procedure_root(node_id) {
                return Err(DeserializationError::InvalidValue(
                    ManifestValidationError::InvalidProcedureExport { path }.to_string(),
                ));
            }
            Some(node_id)
        } else {
            None
        };
        let source_node = if source.read_bool()? {
            Some(DebugSourceMastNodeId::read_from(source)?)
        } else {
            None
        };
        let digest = Word::read_from(source)?;
        // Ensure that the digest associated with `node` matches the provided digest
        if let Some(node) = node
            && digest != mast[node].digest()
        {
            return Err(DeserializationError::InvalidValue(
                ManifestValidationError::InvalidProcedureExport { path }.to_string(),
            ));
        }
        let signature = if source.read_bool()? {
            Some(FunctionType::read_from(source)?)
        } else {
            None
        };
        let attributes = AttributeSet::read_from(source)?;
        Ok(Self {
            path,
            node,
            source_node,
            digest,
            signature,
            attributes,
        })
    }
}

impl Deserializable for ProcedureExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use miden_assembly_syntax::ast::types::FunctionType;
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let node = if source.read_bool()? {
            Some(MastNodeId::new_unchecked(source.read_u32()?))
        } else {
            None
        };
        let source_node = if source.read_bool()? {
            Some(DebugSourceMastNodeId::read_from(source)?)
        } else {
            None
        };
        let digest = Word::read_from(source)?;
        let signature = if source.read_bool()? {
            Some(FunctionType::read_from(source)?)
        } else {
            None
        };
        let attributes = AttributeSet::read_from(source)?;
        Ok(Self {
            path,
            node,
            source_node,
            digest,
            signature,
            attributes,
        })
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
        string::{String, ToString},
        sync::Arc,
        vec,
        vec::Vec,
    };
    use std::collections::BTreeMap;

    use miden_assembly_syntax::ast::{Path as AstPath, PathBuf};
    use miden_core::{
        Felt, Word,
        advice::AdviceMap,
        assert_matches,
        mast::{
            BasicBlockNodeBuilder, MastForest, MastForestContributor, MastNode, MastNodeExt,
            MastNodeId,
        },
        operations::Operation,
        serde::{
            BudgetedReader, ByteWriter, Deserializable, DeserializationError, Serializable,
            SliceReader,
        },
        utils::IndexVec,
    };

    use super::{
        MAGIC_PACKAGE, PACKAGE_BYTE_READ_BUDGET_MULTIPLIER, Package, PackageManifest, Section,
        VERSION,
    };
    use crate::{
        Dependency, ManifestValidationError, PackageDebugInfoError, PackageExport, PackageId,
        ProcedureExport, SectionId, TargetType,
        debug_info::{
            DEBUG_SOURCE_GRAPH_VERSION, DebugSourceAsmOp, DebugSourceGraphSection,
            DebugSourceMapSection, DebugSourceMastNode, DebugSourceMastNodeId,
        },
    };

    fn build_forest() -> (MastForest, MastNodeId) {
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
        forest.make_root(node_id);
        (forest, node_id)
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
        let source_node = DebugSourceMastNodeId::from(0);

        let mast = Arc::new(
            MastForest::from_raw_parts(nodes, vec![node_id], AdviceMap::default())
                .expect("forest should be valid"),
        );
        let path = absolute_path("test::proc");
        let exports = vec![PackageExport::Procedure(
            ProcedureExport::new(path, Some(node_id), digest, None)
                .with_source_node(Some(source_node)),
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
        let source_graph = DebugSourceGraphSection {
            version: DEBUG_SOURCE_GRAPH_VERSION,
            nodes: vec![DebugSourceMastNode::new(node_id, Vec::new(), 0, 1)],
            roots: vec![source_node],
        };
        let source_map = DebugSourceMapSection {
            asm_ops: vec![DebugSourceAsmOp::new(
                source_node,
                0,
                None,
                "trusted".into(),
                "add".into(),
                1,
            )],
            ..DebugSourceMapSection::new()
        };
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
                prop_assert_eq!(bytes, deserialized.to_bytes());
                Ok(())
            })
            .unwrap_or_else(|err| {
                panic!("{err}");
            });
    }

    #[test]
    fn package_checked_deserialization_strips_forest_debug_but_preserves_sections() {
        let package = build_package_with_debug_info();
        let bytes = package.to_bytes();

        let deserialized = Package::read_from_bytes(&bytes).unwrap();

        assert!(
            deserialized
                .sections
                .iter()
                .any(|section| section.id == SectionId::DEBUG_SOURCE_MAP)
        );
        assert!(matches!(
            deserialized.debug_info(),
            Err(PackageDebugInfoError::UntrustedSections)
        ));
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
        // This fuzz payload encodes counts large enough to cause excessive allocation or read work.
        // If this starts succeeding, package byte-slice deserialization is no longer budgeted.
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
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
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
            PackageExport::Procedure(ProcedureExport::new(
                path.clone(),
                None,
                Word::default(),
                None,
            )),
            PackageExport::Procedure(ProcedureExport::new(
                path.clone(),
                None,
                Word::default(),
                None,
            )),
        ];

        let err = PackageManifest::new(exports)
            .expect_err("duplicate export paths should be rejected by constructors");
        assert_matches!(err, ManifestValidationError::DuplicateExport(err_path) if err_path == path);
    }

    #[test]
    fn package_manifest_add_dependency_rejects_duplicate_dependencies() {
        let mut manifest = PackageManifest {
            exports: Default::default(),
            dependencies: Default::default(),
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
        let export =
            PackageExport::Procedure(ProcedureExport::new(path, None, Word::default(), None));

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

    #[test]
    fn package_manifest_deserialization_rejects_malformed_quoted_procedure_leaf() {
        let bad = Arc::<AstPath>::from(AstPath::validate(r#"::foo::"bad name""#).unwrap());
        let exports = BTreeMap::from_iter([(
            bad.clone(),
            PackageExport::Procedure(ProcedureExport::new(bad, None, Default::default(), None)),
        )]);

        let manifest = PackageManifest {
            exports,
            dependencies: Default::default(),
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
            dependencies: Default::default(),
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
            dependencies: Default::default(),
        };

        let bytes = manifest.to_bytes();

        let err = PackageManifest::read_from_bytes(&bytes).expect_err(
            "expected malformed type export leaf name rejection during deserialization",
        );
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
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(1))])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
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
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(1))])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
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
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(1))])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
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
        let err = Package::read_from_bytes(&bytes).expect_err(
            "expected kernel package deserialization to reject inconsistent node digests",
        );
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
        let mut forest = MastForest::new();
        let node_id = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(1))])
            .add_to_forest(&mut forest)
            .expect("failed to build basic block");
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

        // Serialize the MastForest in stripped form so the byte layout is minimal and stable.
        let forest = lib.mast_forest().as_ref();
        let original_digest = forest[MastNodeId::new_unchecked(0)].digest();
        let mut output_bytes = Vec::new();
        lib.write_header_into(&mut output_bytes);
        let forest_offset = output_bytes.len();
        forest.write_stripped(&mut output_bytes);

        let (node_hashes_start, node_count) =
            locate_first_node_hash(&output_bytes[forest_offset..]);
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
}
