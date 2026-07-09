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
//!
//! #### Reader trust policy
//!
//! Package deserialization has two independently important trust decisions:
//!
//! - whether the embedded [`MastForest`] must be recomputed and validated;
//! - whether package-owned debug sections may be exposed to callers.
//!
//! [`Package::read_from`] and [`Package::read_from_bytes`] are the normal untrusted readers. They
//! validate the embedded MAST forest and discard package-owned debug sections before returning the
//! package. Use them for bytes received across a trust boundary.
//!
//! [`Package::read_from_trusted`] and [`Package::read_from_bytes_trusted`] are for local
//! files/cache entries controlled by the same trusted build or execution system. They validate the
//! embedded MAST forest, but preserve package-owned debug sections so [`Package::debug_info`] can
//! decode them.
//!
//! [`Package::read_from_unchecked`] and [`Package::read_from_bytes_unchecked`] are also trusted
//! same-domain readers, but skip MAST validation. Use them only for bytes that were already
//! validated before being persisted by the same trusted system.
//!
//! Embedded kernel package bytes are stored in the opaque `kernel` custom section. Untrusted
//! package reads may carry those bytes, but decoding the embedded kernel through the package API
//! uses the untrusted reader and therefore strips any nested package-owned debug sections.

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::ast::{self, AttributeSet, PathBuf};
use miden_core::{
    Word,
    mast::{MastForest, MastNodeExt, MastNodeId, UntrustedMastForest},
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

use super::{
    ConstantExport, PackageId, PackageModule, PackageSubmodule, ProcedureExport, TargetType,
    TypeExport,
};
use crate::{
    Dependency, ManifestValidationError, Package, PackageExport, PackageManifest, Section,
    debug_info::DebugSourceNodeId,
};

// CONSTANTS
// ================================================================================================

/// Magic string for detecting that a file is serialized [`Package`]
const MAGIC_PACKAGE: &[u8; 5] = b"MASP\0";

/// The format version.
///
/// If future modifications are made to this format, the version should be incremented by 1.
const VERSION: [u8; 3] = [6, 0, 0];

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

    /// Reads a trusted package from `source` without validating the embedded MAST forest.
    ///
    /// # Trust boundary
    ///
    /// This skips embedded MAST validation and trusts serialized node digests. Use it only for
    /// bytes that were already validated before being persisted by the same trusted system.
    ///
    /// Do not use this for user-controlled packages, network input, registry artifacts, or any
    /// other package that crosses a trust boundary. Use [`Package::read_from`] for those
    /// inputs.
    pub fn read_from_unchecked<R: ByteReader>(
        source: &mut R,
    ) -> Result<Self, DeserializationError> {
        let header = Self::read_header_from(source)?;
        let mast_forest = Self::read_mast_forest(source, false)?;
        Self::read_from_with_header_and_mast(source, header, mast_forest, true)
    }

    /// Reads trusted package bytes without validating the embedded MAST forest.
    ///
    /// # Trust boundary
    ///
    /// This skips embedded MAST validation and trusts serialized node digests. Use it only for
    /// bytes that were already validated before being persisted by the same trusted system.
    ///
    /// Do not use this for user-controlled packages, network input, registry artifacts, or any
    /// other package that crosses a trust boundary. Use [`Package::read_from_bytes`] for those
    /// inputs.
    pub fn read_from_bytes_unchecked(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut source = SliceReader::new(bytes);
        Self::read_from_unchecked(&mut source)
    }

    /// Reads a trusted local package while validating the embedded MAST forest.
    ///
    /// This keeps the same structural validation as [`Package::read_from`], but allows
    /// package-owned debug sections to be decoded as trusted metadata. Use this only for local
    /// files or cache artifacts controlled by this process or build system. Do not use this for
    /// inbound artifacts from an untrusted channel; use [`Package::read_from`] instead so debug
    /// sections are discarded before the package is exposed to callers.
    pub fn read_from_trusted<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = Self::read_header_from(source)?;
        let mast_forest = Self::read_mast_forest(source, true)?;
        Self::read_from_with_header_and_mast(source, header, mast_forest, true)
    }

    /// Reads trusted local package bytes while validating the embedded MAST forest.
    ///
    /// See [`Package::read_from_trusted`].
    pub fn read_from_bytes_trusted(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let budget = bytes.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        Self::read_from_trusted(&mut reader)
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
        let mut sections = Vec::<Section>::read_from(source)?;
        if !debug_sections_trusted && sections.iter().any(|section| section.id.is_debug()) {
            log::warn!(
                "Package read ignored debug sections from an untrusted artifact; use Package::read_from_trusted for local cache/debug reads"
            );
            sections.retain(|section| !section.id.is_debug());
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
            .compute_interface_digest()
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
        package.recompute_mast_commitment();

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

        struct PackageModules<'a>(&'a BTreeMap<Arc<Path>, PackageModule>);

        impl serde::Serialize for PackageModules<'_> {
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

        let mut serializer = serializer.serialize_struct("PackageManifest", 4)?;
        serializer.serialize_field("exports", &PackageExports(&self.exports))?;
        serializer.serialize_field("modules", &PackageModules(&self.modules))?;
        serializer.serialize_field("dependencies", &self.dependencies)?;
        serializer.serialize_field("entrypoint", &self.entrypoint)?;
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
            Modules,
            Dependencies,
            Entrypoint,
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
                let modules = seq
                    .next_element::<Vec<PackageModule>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let dependencies = seq
                    .next_element::<Vec<Dependency>>()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let entrypoint = seq
                    .next_element::<Option<PathBuf>>()
                    .map(|p| p.map(|p| p.map(Arc::<ast::Path>::from)))?;
                PackageManifest::new(exports)
                    .and_then(|manifest| manifest.with_modules(modules))
                    .and_then(|manifest| manifest.with_dependencies(dependencies))
                    .and_then(|manifest| {
                        if let Some(Some(entrypoint)) = entrypoint {
                            manifest.with_entrypoint(entrypoint)
                        } else {
                            Ok(manifest)
                        }
                    })
                    .map_err(serde::de::Error::custom)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut exports = None;
                let mut modules = None;
                let mut dependencies = None;
                let mut entrypoint = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Exports => {
                            if exports.is_some() {
                                return Err(serde::de::Error::duplicate_field("exports"));
                            }
                            exports = Some(map.next_value::<Vec<PackageExport>>()?);
                        },
                        Field::Modules => {
                            if modules.is_some() {
                                return Err(serde::de::Error::duplicate_field("modules"));
                            }
                            modules = Some(map.next_value::<Vec<PackageModule>>()?);
                        },
                        Field::Dependencies => {
                            if dependencies.is_some() {
                                return Err(serde::de::Error::duplicate_field("dependencies"));
                            }
                            dependencies = Some(map.next_value::<Vec<Dependency>>()?);
                        },
                        Field::Entrypoint => {
                            if entrypoint.is_some() {
                                return Err(serde::de::Error::duplicate_field("entrypoint"));
                            }
                            entrypoint = Some(
                                map.next_value::<Option<PathBuf>>()
                                    .map(|p| p.map(Arc::<ast::Path>::from))?,
                            );
                        },
                    }
                }
                let exports = exports.ok_or_else(|| serde::de::Error::missing_field("exports"))?;
                let modules = modules.ok_or_else(|| serde::de::Error::missing_field("modules"))?;
                let dependencies =
                    dependencies.ok_or_else(|| serde::de::Error::missing_field("dependencies"))?;
                PackageManifest::new(exports)
                    .and_then(|manifest| manifest.with_modules(modules))
                    .and_then(|manifest| manifest.with_dependencies(dependencies))
                    .and_then(|manifest| {
                        if let Some(Some(entrypoint)) = entrypoint {
                            manifest.with_entrypoint(entrypoint)
                        } else {
                            Ok(manifest)
                        }
                    })
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_struct(
            "PackageManifest",
            &["exports", "modules", "dependencies", "entrypoint"],
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

        // Write module surfaces
        target.write_usize(self.num_modules());
        for module in self.modules() {
            module.write_into(target);
        }

        // Write dependencies
        target.write_usize(self.num_dependencies());
        for dep in self.dependencies() {
            dep.write_into(target);
        }

        // Write entrypoint
        if let Some(entrypoint) = self.entrypoint.as_ref() {
            target.write_bool(true);
            entrypoint.write_into(target);
        } else {
            target.write_bool(false);
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

        // Read module surfaces
        let modules_len = source.read_usize()?;
        let max_modules = source.max_alloc(PackageModule::min_serialized_size());
        if modules_len > max_modules {
            return Err(DeserializationError::InvalidValue(format!(
                "requested {modules_len} elements but reader can provide at most {max_modules}"
            )));
        }
        let modules = source.read_many_iter(modules_len)?.collect::<Result<Vec<_>, _>>()?;

        // Read dependencies
        let dependencies = Vec::<Dependency>::read_from(source)?;

        // Read entrypoint
        let entrypoint = if source.read_bool()? {
            Some(PathBuf::read_from(source).map(Arc::<ast::Path>::from)?)
        } else {
            None
        };

        PackageManifest::new(exports)
            .and_then(|manifest| manifest.with_modules(modules))
            .and_then(|manifest| manifest.with_dependencies(dependencies))
            .and_then(|manifest| {
                if let Some(entrypoint) = entrypoint {
                    manifest.with_entrypoint(entrypoint)
                } else {
                    Ok(manifest)
                }
            })
            .map_err(|error| DeserializationError::InvalidValue(error.to_string()))
    }
}

impl Deserializable for PackageManifest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read exports
        let exports_len = source.read_usize()?;
        let exports = source.read_many_iter(exports_len)?.collect::<Result<Vec<_>, _>>()?;

        // Read module surfaces
        let modules_len = source.read_usize()?;
        let modules = source.read_many_iter(modules_len)?.collect::<Result<Vec<_>, _>>()?;

        // Read dependencies
        let dependencies = Vec::<Dependency>::read_from(source)?;

        // Read entrypoint
        let entrypoint = if source.read_bool()? {
            Some(PathBuf::read_from(source).map(Arc::<ast::Path>::from)?)
        } else {
            None
        };

        PackageManifest::new(exports)
            .and_then(|manifest| manifest.with_modules(modules))
            .and_then(|manifest| manifest.with_dependencies(dependencies))
            .and_then(|manifest| {
                if let Some(entrypoint) = entrypoint {
                    manifest.with_entrypoint(entrypoint)
                } else {
                    Ok(manifest)
                }
            })
            .map_err(|error| DeserializationError::InvalidValue(error.to_string()))
    }
}

// PACKAGE MODULE SURFACE SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for PackageModule {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.path.write_into(target);
        target.write_usize(self.submodules.len());
        for submodule in self.submodules.iter() {
            submodule.write_into(target);
        }
    }
}

impl Deserializable for PackageModule {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let submodules = Vec::<PackageSubmodule>::read_from(source)?;
        Ok(Self { path, submodules })
    }
}

impl Serializable for PackageSubmodule {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.name.write_into(target);
    }
}

impl Deserializable for PackageSubmodule {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name = ast::Ident::read_from(source)?;
        Ok(Self { name })
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
            Some(DebugSourceNodeId::read_from(source)?)
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
            Some(DebugSourceNodeId::read_from(source)?)
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
        let value = ast::ConstantValue::read_from(source)?;
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
mod tests;
