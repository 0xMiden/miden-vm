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
//! validate the embedded MAST forest and package-owned debug information before returning the
//! package. Use them for bytes received across a trust boundary.
//!
//! [`Package::read_from_trusted`] and [`Package::read_from_bytes_trusted`] are for local
//! files/cache entries controlled by the same trusted build or execution system. They preserve
//! package-owned debug sections and skip embedded MAST and manifest cross-check validation.
//!
//! Embedded kernel package bytes are stored in the opaque `kernel` custom section. Decoding an
//! embedded kernel through the package API uses the untrusted reader, so nested package-owned debug
//! information is validated and retained under the same policy.

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

#[cfg(test)]
mod tests;

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

    /// Reads a package from trusted storage without validating the embedded MAST forest.
    ///
    /// # Trust boundary
    ///
    /// This skips embedded MAST and manifest cross-check validation and trusts serialized node
    /// digests. Use it for a package written and retained by the same trusted system, such as a
    /// local build cache.
    ///
    /// Do not use this for user-controlled packages, network input, or any other package that
    /// crosses a trust boundary. Use [`Package::read_from`] for those inputs.
    #[track_caller]
    pub fn read_from_trusted<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = Self::read_header_from(source)?;
        let mast_forest = Self::read_mast_forest(source, false)?;
        Self::read_from_with_header_and_mast(source, header, mast_forest, false, false)
    }

    /// Reads package bytes from trusted storage without validating the embedded MAST forest.
    ///
    /// # Trust boundary
    ///
    /// This skips embedded MAST and manifest cross-check validation and trusts serialized node
    /// digests. Use it for a package written and retained by the same trusted system, such as a
    /// local build cache. This method still applies the finite byte-read budget used by
    /// [`Package::read_from_bytes`].
    ///
    /// Do not use this for user-controlled packages, network input, or any other package that
    /// crosses a trust boundary. Use [`Package::read_from_bytes`] for those inputs.
    #[track_caller]
    pub fn read_from_bytes_trusted(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let budget = bytes.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        Self::read_from_trusted(&mut reader)
    }

    #[track_caller]
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
        validate_manifest: bool,
        validate_debug_sections: bool,
    ) -> Result<Self, DeserializationError> {
        let PackageHeader { name, version, description, kind } = header;

        // Read manifest
        let manifest = if validate_manifest {
            PackageManifest::read_from_safe(source, &mast)?
        } else {
            PackageManifest::read_from_trusted(source, &mast)?
        };

        // Read custom sections
        let sections = Vec::<Section>::read_from(source)?;

        let mut package = Self {
            name,
            version,
            digest: Default::default(),
            description,
            kind,
            mast,
            manifest,
            sections,
            debug_sections_trusted: true,
        };

        if validate_debug_sections {
            package.debug_info().map_err(|err| {
                DeserializationError::InvalidValue(format!(
                    "package contains invalid debug information: {err}"
                ))
            })?;
        }

        if validate_manifest {
            package
                .compute_interface_digest()
                .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
        }
        package.recompute_mast_commitment();

        Ok(package)
    }
}

impl Deserializable for Package {
    /// Reads and validates a package from potentially adversarial input.
    ///
    /// This validates the embedded MAST forest, manifest references, and package-owned debug
    /// information before returning. The caller's [`ByteReader`] controls the resource budget. For
    /// a byte slice, prefer [`Package::read_from_bytes`], which applies a finite byte-read budget.
    /// Use [`Package::read_from_trusted`] for packages written and retained by the same trusted
    /// system when repeating these checks is unnecessary.
    #[track_caller]
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let header = Self::read_header_from(source)?;

        // Read MAST artifact
        let mast = Self::read_mast_forest(source, true)?;

        Self::read_from_with_header_and_mast(source, header, mast, true, true)
    }

    /// Reads and validates a package from a potentially adversarial byte slice.
    ///
    /// This is the recommended reader for untrusted package bytes. It applies a finite byte-read
    /// budget and validates the embedded MAST forest, manifest references, and package-owned debug
    /// information. Use [`Package::read_from_bytes_trusted`] for packages written and retained by
    /// the same trusted system when repeating these checks is unnecessary.
    #[track_caller]
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let budget = bytes.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        Self::read_from(&mut reader)
    }
}

// PACKAGE MANIFEST SERIALIZATION/DESERIALIZATION
// ================================================================================================

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
    pub fn read_from_trusted<R: ByteReader>(
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
            exports.push(PackageExport::read_from_trusted(source, mast)?);
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
    pub fn read_from_trusted<R: ByteReader>(
        source: &mut R,
        mast: &MastForest,
    ) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            1 => ProcedureExport::read_from_trusted(source, mast).map(Self::Procedure),
            2 => ConstantExport::read_from(source).map(Self::Constant),
            3 => TypeExport::read_from(source).map(Self::Type),
            invalid => Err(DeserializationError::InvalidValue(format!(
                "unexpected PackageExport tag: '{invalid}'"
            ))),
        }
    }

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
    pub fn read_from_trusted<R: ByteReader>(
        source: &mut R,
        mast: &MastForest,
    ) -> Result<Self, DeserializationError> {
        use miden_assembly_syntax::ast::types::FunctionType;
        let path = PathBuf::read_from(source)?.into_boxed_path().into();
        let node = if source.read_bool()? {
            Some(MastNodeId::from_u32_safe(source.read_u32()?, mast)?)
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
