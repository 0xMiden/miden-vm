//! The serialization format of `Package` is as follows:
//!
//! (Metadata)
//! - `MAGIC_PACKAGE`
//! - `VERSION`
//!
//! (Package Name)
//! - `name` (`String`)
//!
//! (MAST Artifact)
//! - `mast` (`MastArtifact`)
//!
//!   The serialization format of `MastArtifact` is:
//!   - `tag` (`[u8; 4]`)
//!     - `MAGIC_PROGRAM` if the artifact is a `Program`
//!     - `MAGIC_LIBRARY` if the artifact is a `Library`
//!   - If `Program`:
//!     - `program` (`Program`)
//!   - If `Library`:
//!     - `library` (`Library`)
//!
//! (Package Manifest)
//! - `manifest` (`PackageManifest`)
//!
//!   The serialization format of `PackageManifest` is:
//!   - `exports_len` (`usize`)
//!   - For each export:
//!     - `export` (`PackageExport`)
//!       - `name` (`QualifiedProcedureName`)
//!       - `digest` (`Word`)
//!   - `dependencies_len` (`usize`)
//!   - For each dependency:
//!     - `dependency` (`Dependency`)
//!       - `name` (`String`)
//!       - `digest` (`Word`)

use alloc::{collections::BTreeMap, format, string::String, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    Library,
    ast::QualifiedProcedureName,
    library::{FunctionTypeDeserializer, FunctionTypeSerializer},
};
use miden_core::{
    Program, Word,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

use crate::{Dependency, MastArtifact, Package, PackageExport, PackageManifest};

// CONSTANTS
// ================================================================================================

/// Magic string for detecting that a file is serialized [`Package`]
const MAGIC_PACKAGE: &[u8; 5] = b"MASP\0";

/// Magic string indicating a Program artifact.
const MAGIC_PROGRAM: &[u8; 4] = b"PRG\0";

/// Magic string indicating a Library artifact.
const MAGIC_LIBRARY: &[u8; 4] = b"LIB\0";

/// The format version.
///
/// If future modifications are made to this format, the version should be incremented by 1.
const VERSION: [u8; 3] = [1, 0, 0];

// PACKAGE SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for Package {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write magic & version
        target.write_bytes(MAGIC_PACKAGE);
        target.write_bytes(&VERSION);

        // Write package name
        self.name.write_into(target);

        // Write MAST artifact
        self.mast.write_into(target);

        // Write manifest
        self.manifest.write_into(target);

        // Write optional account component metadata
        self.account_component_metadata_bytes.write_into(target);
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
        let name = String::read_from(source)?;

        // Read MAST artifact
        let mast = MastArtifact::read_from(source)?;

        // Read manifest
        let manifest = PackageManifest::read_from(source)?;

        // Read optional account component metadata
        let account_component_metadata_bytes: Option<Vec<u8>> = Deserializable::read_from(source)?;

        Ok(Self {
            name,
            mast,
            manifest,
            account_component_metadata_bytes,
        })
    }
}

// MAST ARTIFACT SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for MastArtifact {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Executable(program) => {
                target.write_bytes(MAGIC_PROGRAM);
                program.write_into(target);
            },
            Self::Library(library) => {
                target.write_bytes(MAGIC_LIBRARY);
                library.write_into(target);
            },
        }
    }
}

impl Deserializable for MastArtifact {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag: [u8; 4] = source.read_array()?;

        if &tag == MAGIC_PROGRAM {
            Program::read_from(source).map(Arc::new).map(MastArtifact::Executable)
        } else if &tag == MAGIC_LIBRARY {
            Library::read_from(source).map(Arc::new).map(MastArtifact::Library)
        } else {
            Err(DeserializationError::InvalidValue(format!(
                "invalid MAST artifact tag: {:?}",
                &tag
            )))
        }
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
        let mut exports = BTreeMap::new();
        for _ in 0..exports_len {
            let export = PackageExport::read_from(source)?;
            exports.insert(export.name.clone(), export);
        }

        // Read dependencies
        let deps_len = source.read_usize()?;
        let mut dependencies = Vec::with_capacity(deps_len);
        for _ in 0..deps_len {
            dependencies.push(Dependency::read_from(source)?);
        }

        Ok(Self { exports, dependencies })
    }
}

// PACKAGE EXPORT SERIALIZATION/DESERIALIZATION
// ================================================================================================
impl Serializable for PackageExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.name.write_into(target);
        self.digest.write_into(target);
        match self.signature.as_ref() {
            Some(sig) => {
                target.write_bool(true);
                FunctionTypeSerializer(sig).write_into(target);
            },
            None => {
                target.write_bool(false);
            },
        }
    }
}

impl Deserializable for PackageExport {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name = QualifiedProcedureName::read_from(source)?;
        let digest = Word::read_from(source)?;
        let signature = if source.read_bool()? {
            Some(FunctionTypeDeserializer::read_from(source)?.0)
        } else {
            None
        };
        Ok(Self { name, digest, signature })
    }
}
