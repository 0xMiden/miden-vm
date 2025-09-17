//! The serialization format of `Package` is as follows:
//!
//! #### Header
//! - `MAGIC_PACKAGE`, a 4-byte tag, followed by a NUL-byte, i.e. `b"\0"`
//! - `VERSION`, a 3-byte semantic version number, 1 byte for each component, i.e. MAJ.MIN.PATCH
//!
//! #### Metadata
//! - `name` (`String`)
//! - `version` (optional, [`miden_assembly_syntax::Version`] serialized as a `String`)
//! - `description` (optional, `String`)
//!
//! #### Code
//! - `mast` (see [`crate::MastArtifact`])
//!
//! #### Manifest
//! - `manifest` (see [`crate::PackageManifest`])
//!
//! #### Custom Sections
//! - `sections` (a vector of zero or more [`crate::Section`])

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{
    Library,
    ast::QualifiedProcedureName,
    library::{FunctionTypeDeserializer, FunctionTypeSerializer},
};
use miden_core::{
    Program, Word,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

use crate::{Dependency, MastArtifact, Package, PackageExport, PackageManifest, Section};

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
const VERSION: [u8; 3] = [2, 0, 0];

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
        self.version.as_ref().map(|v| v.to_string()).write_into(target);

        // Write package description
        self.description.write_into(target);

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
        let name = String::read_from(source)?;

        // Read package version
        let version = Option::<String>::read_from(source)?;
        let version = match version {
            Some(version) => Some(
                crate::Version::parse(&version)
                    .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?,
            ),
            None => None,
        };

        // Read package description
        let description = Option::<String>::read_from(source)?;

        // Read MAST artifact
        let mast = MastArtifact::read_from(source)?;

        // Read manifest
        let manifest = PackageManifest::read_from(source)?;

        // Read custom sections
        let num_sections = source.read_usize()?;
        let mut sections = Vec::with_capacity(num_sections);
        for _ in 0..num_sections {
            let section = Section::read_from(source)?;
            sections.push(section);
        }

        Ok(Self {
            name,
            version,
            description,
            mast,
            manifest,
            sections,
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

#[cfg(feature = "serde")]
impl serde::Serialize for PackageManifest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        struct PackageExports<'a>(&'a BTreeMap<QualifiedProcedureName, PackageExport>);

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
                Ok(PackageManifest::new(exports).with_dependencies(dependencies))
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
                Ok(PackageManifest::new(exports).with_dependencies(dependencies))
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
