use alloc::{format, string::String, vec::Vec};

use miden_assembly_syntax::diagnostics::Report;
use miden_core::{
    Word,
    serde::{Deserializable, Serializable, SliceReader},
    utils::hash_string_to_word,
};
use miden_mast_package::{Package as MastPackage, Section, SectionId};

use super::PackageBuildSettings;

// PACKAGE BUILD PROVENANCE
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PackageBuildProvenance {
    Path {
        source_hash: Word,
        dependency_hash: Word,
        build_settings: PackageBuildSettings,
    },
    Git {
        repo: String,
        resolved_revision: String,
        dependency_hash: Word,
        build_settings: PackageBuildSettings,
    },
}

impl PackageBuildProvenance {
    pub fn empty_dependency_hash() -> Word {
        hash_string_to_word("")
    }

    pub fn to_section(&self) -> Section {
        let mut data = Vec::new();
        self.write_into(&mut data);
        Section::new(SectionId::PROJECT_SOURCE_PROVENANCE, data)
    }

    pub fn from_package(package: &MastPackage) -> Result<Option<Self>, Report> {
        let Some(section) = package
            .sections
            .iter()
            .find(|section| section.id == SectionId::PROJECT_SOURCE_PROVENANCE)
        else {
            return Ok(None);
        };

        let mut reader = SliceReader::new(section.data.as_ref());
        Self::read_from(&mut reader).map(Some).map_err(|error| {
            Report::msg(format!(
                "failed to decode source provenance for package '{}': {error}",
                package.name
            ))
        })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
            } if *dependency_hash == Self::empty_dependency_hash()
                && build_settings.is_legacy() =>
            {
                format!("path({source_hash})")
            },
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
            } if build_settings.is_legacy() => {
                format!("path({source_hash}, deps={dependency_hash})")
            },
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
            } => {
                format!(
                    "path({source_hash}, deps={dependency_hash}, debug={}, trim_paths={})",
                    build_settings.emit_debug_info, build_settings.trim_paths
                )
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
            } if *dependency_hash == Self::empty_dependency_hash()
                && build_settings.is_legacy() =>
            {
                format!("git({repo}@{resolved_revision})")
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
            } if build_settings.is_legacy() => {
                format!("git({repo}@{resolved_revision}, deps={dependency_hash})")
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
            } => {
                format!(
                    "git({repo}@{resolved_revision}, deps={dependency_hash}, debug={}, trim_paths={})",
                    build_settings.emit_debug_info, build_settings.trim_paths
                )
            },
        }
    }
}

impl Serializable for PackageBuildProvenance {
    fn write_into<W: miden_core::serde::ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
            } if *dependency_hash == Self::empty_dependency_hash()
                && build_settings.is_legacy() =>
            {
                target.write_u8(0);
                source_hash.write_into(target);
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
            } if *dependency_hash == Self::empty_dependency_hash()
                && build_settings.is_legacy() =>
            {
                target.write_u8(1);
                repo.write_into(target);
                resolved_revision.write_into(target);
            },
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
            } if build_settings.is_legacy() => {
                target.write_u8(2);
                source_hash.write_into(target);
                dependency_hash.write_into(target);
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
            } if build_settings.is_legacy() => {
                target.write_u8(3);
                repo.write_into(target);
                resolved_revision.write_into(target);
                dependency_hash.write_into(target);
            },
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
            } => {
                target.write_u8(4);
                source_hash.write_into(target);
                dependency_hash.write_into(target);
                target.write_bool(build_settings.emit_debug_info);
                target.write_bool(build_settings.trim_paths);
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
            } => {
                target.write_u8(5);
                repo.write_into(target);
                resolved_revision.write_into(target);
                dependency_hash.write_into(target);
                target.write_bool(build_settings.emit_debug_info);
                target.write_bool(build_settings.trim_paths);
            },
        }
    }
}

impl Deserializable for PackageBuildProvenance {
    fn read_from<R: miden_core::serde::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_core::serde::DeserializationError> {
        match source.read_u8()? {
            0 => Ok(Self::Path {
                source_hash: Word::read_from(source)?,
                dependency_hash: Self::empty_dependency_hash(),
                build_settings: PackageBuildSettings::legacy(),
            }),
            1 => Ok(Self::Git {
                repo: String::read_from(source)?,
                resolved_revision: String::read_from(source)?,
                dependency_hash: Self::empty_dependency_hash(),
                build_settings: PackageBuildSettings::legacy(),
            }),
            2 => Ok(Self::Path {
                source_hash: Word::read_from(source)?,
                dependency_hash: Word::read_from(source)?,
                build_settings: PackageBuildSettings::legacy(),
            }),
            3 => Ok(Self::Git {
                repo: String::read_from(source)?,
                resolved_revision: String::read_from(source)?,
                dependency_hash: Word::read_from(source)?,
                build_settings: PackageBuildSettings::legacy(),
            }),
            4 => Ok(Self::Path {
                source_hash: Word::read_from(source)?,
                dependency_hash: Word::read_from(source)?,
                build_settings: PackageBuildSettings {
                    emit_debug_info: source.read_bool()?,
                    trim_paths: source.read_bool()?,
                },
            }),
            5 => Ok(Self::Git {
                repo: String::read_from(source)?,
                resolved_revision: String::read_from(source)?,
                dependency_hash: Word::read_from(source)?,
                build_settings: PackageBuildSettings {
                    emit_debug_info: source.read_bool()?,
                    trim_paths: source.read_bool()?,
                },
            }),
            invalid => Err(miden_core::serde::DeserializationError::InvalidValue(format!(
                "invalid project source provenance tag '{invalid}'"
            ))),
        }
    }
}
