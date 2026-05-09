use alloc::{format, string::String, vec::Vec};

use miden_assembly_syntax::diagnostics::Report;
use miden_core::{
    Word,
    serde::{Deserializable, Serializable, SliceReader},
    utils::hash_string_to_word,
};
use miden_mast_package::{Package as MastPackage, Section, SectionId};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;

use super::PackageBuildSettings;

// PACKAGE BUILD PROVENANCE
// ================================================================================================

/// Provenance metadata attached to packages that were assembled from concrete project sources.
///
/// `ProjectAssembler` uses this metadata to decide whether a canonical package already present in
/// the package store is still a valid reuse candidate for a source dependency, or whether the
/// current sources have diverged and the dependency must be rebuilt or semver-bumped instead.
///
/// The value is serialized into the package's [`SectionId::PROJECT_SOURCE_PROVENANCE`] section via
/// [`Self::to_section`] when a package is built from real on-disk sources. Builds that use
/// caller-provided modules or other virtual sources intentionally omit this section because there
/// is no stable filesystem or git identity to compare on a later reuse attempt.
///
/// The recorded fields differ by source origin:
///
/// - [`Self::Path`] tracks a hash of the selected target's build-provenance projection and resolved
///   source files, along with a hash of the fully resolved dependency closure and the build-profile
///   knobs that affect the emitted package bytes.
/// - [`Self::Git`] records the repository identity and resolved revision instead of hashing the
///   checked-out source tree directly, but still includes the dependency-closure hash and build
///   settings for the same reuse decision.
///
/// Beyond direct reuse checks, [`Self::describe`] is also folded into dependency-closure hashing
/// for parent packages and is used in semver-bump diagnostics to explain why an existing canonical
/// artifact no longer matches the current sources.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
pub(super) enum PackageBuildProvenance {
    /// Provenance for a package assembled from sources addressed by a local filesystem path.
    Path {
        /// Hash of the build-provenance projection plus the root/support modules for the target.
        source_hash: Word,
        /// Hash of the resolved dependency closure, including linkage and exact selected
        /// artifacts.
        dependency_hash: Word,
        /// Build-profile settings that materially affect the produced package bytes.
        build_settings: PackageBuildSettings,
    },
    /// Provenance for a package assembled from a checked-out Git source.
    Git {
        /// Repository URI used to fetch the sources.
        repo: String,
        /// Fully resolved revision used for the checkout, after branch/tag resolution.
        resolved_revision: String,
        /// Hash of the resolved dependency closure, including linkage and exact selected
        /// artifacts.
        dependency_hash: Word,
        /// Build-profile settings that materially affect the produced package bytes.
        build_settings: PackageBuildSettings,
    },
}

impl PackageBuildProvenance {
    /// The canonical dependency hash for packages that have no dependencies.
    ///
    /// This keeps the serialized format compact and provides a stable value for older provenance
    /// encodings that predated explicit dependency-closure hashing.
    pub fn empty_dependency_hash() -> Word {
        hash_string_to_word("")
    }

    /// Encode this provenance record as a package section that can be embedded in a `.masp`.
    pub fn to_section(&self) -> Section {
        let mut data = Vec::new();
        self.write_into(&mut data);
        Section::new(SectionId::PROJECT_SOURCE_PROVENANCE, data)
    }

    /// Decode source provenance from `package`, if the package carries a provenance section.
    ///
    /// This is used when considering reuse of a canonical store artifact for a source dependency:
    /// the decoded value is compared against the provenance that would be produced from the current
    /// dependency graph and build profile.
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

    /// Render a stable human-readable summary for diagnostics and dependency-closure hashing.
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

#[cfg(feature = "arbitrary")]
impl Arbitrary for PackageBuildSettings {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<bool>(), any::<bool>())
            .prop_map(|(emit_debug_info, trim_paths)| Self { emit_debug_info, trim_paths })
            .boxed()
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for PackageBuildProvenance {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let word =
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..16).prop_map(|chars| {
                let material = chars.into_iter().collect::<String>();
                hash_string_to_word(material.as_str())
            });
        let text = proptest::collection::vec(
            proptest::prop_oneof![
                proptest::char::range('a', 'z'),
                proptest::char::range('0', '9'),
                Just('/'),
                Just('-'),
                Just('_'),
                Just('.'),
                Just(':'),
            ],
            1..40,
        )
        .prop_map(|chars| chars.into_iter().collect::<String>());

        proptest::prop_oneof![
            (word.clone(), word.clone(), any::<PackageBuildSettings>()).prop_map(
                |(source_hash, dependency_hash, build_settings)| Self::Path {
                    source_hash,
                    dependency_hash,
                    build_settings,
                }
            ),
            (text.clone(), text, word, any::<PackageBuildSettings>()).prop_map(
                |(repo, resolved_revision, dependency_hash, build_settings)| Self::Git {
                    repo,
                    resolved_revision,
                    dependency_hash,
                    build_settings,
                }
            ),
        ]
        .boxed()
    }
}
