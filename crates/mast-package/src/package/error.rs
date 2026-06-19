use alloc::string::String;

use miden_core::serde::DeserializationError;

use super::section::SectionId;

/// Errors raised while stripping package-owned debug information.
#[derive(Debug, thiserror::Error)]
pub enum PackageStripError {
    #[error("failed to decode embedded kernel package while stripping debug info: {source}")]
    DecodeEmbeddedKernel {
        #[source]
        source: DeserializationError,
    },
}

/// Errors raised while decoding trusted package-owned debug information.
#[derive(Debug, thiserror::Error)]
pub enum PackageDebugInfoError {
    #[error("package debug sections are present but are not trusted")]
    /// Package debug sections are present on a package that does not trust them.
    ///
    /// Normal untrusted deserialization discards package-owned debug sections before returning a
    /// package. This error protects callers from manually constructed packages, or future
    /// deserialization paths, that retain debug sections without marking them trusted.
    UntrustedSections,
    #[error("package contains multiple '{id}' debug sections")]
    DuplicateSection {
        /// Duplicated section identifier.
        id: SectionId,
    },
    #[error("failed to decode '{id}' debug section: {source}")]
    DecodeSection {
        /// Section identifier being decoded.
        id: SectionId,
        /// Underlying section deserialization error.
        #[source]
        source: DeserializationError,
    },
    #[error("'{id}' debug section has trailing bytes")]
    TrailingBytes {
        /// Section identifier with unused bytes after decoding.
        id: SectionId,
    },
    #[error("invalid package debug info: {message}")]
    InvalidReference { message: String },
}
