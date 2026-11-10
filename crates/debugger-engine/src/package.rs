use alloc::{string::String, sync::Arc};
use core::fmt;

use miden_assembly_syntax::{
    Report,
    diagnostics::{Diagnostic, miette},
};
use miden_core::serde::DeserializationError;
use miden_debug_types::Uri;
use miden_mast_package::{Package, PackageDebugInfoError};

const PACKAGE_MAGIC: &[u8; 5] = b"MASP\0";
const TOOLCHAIN_HELP: &str = "package, MAST, and debug-info formats are tied to the Miden \
                              toolchain that produced them; rerun with that toolchain, for \
                              example `miden +0.16.0 debug <FILE>`";

#[derive(Debug, thiserror::Error, Diagnostic)]
enum PackageLoadError {
    #[error("failed to load Miden package from {input}")]
    DecodePackage {
        input: Uri,
        #[source]
        cause: DeserializationError,
    },
    #[error("Miden package from {input} uses unsupported package format {version}")]
    #[diagnostic(code(miden_debug::incompatible_package_format))]
    IncompatiblePackageFormat {
        input: Uri,
        version: PackageFormatVersion,
        #[source]
        cause: DeserializationError,
        #[help]
        help: String,
    },
    #[error("failed to load debug information from Miden package {input}")]
    DecodeDebugInfo {
        input: Uri,
        #[source]
        cause: PackageDebugInfoError,
    },
    #[error("Miden package from {input} uses an unsupported debug-info format")]
    #[diagnostic(code(miden_debug::incompatible_debug_info_format))]
    IncompatibleDebugInfoFormat {
        input: Uri,
        #[source]
        cause: PackageDebugInfoError,
        #[help]
        help: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackageFormatVersion([u8; 3]);

impl fmt::Display for PackageFormatVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.0[0], self.0[1], self.0[2])
    }
}

/// Decode a package from the given path.
///
/// Internally calls `read_package_from_bytes`.
#[doc(hidden)]
#[cfg(feature = "std")]
pub fn load_package_from_path(path: &std::path::Path) -> Result<Arc<Package>, Report> {
    use miden_assembly_syntax::diagnostics::IntoDiagnostic;
    let bytes = std::fs::read(path).into_diagnostic()?;
    let uri = Uri::from(path);
    read_package_from_bytes(&bytes, &uri)
}

/// Decode a package and eagerly validate its debug-info section.
///
/// The processor and debugger must use matching package, MAST, and debug-info formats. When the
/// input carries a different format version, this returns an actionable diagnostic that points the
/// user to midenup's versioned toolchain invocation instead of implying that the artifact is
/// corrupt.
#[doc(hidden)]
pub fn read_package_from_bytes(bytes: &[u8], input: &Uri) -> Result<Arc<Package>, Report> {
    let package = Package::read_from_bytes_trusted(bytes).map_err(|cause| {
        if let Some(version) = incompatible_package_format(bytes, &cause) {
            Report::new(PackageLoadError::IncompatiblePackageFormat {
                input: input.clone(),
                version,
                cause,
                help: TOOLCHAIN_HELP.into(),
            })
        } else {
            Report::new(PackageLoadError::DecodePackage {
                input: input.clone(),
                cause,
            })
        }
    })?;

    if let Err(cause) = package.debug_info() {
        let error = if is_incompatible_debug_info(&cause) {
            PackageLoadError::IncompatibleDebugInfoFormat {
                input: input.clone(),
                cause,
                help: TOOLCHAIN_HELP.into(),
            }
        } else {
            PackageLoadError::DecodeDebugInfo {
                input: input.clone(),
                cause,
            }
        };
        return Err(Report::new(error));
    }

    Ok(Arc::new(package))
}

fn incompatible_package_format(
    bytes: &[u8],
    error: &DeserializationError,
) -> Option<PackageFormatVersion> {
    let DeserializationError::InvalidValue(message) = error else {
        return None;
    };
    if !message.starts_with("unsupported version.") {
        return None;
    }

    let version = bytes.strip_prefix(PACKAGE_MAGIC)?.get(..3)?.try_into().ok()?;
    Some(PackageFormatVersion(version))
}

fn is_incompatible_debug_info(error: &PackageDebugInfoError) -> bool {
    let PackageDebugInfoError::DecodeSection { source, .. } = error else {
        return false;
    };
    matches!(
        source,
        DeserializationError::InvalidValue(message)
            if message.starts_with("unsupported debug_info version:")
    )
}

#[cfg(test)]
mod tests;
