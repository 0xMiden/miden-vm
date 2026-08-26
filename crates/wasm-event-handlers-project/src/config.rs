//! The `[package.metadata.wasm-event-handlers]` table of a Miden project manifest.

use std::{
    fmt::Display,
    path::{Path, PathBuf},
};

use miden_assembly::diagnostics::Report;
use miden_project::Package as ProjectPackage;

/// The name of the metadata table the processor reads.
pub(crate) const TABLE: &str = "wasm-event-handlers";

/// The key that names a Rust guest crate directory.
const CRATE_KEY: &str = "crate";

/// The key that names a prebuilt core-Wasm module.
const MODULE_KEY: &str = "module";

/// Where the handler module of a package comes from.
///
/// The whole value — the variant and the path — identifies one way of producing the module, so
/// it is also the memoization key of the derived section.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum HandlerSource {
    /// A Rust guest crate directory, which is built for `wasm32-unknown-unknown`.
    GuestCrate(PathBuf),
    /// A prebuilt core-Wasm module file.
    Module(PathBuf),
}

impl HandlerSource {
    /// Returns the resolved path this source names.
    pub(crate) fn path(&self) -> &Path {
        match self {
            Self::GuestCrate(path) | Self::Module(path) => path,
        }
    }
}

/// Reads the handler source that `package` declares.
///
/// Returns `Ok(None)` when the package declares no `[package.metadata.wasm-event-handlers]`
/// table. Paths in the table resolve against `project_root`, the directory that holds the
/// manifest.
///
/// # Errors
/// Returns an error, naming `manifest_path` and the offending key, when the table sets both keys,
/// neither key, an unknown key, or a key whose value is not a string.
pub(crate) fn read(
    package: &ProjectPackage,
    manifest_path: &Path,
    project_root: &Path,
) -> Result<Option<HandlerSource>, Report> {
    let Some(table) = package.metadata().get(TABLE) else {
        return Ok(None);
    };

    let mut guest_crate = None;
    let mut module = None;
    for (key, value) in table {
        let key = key.inner().as_ref();
        let slot = match key {
            CRATE_KEY => &mut guest_crate,
            MODULE_KEY => &mut module,
            _ => {
                return Err(error(
                    manifest_path,
                    format!(
                        "unknown key '{key}'; the table accepts '{CRATE_KEY}' or '{MODULE_KEY}'"
                    ),
                ));
            },
        };
        let path = value.inner().as_str().ok_or_else(|| {
            error(
                manifest_path,
                format!(
                    "key '{key}' must be a string path, but it is {}",
                    value.inner().type_str()
                ),
            )
        })?;
        let joined = project_root.join(path);
        // Canonicalize so that two spellings of one path (`../guest` vs its absolute form)
        // share one memoization entry. A path that does not exist yet keeps its joined form;
        // the later read or build reports it.
        *slot = Some(joined.canonicalize().unwrap_or(joined));
    }

    match (guest_crate, module) {
        (Some(_), Some(_)) => Err(error(
            manifest_path,
            format!(
                "keys '{CRATE_KEY}' and '{MODULE_KEY}' are mutually exclusive; set exactly one"
            ),
        )),
        (Some(path), None) => Ok(Some(HandlerSource::GuestCrate(path))),
        (None, Some(path)) => Ok(Some(HandlerSource::Module(path))),
        (None, None) => Err(error(
            manifest_path,
            format!("the table must set exactly one of '{CRATE_KEY}' or '{MODULE_KEY}'"),
        )),
    }
}

/// Builds a build error that names the manifest and the table it comes from.
pub(crate) fn error(manifest_path: &Path, message: impl Display) -> Report {
    Report::msg(format!("{}: [package.metadata.{TABLE}]: {message}", label(manifest_path)))
}

/// Names the manifest a message refers to.
///
/// A virtual project has no manifest file, and its manifest path is empty; such a project is
/// named by a placeholder instead of by an empty path.
pub(crate) fn label(manifest_path: &Path) -> String {
    if manifest_path.as_os_str().is_empty() {
        "<virtual project manifest>".to_string()
    } else {
        manifest_path.display().to_string()
    }
}
