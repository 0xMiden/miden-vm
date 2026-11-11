use alloc::{boxed::Box, sync::Arc};
use std::path::{Path, PathBuf};

use miden_assembly_syntax::diagnostics::{IntoDiagnostic, Report};
use miden_mast_package::{Package, PackageId};

/// A compiled library package requested by the user for execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLibrary {
    /// The name of the library.
    ///
    /// If requested by name, e.g. `-l std`, the name is used as given.
    ///
    /// If requested by path, e.g. `-l ./target/libs/miden-base.masp`, then the name of the library
    /// will be the basename of the file specified in the path.
    pub name: PackageId,
    /// If specified, the path from which this library should be loaded
    pub path: Option<PathBuf>,
    /// How to link against this library
    pub linkage: Linkage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Linkage {
    Dynamic,
    Static,
}

impl LinkLibrary {
    /// Get the name of this library
    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn is_core(&self) -> bool {
        matches!(self.name.as_ref(), "miden-core" | "core" | "std")
    }

    pub fn is_protocol(&self) -> bool {
        matches!(self.name.as_ref(), "miden-protocol" | "protocol" | "base")
    }

    pub fn load(&self, search_paths: &[PathBuf]) -> Result<Arc<Package>, Report> {
        if let Some(path) = self.path.as_deref() {
            return self.load_from_path(path);
        }

        // Search for library among specified search paths
        let path = self.find(search_paths)?;

        self.load_from_path(&path)
    }

    fn load_from_path(&self, path: &Path) -> Result<Arc<Package>, Report> {
        if path.extension().is_none_or(|ext| !ext.eq_ignore_ascii_case("masp")) {
            return Err(Report::msg(format!(
                "link library '{}' is not a compiled .masp package",
                path.display()
            )));
        }

        let bytes = std::fs::read(path).into_diagnostic()?;
        miden_mast_package::Package::read_from_bytes_trusted(&bytes)
            .map_err(|e| {
                Report::msg(format!("failed to load Miden package from {}: {e}", path.display()))
            })
            .map(Arc::new)
    }

    fn find(&self, search_paths: &[PathBuf]) -> Result<PathBuf, Report> {
        use std::fs;

        for search_path in search_paths {
            let reader = fs::read_dir(search_path).map_err(|err| {
                Report::msg(format!(
                    "invalid library search path '{}': {err}",
                    search_path.display()
                ))
            })?;
            for entry in reader {
                let Ok(entry) = entry else {
                    continue;
                };
                let path = entry.path();
                if path.extension().is_none_or(|ext| !ext.eq_ignore_ascii_case("masp")) {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                if stem != self.name() {
                    continue;
                }

                if !path.is_file() {
                    return Err(Report::msg(format!(
                        "unable to load Miden Assembly package from '{}': not a file",
                        path.display()
                    )));
                }
                return Ok(path);
            }
        }

        Err(Report::msg(format!(
            "unable to locate library '{}' using any of the provided search paths",
            self.name
        )))
    }
}

#[cfg(feature = "std")]
impl clap::builder::ValueParserFactory for LinkLibrary {
    type Parser = LinkLibraryParser;

    fn value_parser() -> Self::Parser {
        LinkLibraryParser
    }
}

#[cfg(feature = "std")]
#[doc(hidden)]
#[derive(Clone)]
pub struct LinkLibraryParser;

#[cfg(feature = "std")]
impl clap::builder::TypedValueParser for LinkLibraryParser {
    type Value = LinkLibrary;

    fn possible_values(
        &self,
    ) -> Option<Box<dyn Iterator<Item = clap::builder::PossibleValue> + '_>> {
        use clap::builder::PossibleValue;

        Some(Box::new(
            [PossibleValue::new("masp").help("A compiled Miden package file")].into_iter(),
        ))
    }

    /// Parses the `-l` flag using the following format:
    ///
    /// `-l[KIND[:<LINKAGE>]=]NAME`
    ///
    /// * `KIND` is `masp`
    /// * `LINKAGE` is one of: `static`, `dynamic`; defaults to `dynamic`
    /// * `NAME` is either a path, or a name (without extension)
    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::error::Error> {
        use clap::error::{Error, ErrorKind};

        let value = value.to_str().ok_or_else(|| Error::new(ErrorKind::InvalidUtf8))?;
        let (kind, name) = value
            .split_once('=')
            .map(|(kind, name)| (Some(kind), name))
            .unwrap_or((None, value));

        let linkage = match kind {
            Some(kind) => match kind.split_once(':') {
                Some(("masp", "static")) => Linkage::Static,
                Some(("masp", "dynamic")) => Linkage::Dynamic,
                Some(("masp", other)) => {
                    return Err(Error::raw(
                        ErrorKind::ValueValidation,
                        format!("unrecognized linkage modifier '{other}'"),
                    ));
                }
                None if kind == "masp" => Linkage::Dynamic,
                Some(_) | None => {
                    return Err(Error::raw(
                        ErrorKind::ValueValidation,
                        "invalid link library kind: supported values are 'masp'",
                    ));
                }
            },
            None => Linkage::Dynamic,
        };

        if name.is_empty() {
            return Err(Error::raw(
                ErrorKind::ValueValidation,
                "invalid link library: must specify a name or path",
            ));
        }

        let maybe_path = Path::new(name);
        let path = match maybe_path.components().count() {
            _ if maybe_path.extension().is_some() || maybe_path.is_dir() => {
                // Existing directories and values with an extension are always paths.
                maybe_path.canonicalize().map_err(|err| {
                    Error::raw(
                        ErrorKind::ValueValidation,
                        format!("invalid link library '{}': {err}", maybe_path.display()),
                    )
                })?
            }
            1 => {
                // A single component with no extension that is not a directory is a package name.
                let name = maybe_path.file_name().unwrap().to_str().unwrap();
                return Ok(LinkLibrary {
                    name: name.into(),
                    path: None,
                    linkage,
                });
            }
            _ => {
                // A multi-component path is always treated as a path
                maybe_path.canonicalize().map_err(|err| {
                    Error::raw(
                        ErrorKind::ValueValidation,
                        format!("invalid link library: '{}': {err}", maybe_path.display()),
                    )
                })?
            }
        };

        if path.extension().is_none_or(|ext| !ext.eq_ignore_ascii_case("masp")) {
            return Err(Error::raw(
                ErrorKind::ValueValidation,
                format!(
                    "invalid link library: expected '{}' to refer to a compiled .masp package",
                    path.display()
                ),
            ));
        }

        let name = path.file_stem().unwrap().to_str().unwrap();
        Ok(LinkLibrary {
            name: name.into(),
            path: Some(path),
            linkage,
        })
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
