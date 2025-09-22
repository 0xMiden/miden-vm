use alloc::{
    borrow::Cow,
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_debug_types::{SourceContent, SourceFile, SourceLanguage, SourceManager, Uri};

use crate::{
    ast::{Module, ModuleKind},
    diagnostics::{IntoDiagnostic, NamedSource, Report, SourceCode, WrapErr, report},
    library::{LibraryNamespace, LibraryPath},
};

// PARSE OPTIONS
// ================================================================================================

/// The set of options which can be used to control the behavior of the [`Parse`] trait.
#[derive(Debug, Clone)]
pub struct ParseOptions {
    /// The kind of [Module] to parse.
    ///
    /// The default kind is executable.
    pub kind: ModuleKind,
    /// When true, promote warning diagnostics to errors
    pub warnings_as_errors: bool,
    /// The name to give the parsed [Module]
    ///
    /// This option overrides `namespace`.
    ///
    /// If unset, and there is no name associated with the item being parsed (e.g. a file path)
    /// then the path will consist of just a namespace; using the value of `namespace` if provided,
    /// or deriving one from `kind`.
    pub path: Option<LibraryPath>,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            kind: ModuleKind::Executable,
            warnings_as_errors: false,
            path: None,
        }
    }
}
impl ParseOptions {
    /// Configure a set of [`ParseOptions`] to parse a [`Module`] with the given `kind` and `path`.
    ///
    /// This is primarily useful when compiling a module from source code that has no meaningful
    /// [LibraryPath] associated with it, such as when compiling from a `str`. This will override
    /// the default name derived from the given [ModuleKind].
    pub fn new<P, E>(kind: ModuleKind, path: P) -> Result<Self, E>
    where
        P: TryInto<LibraryPath, Error = E>,
    {
        let path = path.try_into()?;
        Ok(Self {
            kind,
            path: Some(path),
            ..Default::default()
        })
    }

    /// Get the default [`ParseOptions`] for compiling a library module.
    pub fn for_library() -> Self {
        Self {
            kind: ModuleKind::Library,
            ..Default::default()
        }
    }

    /// Get the default [`ParseOptions`] for compiling a kernel module.
    pub fn for_kernel() -> Self {
        Self {
            kind: ModuleKind::Kernel,
            ..Default::default()
        }
    }
}

// PARSE TRAIT
// ================================================================================================

/// This trait is meant to be implemented by any type that can be parsed to a [Module],
/// to allow methods which expect a [Module] to accept things like:
///
/// * A [Module] which was previously parsed or deserialized
/// * A string representing the source code of a [Module].
/// * A path to a file containing the source code of a [Module].
/// * A vector of [crate::ast::Form]s comprising the contents of a [Module].
pub trait Parse: Sized {
    /// Parse (or convert) `self` into an executable [Module].
    ///
    /// See [`Parse::parse_with_options`] for more details.
    #[inline]
    fn parse(self, source_manager: &dyn SourceManager) -> Result<Box<Module>, Report> {
        self.parse_with_options(source_manager, ParseOptions::default())
    }

    /// Parse (or convert) `self` into a [Module] using the provided `options`.
    ///
    /// Returns a [Report] if parsing fails due to a parsing or semantic analysis error,
    /// or if the module provided is of the wrong kind (e.g. we expected a library module but got
    /// an executable module).
    ///
    /// See the documentation for [`ParseOptions`] to see how parsing can be configured.
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report>;
}

// PARSE IMPLEMENTATIONS FOR MODULES
// ------------------------------------------------------------------------------------------------

impl Parse for Module {
    #[inline(always)]
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        Box::new(self).parse_with_options(source_manager, options)
    }
}

impl Parse for &Module {
    #[inline(always)]
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        Box::new(self.clone()).parse_with_options(source_manager, options)
    }
}

impl Parse for Box<Module> {
    fn parse_with_options(
        mut self,
        _source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        let actual = self.kind();
        if actual == options.kind {
            if let Some(path) = options.path {
                self.set_path(path);
            }
            Ok(self)
        } else {
            Err(report!(
                "compilation failed: expected a {} module, but got a {actual} module",
                options.kind
            ))
        }
    }
}

impl Parse for Arc<Module> {
    #[inline(always)]
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        Box::new(Arc::unwrap_or_clone(self)).parse_with_options(source_manager, options)
    }
}

// PARSE IMPLEMENTATIONS FOR STRINGS
// ------------------------------------------------------------------------------------------------

impl Parse for Arc<SourceFile> {
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        let source_file = source_manager.copy_into(&self);
        let path = match options.path {
            Some(path) => path,
            None => source_file
                .uri()
                .path()
                .parse::<LibraryPath>()
                .into_diagnostic()
                .wrap_err("cannot parse module as it has an invalid path/name")?,
        };
        let mut parser = Module::parser(options.kind);
        parser.set_warnings_as_errors(options.warnings_as_errors);
        parser.parse(path, source_file)
    }
}

impl Parse for &str {
    #[inline(always)]
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        self.to_string().into_boxed_str().parse_with_options(source_manager, options)
    }
}

impl Parse for &String {
    #[inline(always)]
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        self.clone().into_boxed_str().parse_with_options(source_manager, options)
    }
}

impl Parse for String {
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        self.into_boxed_str().parse_with_options(source_manager, options)
    }
}

impl Parse for Box<str> {
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        let path = options.path.unwrap_or_else(|| {
            LibraryPath::from(match options.kind {
                ModuleKind::Library => LibraryNamespace::Anon,
                ModuleKind::Executable => LibraryNamespace::Exec,
                ModuleKind::Kernel => LibraryNamespace::Kernel,
            })
        });
        let name = Uri::from(path.path().into_owned().into_boxed_str());
        let mut parser = Module::parser(options.kind);
        parser.set_warnings_as_errors(options.warnings_as_errors);
        let content = SourceContent::new(SourceLanguage::Masm, name.clone(), self);
        let source_file = source_manager.load_from_raw_parts(name, content);
        parser.parse(path, source_file)
    }
}

impl Parse for Cow<'_, str> {
    #[inline(always)]
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        self.into_owned().into_boxed_str().parse_with_options(source_manager, options)
    }
}

// PARSE IMPLEMENTATIONS FOR BYTES
// ------------------------------------------------------------------------------------------------

impl Parse for &[u8] {
    #[inline]
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        core::str::from_utf8(self)
            .map_err(|err| {
                Report::from(crate::parser::ParsingError::from_utf8_error(Default::default(), err))
                    .with_source_code(self.to_vec())
            })
            .wrap_err("parsing failed: invalid source code")
            .and_then(|source| source.parse_with_options(source_manager, options))
    }
}

impl Parse for Vec<u8> {
    #[inline]
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        String::from_utf8(self)
            .map_err(|err| {
                let error = crate::parser::ParsingError::from_utf8_error(
                    Default::default(),
                    err.utf8_error(),
                );
                Report::from(error).with_source_code(err.into_bytes())
            })
            .wrap_err("parsing failed: invalid source code")
            .and_then(|source| source.into_boxed_str().parse_with_options(source_manager, options))
    }
}
impl Parse for Box<[u8]> {
    #[inline(always)]
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        Vec::from(self).parse_with_options(source_manager, options)
    }
}

impl<T> Parse for NamedSource<T>
where
    T: SourceCode + AsRef<[u8]>,
{
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        let path = match options.path {
            Some(path) => path,
            None => self
                .name()
                .parse::<LibraryPath>()
                .into_diagnostic()
                .wrap_err("cannot parse module as it has an invalid path/name")?,
        };
        let content = core::str::from_utf8(self.inner().as_ref())
            .map_err(|err| {
                let error = crate::parser::ParsingError::from_utf8_error(Default::default(), err);
                Report::from(error)
            })
            .wrap_err("parsing failed: expected source code to be valid utf-8")?;
        let name = Uri::from(self.name());
        let content = SourceContent::new(
            SourceLanguage::Masm,
            name.clone(),
            content.to_string().into_boxed_str(),
        );
        let source_file = source_manager.load_from_raw_parts(name, content);
        let mut parser = Module::parser(options.kind);
        parser.set_warnings_as_errors(options.warnings_as_errors);
        parser.parse(path, source_file)
    }
}

// PARSE IMPLEMENTATIONS FOR FILES
// ------------------------------------------------------------------------------------------------

#[cfg(feature = "std")]
impl Parse for &std::path::Path {
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        use std::path::Component;

        use miden_debug_types::SourceManagerExt;

        use crate::{ast::Ident, library::PathError};

        let path = match options.path {
            Some(path) => path,
            None => {
                let ns = match options.kind {
                    ModuleKind::Library => LibraryNamespace::Anon,
                    ModuleKind::Executable => LibraryNamespace::Exec,
                    ModuleKind::Kernel => LibraryNamespace::Kernel,
                };
                let mut parts = Vec::default();
                self.components()
                    .skip_while(|component| {
                        matches!(
                            component,
                            Component::Prefix(_)
                                | Component::RootDir
                                | Component::ParentDir
                                | Component::CurDir
                        )
                    })
                    .try_for_each(|component| {
                        let part = component
                            .as_os_str()
                            .to_str()
                            .ok_or(PathError::InvalidUtf8)
                            .and_then(|s| Ident::new(s).map_err(PathError::InvalidComponent))
                            .into_diagnostic()
                            .wrap_err("invalid module path")?;
                        parts.push(part);

                        Ok::<(), Report>(())
                    })?;
                LibraryPath::new_from_components(ns, parts)
            },
        };
        let source_file = source_manager
            .load_file(self)
            .into_diagnostic()
            .wrap_err("source manager is unable to load file")?;
        let mut parser = Module::parser(options.kind);
        parser.parse(path, source_file)
    }
}

#[cfg(feature = "std")]
impl Parse for std::path::PathBuf {
    #[inline(always)]
    fn parse_with_options(
        self,
        source_manager: &dyn SourceManager,
        options: ParseOptions,
    ) -> Result<Box<Module>, Report> {
        self.as_path().parse_with_options(source_manager, options)
    }
}
