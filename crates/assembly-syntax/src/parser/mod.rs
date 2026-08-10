mod cst;
mod error;
#[cfg(test)]
mod tests;
mod value;

use alloc::{boxed::Box, collections::BTreeSet, string::ToString, sync::Arc, vec::Vec};

use miden_debug_types::{SourceFile, SourceLanguage, SourceManager, Uri};
#[cfg(feature = "std")]
use miden_diagnostics::Report;
use miden_diagnostics::{DiagnosticCollector, IntoDiagnostic, Outcome};

pub use self::{
    cst::{ParseInlineMasmOutcome, parse_inline_masm},
    error::{BinErrorKind, HexErrorKind, LiteralErrorKind, ParsingError},
    value::{IntValue, PushValue, WordValue},
};
use crate::{Path, ast, sema};

/// The diagnostic-preserving result of parsing and analyzing a module.
///
/// A missing module indicates that an error prevented construction of a usable AST. Diagnostics
/// remain available regardless of whether a module was produced.
pub type ModuleParseOutcome = Outcome<Option<Box<ast::Module>>>;

// MODULE PARSER
// ================================================================================================

/// This is a wrapper around the lower-level parser infrastructure which handles orchestrating all
/// of the pieces needed to parse a [ast::Module] from source, and run semantic analysis on it.
#[derive(Default)]
pub struct ModuleParser {
    /// The kind of module we're parsing, if known in advance.
    ///
    /// This is used when performing semantic analysis to detect when various invalid constructions
    /// are encountered, such as use of the `syscall` instruction in a kernel module.
    kind: Option<ast::ModuleKind>,
    /// A set of interned strings allocated during parsing/semantic analysis.
    ///
    /// This is a very primitive and imprecise way of interning strings, but was the least invasive
    /// at the time the new parser was implemented. In essence, we avoid duplicating allocations
    /// for frequently occurring strings, by tracking which strings we've seen before, and
    /// sharing a reference counted pointer instead.
    ///
    /// We may want to replace this eventually with a proper interner, so that we can also gain the
    /// benefits commonly provided by interned string handles (e.g. cheap equality comparisons, no
    /// ref- counting overhead, copyable and of smaller size).
    ///
    /// Note that [Ident], [ProcedureName], [LibraryPath] and others are all implemented in terms
    /// of either the actual reference-counted string, e.g. `Arc<str>`, or in terms of [Ident],
    /// which is essentially the former wrapped in a [SourceSpan]. If we ever replace this with
    /// a better interner, we will also want to update those types to be in terms of whatever
    /// the handle type of the interner is.
    interned: BTreeSet<Arc<str>>,
}

impl ModuleParser {
    /// Construct a new parser for the given `kind` of [ast::Module].
    pub fn new(kind: Option<ast::ModuleKind>) -> Self {
        Self { kind, interned: Default::default() }
    }

    /// Parse a [ast::Module] from `source`, and give it the provided `path`.
    ///
    /// If `path` is unset, then it must be derivable in one of two ways:
    ///
    /// 1. From a `namespace` declaration in the module source
    /// 2. Inferred as `$exec` from the presence of a `begin .. end` block in the module source
    ///
    /// If neither is present, then an error will be raised. It can be fixed by simply providing
    /// `path` explicitly.
    pub fn parse(
        &mut self,
        path: Option<&Path>,
        source: Arc<SourceFile>,
        source_manager: Arc<dyn SourceManager>,
    ) -> ModuleParseOutcome {
        use alloc::borrow::Cow;

        let mut diagnostics = DiagnosticCollector::new();
        let path = match path {
            Some(path) => match path
                .canonicalize()
                .and_then(|p| p.to_absolute().map(Cow::into_owned))
                .into_diagnostic()
            {
                Ok(path) => Some(Arc::<Path>::from(path)),
                Err(error) => {
                    let _ = diagnostics.add_report(error);
                    return Outcome {
                        value: None,
                        diagnostics: diagnostics
                            .finish()
                            .attach_session_sources(source_manager.clone()),
                    };
                },
            },
            None => None,
        };
        let Outcome {
            value: forms,
            diagnostics: parse_diagnostics,
        } = parse_forms_internal(source.clone(), &mut self.interned);
        let _ = diagnostics.merge(parse_diagnostics);

        let value = match forms {
            Some(forms) => {
                let Outcome { value, diagnostics: sema_diagnostics } = sema::analyze(
                    source,
                    self.kind,
                    path.as_deref(),
                    forms,
                    source_manager.clone(),
                );
                let _ = diagnostics.merge(sema_diagnostics);
                value
            },
            None => None,
        };

        Outcome {
            value,
            diagnostics: diagnostics.finish().attach_session_sources(source_manager.clone()),
        }
    }

    /// Parse a [ast::Module], `name`, from `path`.
    #[cfg(feature = "std")]
    pub fn parse_file<P>(
        &mut self,
        path: Option<&Path>,
        file_path: P,
        source_manager: Arc<dyn SourceManager>,
    ) -> ModuleParseOutcome
    where
        P: AsRef<std::path::Path>,
    {
        use miden_debug_types::SourceManagerExt;
        use miden_diagnostics::{IntoDiagnostic, WrapErr};

        let file_path = file_path.as_ref();
        let source_file =
            match source_manager.load_file(file_path).into_diagnostic().wrap_err_with(|| {
                format!("failed to load source file from '{}'", file_path.display())
            }) {
                Ok(source_file) => source_file,
                Err(error) => {
                    let mut diagnostics = DiagnosticCollector::new();
                    let _ = diagnostics.add_report(error);
                    return Outcome {
                        value: None,
                        diagnostics: diagnostics
                            .finish()
                            .attach_session_sources(source_manager.clone()),
                    };
                },
            };
        self.parse(path, source_file, source_manager)
    }

    /// Parse a [ast::Module], `name`, from `source`.
    pub fn parse_str(
        &mut self,
        path: Option<&Path>,
        source: impl ToString,
        source_manager: Arc<dyn SourceManager>,
    ) -> ModuleParseOutcome {
        use miden_debug_types::SourceContent;

        let source = source.to_string();
        let source_file = match path {
            Some(path) => {
                let uri = Uri::from(path.as_str().to_string().into_boxed_str());
                let content =
                    SourceContent::new(SourceLanguage::Masm, uri.clone(), source.into_boxed_str());
                source_manager.load_from_raw_parts(uri, content)
            },
            None => source_manager.load_anonymous(SourceLanguage::Masm, source),
        };
        self.parse(path, source_file, source_manager)
    }
}

/// This is used in tests to parse `source` as a set of raw [ast::Form]s rather than as a
/// [ast::Module].
///
/// NOTE: This does _not_ run semantic analysis.
#[cfg(any(test, feature = "testing"))]
pub fn parse_forms(source: Arc<SourceFile>) -> Outcome<Option<Vec<ast::Form>>> {
    let mut interned = BTreeSet::default();
    parse_forms_internal(source, &mut interned)
}

/// Parse `source` as a set of [ast::Form]s
///
/// Aside from catching syntax errors, this does little validation of the resulting forms, that is
/// handled by semantic analysis, which the caller is expected to perform next.
fn parse_forms_internal(
    source: Arc<SourceFile>,
    interned: &mut BTreeSet<Arc<str>>,
) -> Outcome<Option<Vec<ast::Form>>> {
    cst::parse_forms(source, interned)
}

// DIRECTORY PARSER
// ================================================================================================

/// Read the contents (modules) of this library from `dir`, returning any errors that occur
/// while traversing the file system.
///
/// Errors may also be returned if traversal discovers issues with the modules, such as
/// invalid names, etc.
///
/// Returns an iterator over all parsed modules.
#[cfg(feature = "std")]
pub fn read_modules_from_root(
    root: impl AsRef<std::path::Path>,
    namespace: Option<Arc<Path>>,
    kind: Option<ast::ModuleKind>,
    source_manager: Arc<dyn SourceManager>,
) -> Result<Outcome<Option<(Box<ast::Module>, Vec<Box<ast::Module>>)>>, Report> {
    use miden_diagnostics::report;

    let root = root.as_ref();
    let root = Arc::<std::path::Path>::from(
        root.canonicalize()
            .map_err(|err| {
                report!(message: (format!(
                    "invalid root module path '{}': {err}",
                    root.display()
                )))
            })?
            .into_boxed_path(),
    );

    // Make sure the path has the right file extension
    if root
        .extension()
        .is_none_or(|ext| !ext.eq_ignore_ascii_case(ast::Module::FILE_EXTENSION))
    {
        return Err(report!(message: (format!(
            "invalid root module path '{}': expected a .masm file",
            root.display()
        ))));
    }

    // Make sure it is a file
    if !root.is_file() {
        return Err(report!(message: (format!(
            "invalid root module path '{}': not a file",
            root.display()
        ))));
    }

    // Capture the parent directory for resolving submodules
    let root_dir = root
        .parent()
        .ok_or_else(|| {
            report!(message: (format!(
                "invalid root module path '{}': expected path to have a parent directory",
                root.display()
            )))
        })?
        .to_path_buf();

    let mut seen = BTreeSet::<Arc<Path>>::new();
    let mut modules = Vec::new();
    let mut diagnostics = DiagnosticCollector::new();

    let mut parser = ModuleParser::new(kind);
    let Outcome {
        value: root_ast,
        diagnostics: root_diagnostics,
    } = parser.parse_file(namespace.as_deref(), &root, source_manager.clone());
    let _ = diagnostics.merge(root_diagnostics);
    let Some(root_ast) = root_ast else {
        return Ok(Outcome {
            value: None,
            diagnostics: diagnostics.finish().attach_session_sources(source_manager.clone()),
        });
    };

    let namespace = Arc::<Path>::from(root_ast.path().to_path_buf().into_boxed_path());
    let submodules = root_ast.submodules().to_vec();
    seen.insert(namespace.clone());
    let Outcome {
        value: walked,
        diagnostics: walk_diagnostics,
    } = walk_module_tree(namespace, root, root_dir, submodules, source_manager.clone(), |module| {
        if !seen.insert(module.path().into()) {
            Err(report!(message: (format!("duplicate module '{}'", module.path()))))
        } else {
            modules.push(module);
            Ok(())
        }
    });
    let _ = diagnostics.merge(walk_diagnostics);
    if walked.is_none() {
        return Ok(Outcome {
            value: None,
            diagnostics: diagnostics.finish().attach_session_sources(source_manager.clone()),
        });
    }

    Ok(Outcome {
        value: Some((root_ast, modules)),
        diagnostics: diagnostics.finish().attach_session_sources(source_manager.clone()),
    })
}

#[cfg(feature = "std")]
pub fn walk_module_tree<F>(
    namespace: Arc<Path>,
    root: Arc<std::path::Path>,
    current_dir: std::path::PathBuf,
    submodules: Vec<ast::SubmoduleDecl>,
    source_manager: Arc<dyn SourceManager>,
    mut callback: F,
) -> Outcome<Option<()>>
where
    F: FnMut(Box<ast::Module>) -> Result<(), Report>,
{
    use miden_debug_types::{Spanned, Uri};

    struct ModuleEntry {
        pub name: ast::Ident,
        pub namespace: Arc<Path>,
        pub directory: Arc<std::path::Path>,
        pub parent: Arc<std::path::Path>,
    }

    let current_dir = Arc::<std::path::Path>::from(current_dir.into_boxed_path());
    let mut diagnostics = DiagnosticCollector::new();
    let mut visited = BTreeSet::<Arc<std::path::Path>>::from_iter([root.clone()]);
    let mut worklist = submodules
        .iter()
        .map(|sm| ModuleEntry {
            name: sm.name.clone(),
            namespace: namespace.clone(),
            directory: current_dir.clone(),
            parent: root.clone(),
        })
        .collect::<Vec<_>>();

    while let Some(entry) = worklist.pop() {
        let basename = entry.name.replace('-', "_");
        let mod_dir = entry.directory.join(&basename);
        let mod_file = mod_dir.with_extension("masm");
        let mod_dir_mod_masm = mod_dir.join("mod.masm");

        // If the parent module is at `mod_file`, then the parent module and submodule have the
        // same name. We explicitly do not allow this, because what we should do is unclear. We
        // could attempt to add an extra level of nesting, e.g.
        // `<mod_dir>/<basename>/<basename>.masm` or `<mod_dir>/<basename>/<basename>/mod.masm`,
        // but that may not be intended.
        if mod_file.as_path() == &*entry.parent {
            let span = entry.name.span();
            let _ = diagnostics.add(ParsingError::SelfReferentialSubmodule {
                name: entry.name.clone(),
                parent_module_uri: Uri::from(entry.parent),
                span,
            });
            return Outcome {
                value: None,
                diagnostics: diagnostics.finish().attach_session_sources(source_manager.clone()),
            };
        }

        let actual_path = if mod_file.is_file() {
            if mod_dir_mod_masm.is_file() {
                let span = entry.name.span();
                let _ = diagnostics.add(ParsingError::AmbiguousSubmoduleLocation {
                    name: entry.name,
                    first: Box::new(Uri::from(mod_file)),
                    second: Box::new(Uri::from(mod_dir_mod_masm)),
                    span,
                });
                return Outcome {
                    value: None,
                    diagnostics: diagnostics
                        .finish()
                        .attach_session_sources(source_manager.clone()),
                };
            }
            mod_file
        } else if mod_dir_mod_masm.is_file() {
            mod_dir_mod_masm
        } else {
            let span = entry.name.span();
            let _ = diagnostics.add(ParsingError::UndefinedSubmodule {
                name: entry.name,
                basename: basename.into_boxed_str(),
                directory: Box::new(Uri::from(mod_dir)),
                span,
            });
            return Outcome {
                value: None,
                diagnostics: diagnostics.finish().attach_session_sources(source_manager.clone()),
            };
        };

        let actual_path = Arc::<std::path::Path>::from(actual_path);
        if !visited.insert(actual_path.clone()) {
            let span = entry.name.span();
            let _ = diagnostics.add(ParsingError::DuplicateSubmoduleSource {
                name: entry.name,
                module_uri: Uri::from(actual_path.as_ref()),
                span,
            });
            return Outcome {
                value: None,
                diagnostics: diagnostics.finish().attach_session_sources(source_manager.clone()),
            };
        }

        let mut parser = ModuleParser::new(Some(ast::ModuleKind::Library));
        let module_path = Arc::<Path>::from(entry.namespace.join(&entry.name).into_boxed_path());
        let Outcome {
            value: ast,
            diagnostics: module_diagnostics,
        } = parser.parse_file(Some(&module_path), &actual_path, source_manager.clone());
        let _ = diagnostics.merge(module_diagnostics);
        let Some(ast) = ast else {
            return Outcome {
                value: None,
                diagnostics: diagnostics.finish().attach_session_sources(source_manager.clone()),
            };
        };

        let directory = Arc::<std::path::Path>::from(mod_dir);
        worklist.extend(ast.submodules().iter().map(|sm| ModuleEntry {
            name: sm.name.clone(),
            namespace: module_path.clone(),
            directory: directory.clone(),
            parent: actual_path.clone(),
        }));

        if let Err(error) = callback(ast) {
            let _ = diagnostics.add_report(error);
            return Outcome {
                value: None,
                diagnostics: diagnostics.finish().attach_session_sources(source_manager.clone()),
            };
        }
    }

    Outcome {
        value: Some(()),
        diagnostics: diagnostics.finish().attach_session_sources(source_manager.clone()),
    }
}
