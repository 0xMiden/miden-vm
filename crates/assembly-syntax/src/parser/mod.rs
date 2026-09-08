mod cst;
mod error;
#[cfg(test)]
mod tests;
mod value;

use alloc::{boxed::Box, collections::BTreeSet, string::ToString, sync::Arc, vec::Vec};

use miden_diagnostics::{
    DiagnosticCollector, IntoDiagnostic, Outcome, Report, SourceId, SourceKey, SourceMap,
    SourceSpan, TextRange,
};

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
pub type ModuleParseOutcome = Outcome<Box<ast::Module>>;

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
        source_id: SourceId,
        source: &str,
    ) -> ModuleParseOutcome {
        use alloc::borrow::Cow;

        let path = match path {
            Some(path) => match path
                .canonicalize()
                .and_then(|p| p.to_absolute().map(Cow::into_owned))
                .into_diagnostic()
            {
                Ok(path) => Some(Arc::<Path>::from(path)),
                Err(error) => {
                    let mut diagnostics = DiagnosticCollector::new();
                    let _ = diagnostics.add_report(error);
                    return Outcome {
                        result: Err(()),
                        diagnostics: diagnostics.finish(),
                    };
                },
            },
            None => None,
        };
        let source_span = match TextRange::try_from_usize(0, source.len()) {
            Ok(range) => SourceSpan::new(SourceKey::Session(source_id), None, range),
            Err(error) => {
                let mut diagnostics = DiagnosticCollector::new();
                let _ = diagnostics.add_report(Report::from_error(error));
                return Outcome {
                    result: Err(()),
                    diagnostics: diagnostics.finish(),
                };
            },
        };
        parse_forms_internal(source_id, source, &mut self.interned).and_then(|forms, collector| {
            let Outcome { result, diagnostics: sema_diagnostics } =
                sema::analyze(source_span, self.kind, path.as_deref(), forms);
            collector.merge(sema_diagnostics);
            result
        })
    }

    /// Parse a [ast::Module], `name`, from `path`.
    #[cfg(feature = "std")]
    pub fn parse_file<P>(
        &mut self,
        path: Option<&Path>,
        file_path: P,
        sources: &mut SourceMap,
    ) -> ModuleParseOutcome
    where
        P: AsRef<std::path::Path>,
    {
        use miden_diagnostics::{IntoDiagnostic, WrapErr};

        let file_path = file_path.as_ref();
        let source = match std::fs::read_to_string(file_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to load source file from '{}'", file_path.display()))
        {
            Ok(source) => source,
            Err(error) => {
                let mut diagnostics = DiagnosticCollector::new();
                let _ = diagnostics.add_report(error);
                return Outcome {
                    result: Err(()),
                    diagnostics: diagnostics.finish(),
                };
            },
        };
        let source_id = match sources.insert(file_path.display().to_string(), source.clone(), None)
        {
            Ok(source_id) => source_id,
            Err(error) => {
                let mut diagnostics = DiagnosticCollector::new();
                let _ = diagnostics.add_report(Report::from_error(error));
                return Outcome {
                    result: Err(()),
                    diagnostics: diagnostics.finish(),
                };
            },
        };
        self.parse(path, source_id, &source)
    }

    /// Parse a [ast::Module], `name`, from `source`.
    pub fn parse_str(
        &mut self,
        path: Option<&Path>,
        source: impl ToString,
        sources: &mut SourceMap,
    ) -> ModuleParseOutcome {
        let source = source.to_string();
        let display_name = path.map_or_else(|| "<anonymous>".to_string(), Path::to_string);
        let source_id = match sources.insert(display_name, source.clone(), None) {
            Ok(source_id) => source_id,
            Err(error) => {
                let mut diagnostics = DiagnosticCollector::new();
                let _ = diagnostics.add_report(Report::from_error(error));
                return Outcome {
                    result: Err(()),
                    diagnostics: diagnostics.finish(),
                };
            },
        };
        self.parse(path, source_id, &source)
    }
}

/// This is used in tests to parse `source` as a set of raw [ast::Form]s rather than as a
/// [ast::Module].
///
/// NOTE: This does _not_ run semantic analysis.
#[cfg(any(test, feature = "testing"))]
pub fn parse_forms(source_id: SourceId, source: &str) -> Outcome<Vec<ast::Form>> {
    let mut interned = BTreeSet::default();
    parse_forms_internal(source_id, source, &mut interned)
}

/// Parse `source` as a set of [ast::Form]s
///
/// Aside from catching syntax errors, this does little validation of the resulting forms, that is
/// handled by semantic analysis, which the caller is expected to perform next.
fn parse_forms_internal(
    source_id: SourceId,
    source: &str,
    interned: &mut BTreeSet<Arc<str>>,
) -> Outcome<Vec<ast::Form>> {
    cst::parse_forms(source_id, source, interned)
}

// DIRECTORY PARSER
// ================================================================================================

/// Read the root module and its supporting modules from the filesystem.
///
/// Filesystem, parsing, and semantic-analysis failures are returned as diagnostics. A recovered
/// root/support pair is present in the outcome when module loading can continue; callers choose a
/// [`FailurePolicy`](miden_diagnostics::FailurePolicy) at the application boundary.
#[cfg(feature = "std")]
pub fn read_modules_from_root(
    root: impl AsRef<std::path::Path>,
    namespace: Option<Arc<Path>>,
    kind: Option<ast::ModuleKind>,
    sources: &mut SourceMap,
) -> Outcome<(Box<ast::Module>, Vec<Box<ast::Module>>)> {
    match read_modules_from_root_impl(root, namespace, kind, sources) {
        Ok(outcome) => outcome,
        Err(report) => {
            let mut collector = DiagnosticCollector::default();
            collector.add_report(report);
            Outcome {
                result: Err(()),
                diagnostics: collector.finish(),
            }
        },
    }
}

#[cfg(feature = "std")]
#[allow(clippy::vec_box)]
fn read_modules_from_root_impl(
    root: impl AsRef<std::path::Path>,
    namespace: Option<Arc<Path>>,
    kind: Option<ast::ModuleKind>,
    sources: &mut SourceMap,
) -> Result<Outcome<(Box<ast::Module>, Vec<Box<ast::Module>>)>, Report> {
    let root = root.as_ref();
    let root = Arc::<std::path::Path>::from(
        root.canonicalize()
            .map_err(|err| {
                Report::msg(format!("invalid root module path '{}': {err}", root.display()))
            })?
            .into_boxed_path(),
    );

    // Make sure the path has the right file extension
    if root
        .extension()
        .is_none_or(|ext| !ext.eq_ignore_ascii_case(ast::Module::FILE_EXTENSION))
    {
        return Err(Report::msg(format!(
            "invalid root module path '{}': expected a .masm file",
            root.display()
        )));
    }

    // Make sure it is a file
    if !root.is_file() {
        return Err(Report::msg(format!(
            "invalid root module path '{}': not a file",
            root.display()
        )));
    }

    // Capture the parent directory for resolving submodules
    let root_dir = root
        .parent()
        .ok_or_else(|| {
            Report::msg(format!(
                "invalid root module path '{}': expected path to have a parent directory",
                root.display()
            ))
        })?
        .to_path_buf();

    let mut seen = BTreeSet::<Arc<Path>>::new();
    let mut modules = Vec::new();
    let mut diagnostics = DiagnosticCollector::new();

    let mut parser = ModuleParser::new(kind);
    let Outcome {
        result: root_ast,
        diagnostics: root_diagnostics,
    } = parser.parse_file(namespace.as_deref(), &root, sources);
    let _ = diagnostics.merge(root_diagnostics);
    let Ok(root_ast) = root_ast else {
        return Ok(Outcome {
            result: Err(()),
            diagnostics: diagnostics.finish(),
        });
    };

    let namespace = Arc::<Path>::from(root_ast.path().to_path_buf().into_boxed_path());
    let submodules = root_ast.submodules().to_vec();
    seen.insert(namespace.clone());
    let Outcome {
        result: walked,
        diagnostics: walk_diagnostics,
    } = walk_module_tree(namespace, root, root_dir, submodules, sources, |module| {
        if !seen.insert(module.path().into()) {
            Err(Report::msg(format!("duplicate module '{}'", module.path())))
        } else {
            modules.push(module);
            Ok(())
        }
    });
    let _ = diagnostics.merge(walk_diagnostics);
    if walked.is_err() {
        return Ok(Outcome {
            result: Err(()),
            diagnostics: diagnostics.finish(),
        });
    }

    Ok(Outcome {
        result: Ok((root_ast, modules)),
        diagnostics: diagnostics.finish(),
    })
}

#[cfg(feature = "std")]
pub fn walk_module_tree<F>(
    namespace: Arc<Path>,
    root: Arc<std::path::Path>,
    current_dir: std::path::PathBuf,
    submodules: Vec<ast::SubmoduleDecl>,
    sources: &mut SourceMap,
    mut callback: F,
) -> Outcome<()>
where
    F: FnMut(Box<ast::Module>) -> Result<(), Report>,
{
    use miden_debug_types::Uri;
    use miden_diagnostics::Spanned;

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
                result: Err(()),
                diagnostics: diagnostics.finish(),
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
                    result: Err(()),
                    diagnostics: diagnostics.finish(),
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
                result: Err(()),
                diagnostics: diagnostics.finish(),
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
                result: Err(()),
                diagnostics: diagnostics.finish(),
            };
        }

        let mut parser = ModuleParser::new(Some(ast::ModuleKind::Library));
        let module_path = Arc::<Path>::from(entry.namespace.join(&entry.name).into_boxed_path());
        let Outcome {
            result: ast,
            diagnostics: module_diagnostics,
        } = parser.parse_file(Some(&module_path), &actual_path, sources);
        let _ = diagnostics.merge(module_diagnostics);
        let Ok(ast) = ast else {
            return Outcome {
                result: Err(()),
                diagnostics: diagnostics.finish(),
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
                result: Err(()),
                diagnostics: diagnostics.finish(),
            };
        }
    }

    Outcome {
        result: Ok(()),
        diagnostics: diagnostics.finish(),
    }
}
