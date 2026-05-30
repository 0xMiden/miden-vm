mod cst;
mod error;
#[cfg(test)]
mod tests;
mod value;

use alloc::{boxed::Box, collections::BTreeSet, string::ToString, sync::Arc, vec::Vec};

use miden_debug_types::{SourceFile, SourceLanguage, SourceManager, Uri};
use miden_utils_diagnostics::{IntoDiagnostic, Report};

pub use self::{
    cst::parse_inline_masm,
    error::{BinErrorKind, HexErrorKind, LiteralErrorKind, ParsingError},
    value::{IntValue, PushValue, WordValue},
};
use crate::{Path, ast, sema};

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
    /// When true, all warning diagnostics are promoted to error severity
    warnings_as_errors: bool,
}

impl ModuleParser {
    /// Construct a new parser for the given `kind` of [ast::Module].
    pub fn new(kind: Option<ast::ModuleKind>) -> Self {
        Self {
            kind,
            interned: Default::default(),
            warnings_as_errors: false,
        }
    }

    /// Configure this parser so that any warning diagnostics are promoted to errors.
    pub fn set_warnings_as_errors(&mut self, yes: bool) {
        self.warnings_as_errors = yes;
    }

    /// Parse a [ast::Module] from `source`, and give it the provided `path`.
    pub fn parse(
        &mut self,
        path: Option<&Path>,
        source: Arc<SourceFile>,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<ast::Module>, Report> {
        use alloc::borrow::Cow;

        let path = match path {
            Some(path) => Some(Arc::<Path>::from(
                path.canonicalize()
                    .and_then(|p| p.to_absolute().map(Cow::into_owned))
                    .into_diagnostic()?,
            )),
            None => None,
        };
        let forms = parse_forms_internal(source.clone(), &mut self.interned)?;
        sema::analyze(
            source,
            self.kind,
            path.as_deref(),
            forms,
            self.warnings_as_errors,
            source_manager,
        )
        .map_err(Report::new)
    }

    /// Parse a [ast::Module], `name`, from `path`.
    #[cfg(feature = "std")]
    pub fn parse_file<P>(
        &mut self,
        path: Option<&Path>,
        file_path: P,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<ast::Module>, Report>
    where
        P: AsRef<std::path::Path>,
    {
        use miden_debug_types::SourceManagerExt;
        use miden_utils_diagnostics::{IntoDiagnostic, WrapErr};

        let file_path = file_path.as_ref();
        let source_file =
            source_manager.load_file(file_path).into_diagnostic().wrap_err_with(|| {
                format!("failed to load source file from '{}'", file_path.display())
            })?;
        self.parse(path, source_file, source_manager)
    }

    /// Parse a [ast::Module], `name`, from `source`.
    pub fn parse_str(
        &mut self,
        path: Option<&Path>,
        source: impl ToString,
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<ast::Module>, Report> {
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
pub fn parse_forms(source: Arc<SourceFile>) -> Result<Vec<ast::Form>, Report> {
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
) -> Result<Vec<ast::Form>, Report> {
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
    warnings_as_errors: bool,
) -> Result<(Box<ast::Module>, Vec<Box<ast::Module>>), Report> {
    use miden_utils_diagnostics::report;

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

    let mut parser = ModuleParser::new(kind);
    parser.set_warnings_as_errors(warnings_as_errors);
    let root_ast = parser.parse_file(namespace.as_deref(), &root, source_manager.clone())?;

    let namespace = Arc::<Path>::from(root_ast.path().to_path_buf().into_boxed_path());
    let submodules = root_ast.submodules().to_vec();
    seen.insert(namespace.clone());
    walk_module_tree(
        namespace,
        root,
        root_dir,
        submodules,
        source_manager,
        warnings_as_errors,
        |module| {
            if seen.contains(module.path()) {
                Err(report!("duplicate module '{0}'", module.path()))
            } else {
                modules.push(module);
                Ok(())
            }
        },
    )?;

    Ok((root_ast, modules))
}

#[cfg(feature = "std")]
pub fn walk_module_tree<F>(
    namespace: Arc<Path>,
    root: Arc<std::path::Path>,
    current_dir: std::path::PathBuf,
    submodules: Vec<ast::SubmoduleDecl>,
    source_manager: Arc<dyn SourceManager>,
    warnings_as_errors: bool,
    mut callback: F,
) -> Result<(), Report>
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
            let source_file = source_manager.get(span.source_id()).ok();
            return Err(ParsingError::SelfReferentialSubmodule {
                name: entry.name.clone(),
                parent_module_uri: Uri::from(entry.parent),
                span,
                source_file,
            }
            .into());
        }

        let actual_path = if mod_file.is_file() {
            if mod_dir_mod_masm.is_file() {
                let span = entry.name.span();
                let source_file = source_manager.get(span.source_id()).ok();
                return Err(ParsingError::AmbiguousSubmoduleLocation {
                    name: entry.name,
                    first: Uri::from(mod_file),
                    second: Uri::from(mod_dir_mod_masm),
                    span,
                    source_file,
                }
                .into());
            }
            mod_file
        } else if mod_dir_mod_masm.is_file() {
            mod_dir_mod_masm
        } else {
            let span = entry.name.span();
            let source_file = source_manager.get(span.source_id()).ok();
            return Err(ParsingError::UndefinedSubmodule {
                name: entry.name,
                basename: basename.into_boxed_str(),
                directory: Uri::from(mod_dir),
                span,
                source_file,
            }
            .into());
        };

        let actual_path = Arc::<std::path::Path>::from(actual_path);
        if !visited.insert(actual_path.clone()) {
            let span = entry.name.span();
            let source_file = source_manager.get(span.source_id()).ok();
            return Err(ParsingError::DuplicateSubmoduleSource {
                name: entry.name,
                module_uri: Uri::from(actual_path.as_ref()),
                span,
                source_file,
            }
            .into());
        }

        let mut parser = ModuleParser::new(Some(ast::ModuleKind::Library));
        parser.set_warnings_as_errors(warnings_as_errors);
        let module_path = Arc::<Path>::from(entry.namespace.join(&entry.name).into_boxed_path());
        let ast = parser.parse_file(Some(&module_path), &actual_path, source_manager.clone())?;

        let directory = Arc::<std::path::Path>::from(mod_dir);
        worklist.extend(ast.submodules().iter().map(|sm| ModuleEntry {
            name: sm.name.clone(),
            namespace: module_path.clone(),
            directory: directory.clone(),
            parent: actual_path.clone(),
        }));

        callback(ast)?;
    }

    Ok(())
}
