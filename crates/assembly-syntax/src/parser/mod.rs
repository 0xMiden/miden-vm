/// Simple macro used in the grammar definition for constructing spans
macro_rules! span {
    ($id:expr, $l:expr, $r:expr) => {
        ::miden_debug_types::SourceSpan::new($id, $l..$r)
    };
    ($id:expr, $i:expr) => {
        ::miden_debug_types::SourceSpan::at($id, $i)
    };
}

lalrpop_util::lalrpop_mod!(
    #[allow(clippy::all)]
    grammar,
    "/parser/grammar.rs"
);

mod error;
mod lexer;
mod scanner;
mod token;

use alloc::{boxed::Box, collections::BTreeSet, string::ToString, sync::Arc, vec::Vec};

use miden_debug_types::{SourceFile, SourceLanguage, SourceManager, Uri};
use miden_utils_diagnostics::Report;

pub use self::{
    error::{BinErrorKind, HexErrorKind, LiteralErrorKind, ParsingError},
    lexer::Lexer,
    scanner::Scanner,
    token::{BinEncodedValue, DocumentationType, IntValue, PushValue, Token, WordValue},
};
use crate::{Path, ast, sema};

// TYPE ALIASES
// ================================================================================================

type ParseError<'a> = lalrpop_util::ParseError<u32, Token<'a>, ParsingError>;

// MODULE PARSER
// ================================================================================================

/// This is a wrapper around the lower-level parser infrastructure which handles orchestrating all
/// of the pieces needed to parse a [ast::Module] from source, and run semantic analysis on it.
#[derive(Default)]
pub struct ModuleParser {
    /// The kind of module we're parsing.
    ///
    /// This is used when performing semantic analysis to detect when various invalid constructions
    /// are encountered, such as use of the `syscall` instruction in a kernel module.
    kind: ast::ModuleKind,
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
    pub fn new(kind: ast::ModuleKind) -> Self {
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
        path: impl AsRef<Path>,
        source: Arc<SourceFile>,
    ) -> Result<Box<ast::Module>, Report> {
        let path = path.as_ref();
        let forms = parse_forms_internal(source.clone(), &mut self.interned)
            .map_err(|err| Report::new(err).with_source_code(source.clone()))?;
        sema::analyze(source, self.kind, path, forms, self.warnings_as_errors).map_err(Report::new)
    }

    /// Parse a [ast::Module], `name`, from `path`.
    #[cfg(feature = "std")]
    pub fn parse_file<N, P>(
        &mut self,
        name: N,
        path: P,
        source_manager: &dyn SourceManager,
    ) -> Result<Box<ast::Module>, Report>
    where
        N: AsRef<Path>,
        P: AsRef<std::path::Path>,
    {
        use miden_debug_types::SourceManagerExt;
        use miden_utils_diagnostics::{IntoDiagnostic, WrapErr};

        let path = path.as_ref();
        let source_file = source_manager
            .load_file(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to load source file from '{}'", path.display()))?;
        self.parse(name, source_file)
    }

    /// Parse a [ast::Module], `name`, from `source`.
    pub fn parse_str(
        &mut self,
        name: impl AsRef<Path>,
        source: impl ToString,
        source_manager: &dyn SourceManager,
    ) -> Result<Box<ast::Module>, Report> {
        use miden_debug_types::SourceContent;

        let name = name.as_ref();
        let uri = Uri::from(name.as_str().to_string().into_boxed_str());
        let content = SourceContent::new(
            SourceLanguage::Masm,
            uri.clone(),
            source.to_string().into_boxed_str(),
        );
        let source_file = source_manager.load_from_raw_parts(uri, content);
        self.parse(name, source_file)
    }
}

/// This is used in tests to parse `source` as a set of raw [ast::Form]s rather than as a
/// [ast::Module].
///
/// NOTE: This does _not_ run semantic analysis.
#[cfg(any(test, feature = "testing"))]
pub fn parse_forms(source: Arc<SourceFile>) -> Result<Vec<ast::Form>, ParsingError> {
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
) -> Result<Vec<ast::Form>, ParsingError> {
    let source_id = source.id();
    let scanner = Scanner::new(source.as_str());
    let lexer = Lexer::new(source_id, scanner);
    let felt_type = Arc::new(ast::types::ArrayType::new(ast::types::Type::Felt, 4));
    grammar::FormsParser::new()
        .parse(source_id, interned, &felt_type, core::marker::PhantomData, lexer)
        .map_err(|err| ParsingError::from_parse_error(source_id, err))
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
pub fn read_modules_from_dir(
    dir: impl AsRef<std::path::Path>,
    namespace: impl AsRef<Path>,
    source_manager: &dyn SourceManager,
) -> Result<impl Iterator<Item = Box<ast::Module>>, Report> {
    use std::collections::{BTreeMap, btree_map::Entry};

    use miden_utils_diagnostics::{IntoDiagnostic, WrapErr, report};
    use module_walker::{ModuleEntry, WalkModules};

    let dir = dir.as_ref();
    if !dir.is_dir() {
        return Err(report!("the provided path '{}' is not a valid directory", dir.display()));
    }

    // mod.masm is not allowed in the root directory
    if dir.join(ast::Module::ROOT_FILENAME).exists() {
        return Err(report!("{} is not allowed in the root directory", ast::Module::ROOT_FILENAME));
    }

    let mut modules = BTreeMap::default();

    let walker = WalkModules::new(namespace.as_ref().to_path_buf(), dir)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to load modules from '{}'", dir.display()))?;
    for entry in walker {
        let ModuleEntry { mut name, source_path } = entry?;
        if name.last().unwrap() == ast::Module::ROOT {
            name.pop();
        }

        // Parse module at the given path
        let mut parser = ModuleParser::new(ast::ModuleKind::Library);
        let ast = parser.parse_file(&name, &source_path, source_manager)?;
        match modules.entry(name) {
            Entry::Occupied(ref entry) => {
                return Err(report!("duplicate module '{0}'", entry.key().clone()));
            },
            Entry::Vacant(entry) => {
                entry.insert(ast);
            },
        }
    }

    Ok(modules.into_values())
}

#[cfg(feature = "std")]
mod module_walker {
    use std::{
        ffi::OsStr,
        fs::{self, DirEntry, FileType},
        io,
        path::{Path, PathBuf},
    };

    use miden_utils_diagnostics::{IntoDiagnostic, Report, report};

    use crate::{Path as LibraryPath, PathBuf as LibraryPathBuf, ast::Module};

    pub struct ModuleEntry {
        pub name: LibraryPathBuf,
        pub source_path: PathBuf,
    }

    pub struct WalkModules<'a> {
        namespace: LibraryPathBuf,
        root: &'a Path,
        stack: alloc::collections::VecDeque<io::Result<DirEntry>>,
    }

    impl<'a> WalkModules<'a> {
        pub fn new(namespace: LibraryPathBuf, path: &'a Path) -> io::Result<Self> {
            use alloc::collections::VecDeque;

            let stack = VecDeque::from_iter(fs::read_dir(path)?);

            Ok(Self { namespace, root: path, stack })
        }

        fn next_entry(
            &mut self,
            entry: &DirEntry,
            ty: &FileType,
        ) -> Result<Option<ModuleEntry>, Report> {
            if ty.is_dir() {
                let dir = entry.path();
                self.stack.extend(fs::read_dir(dir).into_diagnostic()?);
                return Ok(None);
            }

            let mut file_path = entry.path();
            let is_module = file_path
                .extension()
                .map(|ext| ext == AsRef::<OsStr>::as_ref(Module::FILE_EXTENSION))
                .unwrap_or(false);
            if !is_module {
                return Ok(None);
            }

            // Remove the file extension and the root prefix, leaving a namespace-relative path
            file_path.set_extension("");
            if file_path.is_dir() {
                return Err(report!(
                    "file and directory with same name are not allowed: {}",
                    file_path.display()
                ));
            }
            let relative_path = file_path
                .strip_prefix(self.root)
                .expect("expected path to be a child of the root directory");

            // Construct a [LibraryPath] from the path components, after validating them
            let mut libpath = self.namespace.clone();
            for component in relative_path.iter() {
                let component = component.to_str().ok_or_else(|| {
                    let p = entry.path();
                    report!("{} is an invalid directory entry", p.display())
                })?;
                LibraryPath::validate(component).into_diagnostic()?;
                libpath.push(component);
            }
            Ok(Some(ModuleEntry { name: libpath, source_path: entry.path() }))
        }
    }

    impl Iterator for WalkModules<'_> {
        type Item = Result<ModuleEntry, Report>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                let entry = self
                    .stack
                    .pop_front()?
                    .and_then(|entry| entry.file_type().map(|ft| (entry, ft)))
                    .into_diagnostic();

                match entry {
                    Ok((ref entry, ref file_type)) => {
                        match self.next_entry(entry, file_type).transpose() {
                            None => continue,
                            result => break result,
                        }
                    },
                    Err(err) => break Some(Err(err)),
                }
            }
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::assert_matches;
    use miden_debug_types::SourceId;

    use super::*;

    // This test checks the lexer behavior with regard to tokenizing `exp(.u?[\d]+)?`
    #[test]
    fn lex_exp() {
        let source_id = SourceId::default();
        let scanner = Scanner::new("begin exp.u9 end");
        let mut lexer = Lexer::new(source_id, scanner).map(|result| result.map(|(_, t, _)| t));
        assert_matches!(lexer.next(), Some(Ok(Token::Begin)));
        assert_matches!(lexer.next(), Some(Ok(Token::ExpU)));
        assert_matches!(lexer.next(), Some(Ok(Token::Int(n))) if n == 9);
        assert_matches!(lexer.next(), Some(Ok(Token::End)));
    }

    #[test]
    fn lex_block() {
        let source_id = SourceId::default();
        let scanner = Scanner::new(
            "\
const ERR1 = 1

begin
    u32assertw
    u32assertw.err=ERR1
    u32assertw.err=2
end
",
        );
        let mut lexer = Lexer::new(source_id, scanner).map(|result| result.map(|(_, t, _)| t));
        assert_matches!(lexer.next(), Some(Ok(Token::Const)));
        assert_matches!(lexer.next(), Some(Ok(Token::ConstantIdent("ERR1"))));
        assert_matches!(lexer.next(), Some(Ok(Token::Equal)));
        assert_matches!(lexer.next(), Some(Ok(Token::Int(1))));
        assert_matches!(lexer.next(), Some(Ok(Token::Begin)));
        assert_matches!(lexer.next(), Some(Ok(Token::U32Assertw)));
        assert_matches!(lexer.next(), Some(Ok(Token::U32Assertw)));
        assert_matches!(lexer.next(), Some(Ok(Token::Dot)));
        assert_matches!(lexer.next(), Some(Ok(Token::Err)));
        assert_matches!(lexer.next(), Some(Ok(Token::Equal)));
        assert_matches!(lexer.next(), Some(Ok(Token::ConstantIdent("ERR1"))));
        assert_matches!(lexer.next(), Some(Ok(Token::U32Assertw)));
        assert_matches!(lexer.next(), Some(Ok(Token::Dot)));
        assert_matches!(lexer.next(), Some(Ok(Token::Err)));
        assert_matches!(lexer.next(), Some(Ok(Token::Equal)));
        assert_matches!(lexer.next(), Some(Ok(Token::Int(2))));
        assert_matches!(lexer.next(), Some(Ok(Token::End)));
        assert_matches!(lexer.next(), Some(Ok(Token::Eof)));
    }

    #[test]
    fn lex_emit() {
        let source_id = SourceId::default();
        let scanner = Scanner::new(
            "\
begin
    push.1
    emit.event(\"abc\")
end
",
        );
        let mut lexer = Lexer::new(source_id, scanner).map(|result| result.map(|(_, t, _)| t));
        assert_matches!(lexer.next(), Some(Ok(Token::Begin)));
        assert_matches!(lexer.next(), Some(Ok(Token::Push)));
        assert_matches!(lexer.next(), Some(Ok(Token::Dot)));
        assert_matches!(lexer.next(), Some(Ok(Token::Int(1))));
        assert_matches!(lexer.next(), Some(Ok(Token::Emit)));
        assert_matches!(lexer.next(), Some(Ok(Token::Dot)));
        assert_matches!(lexer.next(), Some(Ok(Token::Event)));
        assert_matches!(lexer.next(), Some(Ok(Token::Lparen)));
        assert_matches!(lexer.next(), Some(Ok(Token::QuotedIdent("abc"))));
        assert_matches!(lexer.next(), Some(Ok(Token::Rparen)));
        assert_matches!(lexer.next(), Some(Ok(Token::End)));
        assert_matches!(lexer.next(), Some(Ok(Token::Eof)));
    }
}
