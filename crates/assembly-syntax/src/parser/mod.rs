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
    #[expect(clippy::all)]
    #[expect(clippy::redundant_closure_for_method_calls)]
    #[expect(clippy::trivially_copy_pass_by_ref)]
    #[expect(unused_lifetimes)]
    #[expect(unused_qualifications)]
    grammar,
    "/parser/grammar.rs"
);

#[cfg(feature = "std")]
mod cst_lowering;
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

#[cfg_attr(not(any(test, feature = "testing")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalParserBackend {
    Legacy,
    #[cfg(feature = "std")]
    Cst,
}

impl Default for InternalParserBackend {
    fn default() -> Self {
        #[cfg(feature = "std")]
        {
            return Self::Cst;
        }

        #[cfg(not(feature = "std"))]
        Self::Legacy
    }
}

#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// Selects which raw parser implementation to use when parsing forms in tests or differential
/// validation.
pub enum ParserBackend {
    /// Uses the original LALRPOP-based parser.
    Legacy,
    #[cfg(feature = "std")]
    /// Uses the lossless CST parser followed by CST-to-AST lowering.
    Cst,
}

#[cfg(any(test, feature = "testing"))]
impl Default for ParserBackend {
    fn default() -> Self {
        #[cfg(feature = "std")]
        {
            return Self::Cst;
        }

        #[cfg(not(feature = "std"))]
        Self::Legacy
    }
}

#[cfg(any(test, feature = "testing"))]
impl From<ParserBackend> for InternalParserBackend {
    fn from(backend: ParserBackend) -> Self {
        match backend {
            ParserBackend::Legacy => Self::Legacy,
            #[cfg(feature = "std")]
            ParserBackend::Cst => Self::Cst,
        }
    }
}

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
        source_manager: Arc<dyn SourceManager>,
    ) -> Result<Box<ast::Module>, Report> {
        let path = path.as_ref();
        if let Err(err) = Path::validate(path.as_str()) {
            return Err(Report::msg(err.to_string()).with_source_code(source));
        }
        let forms = parse_forms_internal(source.clone(), &mut self.interned)
            .map_err(|err| Report::new(err).with_source_code(source.clone()))?;
        sema::analyze(source, self.kind, path, forms, self.warnings_as_errors, source_manager)
            .map_err(Report::new)
    }

    /// Parse a [ast::Module], `name`, from `path`.
    #[cfg(feature = "std")]
    pub fn parse_file<N, P>(
        &mut self,
        name: N,
        path: P,
        source_manager: Arc<dyn SourceManager>,
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
        self.parse(name, source_file, source_manager)
    }

    /// Parse a [ast::Module], `name`, from `source`.
    pub fn parse_str(
        &mut self,
        name: impl AsRef<Path>,
        source: impl ToString,
        source_manager: Arc<dyn SourceManager>,
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
        self.parse(name, source_file, source_manager)
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

/// Parses raw forms with an explicitly selected backend.
///
/// This is intended for tests and differential validation. Ordinary callers should use
/// [`parse_forms`] or [`ModuleParser`] and accept the default backend.
#[cfg(any(test, feature = "testing"))]
pub fn parse_forms_with_backend(
    source: Arc<SourceFile>,
    backend: ParserBackend,
) -> Result<Vec<ast::Form>, ParsingError> {
    let mut interned = BTreeSet::default();
    parse_forms_internal_with_backend(source, &mut interned, backend.into())
}

/// Parse `source` as a set of [ast::Form]s
///
/// Aside from catching syntax errors, this does little validation of the resulting forms, that is
/// handled by semantic analysis, which the caller is expected to perform next.
fn parse_forms_internal(
    source: Arc<SourceFile>,
    interned: &mut BTreeSet<Arc<str>>,
) -> Result<Vec<ast::Form>, ParsingError> {
    parse_forms_internal_with_backend(source, interned, InternalParserBackend::default())
}

fn parse_forms_internal_with_backend(
    source: Arc<SourceFile>,
    interned: &mut BTreeSet<Arc<str>>,
    backend: InternalParserBackend,
) -> Result<Vec<ast::Form>, ParsingError> {
    match backend {
        InternalParserBackend::Legacy => parse_forms_with_lalrpop(source, interned),
        #[cfg(feature = "std")]
        InternalParserBackend::Cst => cst_lowering::parse_forms_from_cst(source, interned),
    }
}

fn parse_forms_with_lalrpop(
    source: Arc<SourceFile>,
    interned: &mut BTreeSet<Arc<str>>,
) -> Result<Vec<ast::Form>, ParsingError> {
    let felt_type = Arc::new(ast::types::ArrayType::new(ast::types::Type::Felt, 4));
    let source_id = source.id();
    let scanner = Scanner::new(source.as_str());
    let lexer = Lexer::new(source_id, scanner);
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
    source_manager: Arc<dyn SourceManager>,
    warnings_as_errors: bool,
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
        parser.set_warnings_as_errors(warnings_as_errors);
        let ast = parser.parse_file(&name, &source_path, source_manager.clone())?;
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
            ty: FileType,
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
                    Ok((ref entry, file_type)) => {
                        match self.next_entry(entry, file_type).transpose() {
                            None => {},
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
    use std::{
        fs,
        path::{Path as FsPath, PathBuf},
        sync::Arc,
    };

    use miden_core::assert_matches;
    use miden_debug_types::{SourceFile, SourceId, SourceLanguage, Uri};

    use super::*;

    fn test_source_file(source: &str) -> Arc<SourceFile> {
        Arc::new(SourceFile::new(
            SourceId::default(),
            SourceLanguage::Masm,
            Uri::new("memory:///parser-backend-test.masm"),
            source.to_string().into_boxed_str(),
        ))
    }

    #[cfg(feature = "std")]
    fn repo_root() -> PathBuf {
        FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(FsPath::parent)
            .expect("workspace root should be two levels above crates/assembly-syntax")
            .to_path_buf()
    }

    #[cfg(feature = "std")]
    fn checked_in_masm_corpus() -> Vec<PathBuf> {
        let root = repo_root();
        let mut files = Vec::new();
        for relative in [
            "crates/lib/core/asm",
            "crates/project/examples",
            "miden-vm/masm-examples",
            "miden-vm/tests/integration/cli/data",
        ] {
            collect_masm_files(&root.join(relative), &mut files);
        }
        files.sort();
        files
    }

    #[cfg(feature = "std")]
    fn collect_masm_files(dir: &FsPath, files: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()));
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| {
                panic!("failed to read a directory entry under {}: {error}", dir.display())
            });
            let path = entry.path();
            if path.is_dir() {
                collect_masm_files(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "masm") {
                files.push(path);
            }
        }
    }

    #[cfg(feature = "std")]
    fn load_source_file(path: &FsPath) -> Arc<SourceFile> {
        let source = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        Arc::new(SourceFile::new(
            SourceId::default(),
            SourceLanguage::Masm,
            Uri::new(format!("file://{}", path.display())),
            source.into_boxed_str(),
        ))
    }

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

    #[test]
    fn lex_invalid_token_after_whitespace_returns_error() {
        let source_id = SourceId::default();
        let scanner = Scanner::new("begin \u{0001}\nend\n");
        let mut lexer = Lexer::new(source_id, scanner).map(|result| result.map(|(_, t, _)| t));

        assert_matches!(lexer.next(), Some(Ok(Token::Begin)));
        assert_matches!(
            lexer.next(),
            Some(Err(ParsingError::InvalidToken { span })) if span.into_range() == (6..7)
        );
    }

    #[test]
    fn lex_invalid_underscore_token_span() {
        let source_id = SourceId::default();
        let scanner = Scanner::new("begin _-\nend\n");
        let mut lexer = Lexer::new(source_id, scanner).map(|result| result.map(|(_, t, _)| t));

        assert_matches!(lexer.next(), Some(Ok(Token::Begin)));
        assert_matches!(
            lexer.next(),
            Some(Err(ParsingError::InvalidToken { span })) if span.into_range() == (6..7)
        );
    }

    #[test]
    fn lex_single_char_token_and_ident_spans() {
        let source_id = SourceId::default();
        let scanner = Scanner::new("@\nA\n");
        let mut lexer = Lexer::new(source_id, scanner);

        assert_matches!(lexer.next(), Some(Ok((0, Token::At, 1))));
        assert_matches!(lexer.next(), Some(Ok((2, Token::ConstantIdent("A"), 3))));
    }

    #[test]
    fn overlong_path_component_is_rejected_without_panic() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        use crate::{
            debuginfo::DefaultSourceManager,
            parse::{Parse, ParseOptions},
        };

        let big_component = "a".repeat(256);
        let source = format!("begin\n    exec.{big_component}::x::foo\nend\n");

        let source_manager = Arc::new(DefaultSourceManager::default());
        let parsed = catch_unwind(AssertUnwindSafe(|| {
            source.parse_with_options(source_manager, ParseOptions::default())
        }));

        assert!(parsed.is_ok(), "parsing panicked, expected a structured error");
        let err = parsed.unwrap().expect_err("parsing succeeded, expected an error");
        crate::assert_diagnostic!(err, "length exceeds the maximum of 255 bytes");
    }

    #[cfg(feature = "std")]
    #[test]
    fn parse_forms_uses_cst_backend_by_default_under_std() {
        let source = test_source_file(
            "\
const ERR = 1
begin
    push.1
    add
end
",
        );

        let default = parse_forms(source.clone()).expect("default parser should succeed");
        let cst = parse_forms_with_backend(source.clone(), ParserBackend::Cst)
            .expect("cst backend should succeed");
        let legacy = parse_forms_with_backend(source, ParserBackend::Legacy)
            .expect("legacy parser should succeed");

        assert_eq!(default, cst);
        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_top_level_form_sequences() {
        let source = test_source_file(
            "\
#! Module docs line 1
#! Module docs line 2

#! Import docs
use std::math::u64

#! Constant docs
const ERR = 1

type FeltAlias = felt
adv_map TABLE = [1, 2]
begin
    nop
end

@locals(1)
pub proc foo
    loc_load.0
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_doc_comment_trimming() {
        let source = test_source_file(
            "\
#! heading
#!  - bullet
#!    continuation

#!  item docs
const VALUE = 1
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_doc_kind_after_leading_line_comment() {
        let source = test_source_file(
            "\
# heading comment

#! item docs
pub proc foo
    nop
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_path_import_forms() {
        let source = test_source_file(
            "\
use std::math::u64
pub use ::std::math::u64->math_u64
use foo::\"miden::base/account@0.1.0\"->account
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_digest_import_forms() {
        let source = test_source_file(
            "\
use 0x0000000000000000000000000000000000000000000000000000000000000000->entry
pub use 0x0000000000000000000000000000000000000000000000000000000000000000->public_entry
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_unnamed_digest_imports() {
        let source = test_source_file(
            "\
use 0x0000000000000000000000000000000000000000000000000000000000000000
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert_matches!(legacy, Err(ParsingError::UnnamedReexportOfMastRoot { .. }));
        assert_matches!(cst, Err(ParsingError::UnnamedReexportOfMastRoot { .. }));
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_invalid_digest_imports() {
        let source = test_source_file("use 0x1234->entry\n");

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert_matches!(legacy, Err(ParsingError::InvalidMastRoot { .. }));
        assert_matches!(cst, Err(ParsingError::InvalidMastRoot { .. }));
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_constant_forms() {
        let source = test_source_file(
            "\
const WORD = [1, 2, 3, 4]
const DIGEST = word(\"miden::digest\")
const EVENT_ID = event(\"miden::event\")
const VALUE = (parts::COUNT + 3) // 2
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_string_constant_forms() {
        let source = test_source_file("const ERR = \"failed to load the circuit description\"\n");

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_type_alias_forms() {
        let source = test_source_file(
            "\
type WordAlias = word
type Buffer = ptr<u8, addrspace(byte)>
type Digest = [u32; 4]
type Point = struct @align(16) { x: u32, y: ptr<u8, addrspace(byte)> }
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_enum_forms() {
        let source = test_source_file(
            "\
enum Tag : u8 {
    A,
    B = 2,
    C = B * 2,
    D,
}

pub enum Result : felt {
    OK = 1,
    ERR = OK + 1,
}
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_procedure_signatures() {
        let source = test_source_file(
            "\
pub proc println(message: ptr<u8, addrspace(byte)>) -> ptr<u8, addrspace(byte)>
    nop
end

pub proc classify(value: felt) -> (ok: i1, words: [u32; 4])
    push.1
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_advice_map_and_begin_forms() {
        let source = test_source_file(
            "\
adv_map TABLE = [1, 2, 3]
adv_map DIGEST([1, 2, 3, 4]) = [5, 6]

begin
    push.1
    add
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_procedure_attributes() {
        let source = test_source_file(
            "\
@inline
@storage(offset = 1)
@storage(size = 2)
@callconv(\"C\")
@locals(4)
pub proc foo(a: felt) -> felt
    push.1
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_nested_structured_blocks() {
        let source = test_source_file(
            "\
const COUNT = 3

begin
    if.true
        add.0
    else
        push.1
    end

    if.false
        push.2
    else
        mul
    end

    while.true
        repeat.COUNT
            push.1
        end
        neq.0
    end
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_primitive_instruction_blocks() {
        let source = test_source_file(
            "\
begin
    add
    eq
    dup
    swap
    assert
    adv.insert_hdword
    adv.push_mapvaln
    emit
    debug.stack
    mem_load
    u32div
    add.1
    dup.3
    adv.push_mapvaln.4
    u32shl.1
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_immediate_instruction_blocks() {
        let source = test_source_file(
            "\
begin
    add.1
    eq.FLAG
    lt.3
    exp.u32
    exp.POWER
    mem_load.0b1010
    locaddr.LOCAL
    adv_push.1
    dup.3
    swap.2
    movup.4
    adv.push_mapvaln.8
    u32div.1
    u32wrapping_mul.0
    u32and.MASK
    u32shl.SHIFT
    debug.stack.4
    push.1
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_extended_instruction_blocks() {
        let source = test_source_file(
            "\
begin
    push.1.2.3
    push.[1,2,3,4]
    push.[1,2,3,4][1]
    push.[1,2,3,4][1..3]
    exec.foo
    call.foo::bar
    syscall.0x065c394c00227acff3545da5493cf1b79d9a9f5628db553d240edf8ef0cca04a
    procref.foo::bar
    debug.adv_stack
    debug.adv_stack.2
    debug.mem.1
    debug.mem.1.2
    debug.local.3
    debug.local.3.4
    emit.EVENT_ID
    emit.event(\"abc\")
    trace.7
    assert.err=\"oops\"
    u32assert.err=ERR_CODE
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
            .expect("legacy parser should succeed");
        let cst = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect("cst backend should succeed");

        assert_eq!(cst, legacy);
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_matches_legacy_checked_in_masm_corpus() {
        let files = checked_in_masm_corpus();
        assert!(
            !files.is_empty(),
            "expected the checked-in MASM corpus to contain at least one source file"
        );

        for path in files {
            let source = load_source_file(&path);
            let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
            let cst = parse_forms_with_backend(source, ParserBackend::Cst);
            assert_eq!(cst, legacy, "parser backend mismatch for {}", path.display());
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_unqualified_imports() {
        let source = test_source_file("use foo\n");

        let err = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect_err("cst backend should reject unqualified imports");

        assert_matches!(err, ParsingError::UnqualifiedImport { .. });
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_invalid_struct_repr_from_direct_type_lowering() {
        let source = test_source_file("type Foo = struct @align { x: u32 }\n");

        let err = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect_err("cst backend should reject invalid struct repr");

        assert_matches!(err, ParsingError::InvalidStructRepr { .. });
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_attribute_key_value_conflicts() {
        let source = test_source_file(
            "\
@storage(offset = 1)
@storage(offset = 2)
proc foo
    nop
end
",
        );

        let err = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect_err("cst backend should reject conflicting attribute keys");

        assert_matches!(err, ParsingError::AttributeKeyValueConflict { .. });
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_invalid_advice_map_keys() {
        let source = test_source_file("adv_map TABLE(1) = [1]\n");

        let err = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect_err("cst backend should reject invalid advice-map keys");

        assert_matches!(err, ParsingError::InvalidAdvMapKey { .. });
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_direct_division_by_zero_for_foldable_instructions() {
        let source = test_source_file(
            "\
begin
    u32div.0
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert_matches!(legacy, Err(ParsingError::DivisionByZero { .. }));
        assert_matches!(cst, Err(ParsingError::DivisionByZero { .. }));
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_direct_invalid_pad_values() {
        let source = test_source_file(
            "\
begin
    adv.push_mapvaln.5
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert_matches!(legacy, Err(ParsingError::InvalidPadValue { .. }));
        assert_matches!(cst, Err(ParsingError::InvalidPadValue { .. }));
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_direct_invalid_mast_roots() {
        let source = test_source_file(
            "\
begin
    exec.0x1234
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert_matches!(legacy, Err(ParsingError::InvalidMastRoot { .. }));
        assert_matches!(cst, Err(ParsingError::InvalidMastRoot { .. }));
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_direct_push_overflow() {
        let source = test_source_file(
            "\
begin
    push.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert_matches!(legacy, Err(ParsingError::PushOverflow { count: 17, .. }));
        assert_matches!(cst, Err(ParsingError::PushOverflow { count: 17, .. }));
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_direct_deprecated_memory_word_aliases() {
        let source = test_source_file(
            "\
begin
    mem_loadw.1
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert_matches!(legacy, Err(ParsingError::DeprecatedInstruction { .. }));
        assert_matches!(cst, Err(ParsingError::DeprecatedInstruction { .. }));
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_direct_deprecated_local_word_aliases() {
        let source = test_source_file(
            "\
begin
    loc_storew.0
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert_matches!(legacy, Err(ParsingError::DeprecatedInstruction { .. }));
        assert_matches!(cst, Err(ParsingError::DeprecatedInstruction { .. }));
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_reports_direct_invalid_instruction_syntax() {
        let source = test_source_file(
            "\
begin
    u32widening_mulx
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert!(legacy.is_err(), "legacy parser should reject invalid instructions");
        assert_matches!(cst, Err(ParsingError::InvalidSyntax { .. }));
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_rejects_empty_while_blocks() {
        let source = test_source_file(
            "\
begin
    while.true
    end
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert!(legacy.is_err(), "legacy parser should reject empty while blocks");
        assert!(cst.is_err(), "cst backend should reject empty while blocks");
    }

    #[cfg(feature = "std")]
    #[test]
    fn cst_backend_rejects_empty_if_then_without_else() {
        let source = test_source_file(
            "\
begin
    if.true
    end
end
",
        );

        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);

        assert!(legacy.is_err(), "legacy parser should reject empty if-then blocks");
        assert!(cst.is_err(), "cst backend should reject empty if-then blocks");
    }

    #[test]
    fn cst_backend_reports_cst_parse_errors() {
        let source = test_source_file("begin\n    if.true\n        add\n");

        let err = parse_forms_with_backend(source, ParserBackend::Cst)
            .expect_err("cst backend should surface a parse error");

        assert_matches!(
            err,
            ParsingError::InvalidSyntax { message, .. } if message.contains("expected `end`")
        );
    }
}
