use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    sync::Arc,
};

use miden_assembly_syntax_cst::{
    Parse as CstParse, SyntaxKind, SyntaxToken,
    ast::{AstNode, Path as CstPath, Visibility as CstVisibility},
};
use miden_debug_types::{SourceFile, SourceSpan, Span};

use crate::{Path, ast, parser::ParsingError};

/// Shared lowering state for a single CST-to-AST pass.
///
/// This owns the lossless CST parse and the string interner used to construct AST identifiers,
/// and provides the small set of span-aware conversion helpers needed by the lowering modules.
pub(super) struct LoweringContext<'a> {
    parse: CstParse,
    interned: &'a mut BTreeSet<Arc<str>>,
}

impl<'a> LoweringContext<'a> {
    /// Creates a new lowering context for `parse`.
    pub(super) fn new(parse: CstParse, interned: &'a mut BTreeSet<Arc<str>>) -> Self {
        Self { parse, interned }
    }

    /// Returns the underlying CST parse being lowered.
    pub(super) fn parse(&self) -> &CstParse {
        &self.parse
    }

    /// Returns the source file associated with the CST parse.
    pub(super) fn source_file(&self) -> &SourceFile {
        self.parse.source()
    }

    /// Returns the exact source text covered by `span`.
    ///
    /// All spans used by CST lowering are expected to come from the same source file as the parse.
    pub(super) fn source_text(&self, span: SourceSpan) -> &str {
        self.source_file()
            .source_slice(span.into_slice_index())
            .expect("cst spans should always refer to valid source slices")
    }

    /// Lowers optional CST visibility into the AST visibility enum.
    pub(super) fn lower_visibility(&self, visibility: Option<CstVisibility>) -> ast::Visibility {
        if visibility.is_some() {
            ast::Visibility::Public
        } else {
            ast::Visibility::Private
        }
    }

    /// Lowers a CST identifier token into an AST identifier.
    ///
    /// Quoted identifiers are unquoted before validation and interning; all other identifier-like
    /// tokens are lowered using their original spelling.
    pub(super) fn lower_ident_token(
        &mut self,
        token: &SyntaxToken,
    ) -> Result<ast::Ident, ParsingError> {
        let span = self.parse.span_for_token(token);
        let raw = match token.kind() {
            SyntaxKind::QuotedIdent if token.text().len() >= 2 => {
                &token.text()[1..token.text().len() - 1]
            },
            _ => token.text(),
        };
        self.lower_ident_text(span, raw)
    }

    /// Lowers a procedure-name token using the token's original spelling.
    ///
    /// Procedure names have slightly different validation semantics than plain identifiers, and
    /// quoted names must preserve the original token text for accurate diagnostics.
    pub(super) fn lower_procedure_name_token(
        &mut self,
        token: &SyntaxToken,
    ) -> Result<ast::ProcedureName, ParsingError> {
        let span = self.parse.span_for_token(token);
        ast::ProcedureName::new_with_span(span, token.text())
            .map_err(|error| ParsingError::InvalidIdentifier { error, span })
    }

    /// Lowers an identifier token that must satisfy MASM constant naming rules.
    ///
    /// This is stricter than [`Self::lower_ident_token`] because constants must be screaming-case
    /// bare identifiers; quoted identifiers and non-constant casing are rejected.
    pub(super) fn lower_constant_ident_token(
        &mut self,
        token: &SyntaxToken,
    ) -> Result<ast::Ident, ParsingError> {
        let span = self.parse.span_for_token(token);
        if token.kind() != SyntaxKind::Ident {
            return Err(ParsingError::InvalidIdentifier {
                error: ast::IdentError::Casing(ast::CaseKindError::Screaming),
                span,
            });
        }

        let ident = self.lower_ident_token(token)?;
        if ident.is_constant_ident() {
            Ok(ident)
        } else {
            Err(ParsingError::InvalidIdentifier {
                error: ast::IdentError::Casing(ast::CaseKindError::Screaming),
                span,
            })
        }
    }

    /// Validates and interns raw identifier text at the given span.
    pub(super) fn lower_ident_text(
        &mut self,
        span: SourceSpan,
        text: &str,
    ) -> Result<ast::Ident, ParsingError> {
        let interned = self.intern(text);
        ast::Ident::validate(interned.as_ref())
            .map_err(|error| ParsingError::InvalidIdentifier { error, span })?;
        Ok(ast::Ident::from_raw_parts(Span::new(span, interned)))
    }

    /// Interns arbitrary string text and wraps it as an AST identifier payload without validation.
    ///
    /// This is used for contexts such as string constants and hashed event names, where the raw
    /// text is semantically meaningful but does not have to satisfy identifier rules.
    pub(super) fn lower_string_text(&mut self, span: SourceSpan, text: &str) -> ast::Ident {
        let interned = self.intern(text);
        ast::Ident::from_raw_parts(Span::new(span, interned))
    }

    /// Lowers a CST path node into a validated AST path, discarding trivia but preserving span.
    pub(super) fn lower_path(&mut self, path: &CstPath) -> Result<Span<Arc<Path>>, ParsingError> {
        let span = self.parse.span_for_node(path.syntax());
        let mut raw = String::new();
        for token in path.syntax().children_with_tokens().filter_map(|element| element.into_token())
        {
            if !token.kind().is_trivia() {
                raw.push_str(token.text());
            }
        }

        self.lower_raw_path(span, &raw)
    }

    /// Parses and validates a raw path string at the given span.
    ///
    /// Callers are responsible for ensuring that `raw` has already been normalized to the spelling
    /// expected by the existing AST/path infrastructure.
    pub(super) fn lower_raw_path(
        &mut self,
        span: SourceSpan,
        raw: &str,
    ) -> Result<Span<Arc<Path>>, ParsingError> {
        let path = crate::ast::PathBuf::new(&raw).map_err(|error| {
            ParsingError::InvalidLibraryPath { span, message: error.to_string() }
        })?;
        Ok(Span::new(span, Arc::<Path>::from(path)))
    }

    /// Returns an interned copy of `text`, inserting it into the shared interner if needed.
    fn intern(&mut self, text: &str) -> Arc<str> {
        self.interned.get(text).cloned().unwrap_or_else(|| {
            let interned = Arc::<str>::from(text.to_string().into_boxed_str());
            self.interned.insert(interned.clone());
            interned
        })
    }
}
