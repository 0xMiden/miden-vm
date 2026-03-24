use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    sync::Arc,
};

use miden_assembly_syntax_cst::{
    Parse as CstParse, SyntaxKind, SyntaxToken,
    ast::{AstNode, Path as CstPath, Visibility as CstVisibility},
};
use miden_debug_types::{SourceFile, SourceLanguage, SourceSpan, Span, Spanned};

use crate::{Path, ast, parser::ParsingError};

pub(super) struct LoweringContext<'a> {
    source: Arc<SourceFile>,
    parse: CstParse,
    interned: &'a mut BTreeSet<Arc<str>>,
}

impl<'a> LoweringContext<'a> {
    pub(super) fn new(
        source: Arc<SourceFile>,
        parse: CstParse,
        interned: &'a mut BTreeSet<Arc<str>>,
    ) -> Self {
        Self { source, parse, interned }
    }

    pub(super) fn parse(&self) -> &CstParse {
        &self.parse
    }

    pub(super) fn source_file(&self) -> &Arc<SourceFile> {
        &self.source
    }

    pub(super) fn source_text(&self, span: SourceSpan) -> &str {
        self.source
            .source_slice(span.into_slice_index())
            .expect("cst spans should always refer to valid source slices")
    }

    pub(super) fn lower_visibility(&self, visibility: Option<CstVisibility>) -> ast::Visibility {
        if visibility.is_some() {
            ast::Visibility::Public
        } else {
            ast::Visibility::Private
        }
    }

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

    pub(super) fn lower_procedure_name_token(
        &mut self,
        token: &SyntaxToken,
    ) -> Result<ast::ProcedureName, ParsingError> {
        let ident = self.lower_ident_token(token)?;
        ast::ProcedureName::new_with_span(ident.span(), ident.as_str())
            .map_err(|error| ParsingError::InvalidIdentifier { error, span: ident.span() })
    }

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

    pub(super) fn lower_string_text(&mut self, span: SourceSpan, text: &str) -> ast::Ident {
        let interned = self.intern(text);
        ast::Ident::from_raw_parts(Span::new(span, interned))
    }

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

    pub(super) fn lower_form_with_legacy_parser(
        &mut self,
        span: SourceSpan,
    ) -> Result<ast::Form, ParsingError> {
        let source = self.masked_source_file(span);
        let mut forms = super::super::parse_forms_with_lalrpop(source, self.interned)?;
        if forms.len() == 1 {
            return Ok(forms.pop().expect("single form"));
        }

        Err(ParsingError::InvalidSyntax {
            span,
            message: "expected a single top-level form from CST item lowering".to_string(),
        })
    }

    fn intern(&mut self, text: &str) -> Arc<str> {
        self.interned.get(text).cloned().unwrap_or_else(|| {
            let interned = Arc::<str>::from(text.to_string().into_boxed_str());
            self.interned.insert(interned.clone());
            interned
        })
    }

    fn masked_source_file(&self, span: SourceSpan) -> Arc<SourceFile> {
        let full_source = self.source.as_str();
        let range = span.into_slice_index();
        let mut masked = String::with_capacity(range.end);
        masked.push_str(&mask_prefix(&full_source[..range.start]));
        masked.push_str(&full_source[range.clone()]);

        Arc::new(SourceFile::new(
            self.source.id(),
            SourceLanguage::Masm,
            self.source.uri().clone(),
            masked.into_boxed_str(),
        ))
    }
}

fn mask_prefix(prefix: &str) -> String {
    let mut masked = String::with_capacity(prefix.len());
    for byte in prefix.bytes() {
        match byte {
            b'\n' => masked.push('\n'),
            b'\r' => masked.push('\r'),
            _ => masked.push(' '),
        }
    }
    masked
}
