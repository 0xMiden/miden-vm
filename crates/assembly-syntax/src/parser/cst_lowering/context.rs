use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    sync::Arc,
};

use miden_assembly_syntax_cst::Parse as CstParse;
use miden_debug_types::{SourceFile, SourceLanguage, SourceSpan};

use crate::{ast, parser::ParsingError};

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
