use alloc::{string::String, vec::Vec};

use miden_debug_types::{SourceSpan, Span};

use super::DocString;
use crate::{Felt, ast::Ident, parser::WordValue};

// Advice Map data that the host populates before the VM starts.
// ============================================================

#[derive(Debug, PartialEq, Eq)]
pub struct AdviceMapEntry {
    /// The source span of the definition.
    pub span: SourceSpan,
    /// The documentation string attached to this definition.
    pub docs: Option<DocString>,
    /// The name of the constant.
    pub name: Ident,
    /// The key to insert in the Advice Map.
    pub key: Option<Span<WordValue>>,
    /// The value to insert in the Advice Map.
    pub value: Vec<Felt>,
}

impl AdviceMapEntry {
    pub fn new(
        span: SourceSpan,
        name: Ident,
        key: Option<Span<WordValue>>,
        value: Vec<Felt>,
    ) -> Self {
        Self { span, docs: None, name, key, value }
    }

    /// Adds documentation to this constant declaration.
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }
}
