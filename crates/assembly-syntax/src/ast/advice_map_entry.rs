use alloc::{string::String, vec::Vec};

use miden_debug_types::{SourceSpan, Span};

use super::DocString;
use crate::{
    Felt,
    ast::{Ident, Immediate, Visibility},
    parser::WordValue,
};

// Advice Map data that the host populates before the VM starts.
// ============================================================

#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub value: Vec<Immediate<Felt>>,
}

impl AdviceMapEntry {
    pub fn new(
        span: SourceSpan,
        name: Ident,
        key: Option<Span<WordValue>>,
        value: Vec<Immediate<Felt>>,
    ) -> Self {
        Self { span, docs: None, name, key, value }
    }

    /// Adds documentation to this constant declaration.
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }

    /// Returns the name of this advice map entry within its containing module.
    pub fn name(&self) -> &Ident {
        &self.name
    }

    /// Returns the documentation associated with this item.
    pub fn docs(&self) -> Option<Span<&str>> {
        self.docs.as_ref().map(|docstring| docstring.as_spanned_str())
    }

    /// Returns the visibility of this alias
    pub const fn visibility(&self) -> Visibility {
        Visibility::Public
    }

    pub fn span(&self) -> SourceSpan {
        self.span
    }
}

impl crate::prettier::PrettyPrint for AdviceMapEntry {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = self
            .docs
            .as_ref()
            .map(|docstring| docstring.render())
            .unwrap_or(Document::Empty);

        doc += flatten(const_text("AdviceMapEntry") + const_text(" ") + display(&self.name));

        doc
    }
}
