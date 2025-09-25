use alloc::string::String;

use miden_debug_types::{SourceSpan, Span, Spanned};

use crate::prettier::PrettyPrint;

/// Represents a documentation string in Miden Assembly
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DocString(Span<String>);

impl DocString {
    /// Create a new [DocString] from `content`
    pub fn new(content: Span<String>) -> Self {
        Self(content)
    }

    /// Set the content of this docstring to `content`
    pub fn set(&mut self, content: String) {
        *self.0 = content;
    }

    /// Get the content of this docstring as a `str` reference.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    /// Get the content of this docstring as a `str` reference, with source span.
    #[inline]
    pub fn as_spanned_str(&self) -> Span<&str> {
        self.0.as_deref()
    }

    /// Returns true if this docstring is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Spanned for DocString {
    fn span(&self) -> SourceSpan {
        self.0.span()
    }
}

impl AsRef<str> for DocString {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl core::fmt::Display for DocString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use crate::prettier::PrettyPrint;

        self.pretty_print(f)
    }
}

impl PrettyPrint for DocString {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        if self.is_empty() {
            return Document::Empty;
        }

        let content = self.as_str();

        let fragment = content.lines().map(text).reduce(|acc, line| {
            if line.is_empty() {
                acc + nl() + text("#!")
            } else {
                acc + nl() + text("#! ") + line
            }
        });

        fragment.map(|doc| const_text("#! ") + doc + nl()).unwrap_or(Document::Empty)
    }
}
