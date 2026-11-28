use alloc::borrow::Cow;
use core::ops::Range;

use miden_debug_types::{SourceId, SourceSpan};

/// A byte span with an optional message to show beside the source excerpt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub span: SourceSpan,
    pub primary: bool,
    message: Option<Cow<'static, str>>,
    detached: bool,
}

impl Label {
    pub fn new(span: SourceSpan, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            span,
            primary: false,
            message: Some(message.into()),
            detached: false,
        }
    }

    pub fn underline(span: SourceSpan) -> Self {
        Self {
            span,
            primary: false,
            message: None,
            detached: false,
        }
    }

    /// Creates a label for a known byte range in a source whose ID is not assigned yet.
    /// An empty range at offset zero is a valid detached location.
    pub fn detached(range: Range<u32>, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            span: SourceSpan::new(SourceId::UNKNOWN, range),
            primary: false,
            message: Some(message.into()),
            detached: true,
        }
    }

    pub(crate) fn has_source_range(&self) -> bool {
        !self.span.is_synthetic() && (!self.span.is_unknown() || self.detached)
    }

    pub fn primary(mut self) -> Self {
        self.primary = true;
        self
    }

    pub fn label(&self) -> Option<&str> {
        self.message.as_deref()
    }
}
