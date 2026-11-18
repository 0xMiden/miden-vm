use alloc::borrow::Cow;

use miden_debug_types::SourceSpan;

/// A byte span with an optional message to show beside the source excerpt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub span: SourceSpan,
    pub primary: bool,
    message: Option<Cow<'static, str>>,
}

impl Label {
    pub fn new(span: SourceSpan, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            span,
            primary: false,
            message: Some(message.into()),
        }
    }

    pub fn underline(span: SourceSpan) -> Self {
        Self { span, primary: false, message: None }
    }

    pub fn primary(mut self) -> Self {
        self.primary = true;
        self
    }

    pub fn label(&self) -> Option<&str> {
        self.message.as_deref()
    }
}
