use core::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    span: Range<usize>,
    message: String,
}

impl Diagnostic {
    pub fn new(span: Range<usize>, message: impl Into<String>) -> Self {
        Self { span, message: message.into() }
    }

    pub fn span(&self) -> Range<usize> {
        self.span.clone()
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}
