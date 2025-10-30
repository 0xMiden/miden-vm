use alloc::borrow::Cow;
use core::ops::Range;

use super::LabeledSpan;

/// Represents a diagnostic label.
///
/// A label is a source span and optional diagnostic text that should be laid out next to the
/// source snippet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    span: miette::SourceSpan,
    label: Option<Cow<'static, str>>,
}

impl Label {
    /// Construct a label for the given range of bytes, expressible as any type which can be
    /// converted to a [`Range<usize>`], e.g. [miette::SourceSpan].
    pub fn at<R>(range: R) -> Self
    where
        Range<usize>: From<R>,
    {
        let range = Range::<usize>::from(range);
        Self { span: range.into(), label: None }
    }

    /// Construct a label which points to a specific offset in the source file.
    pub fn point<L>(at: usize, label: L) -> Self
    where
        Cow<'static, str>: From<L>,
    {
        Self {
            span: miette::SourceSpan::from(at),
            label: Some(Cow::from(label)),
        }
    }

    /// Construct a label from the given source range and diagnostic text.
    pub fn new<R, L>(range: R, label: L) -> Self
    where
        Range<usize>: From<R>,
        Cow<'static, str>: From<L>,
    {
        let range = Range::<usize>::from(range);
        Self {
            span: range.into(),
            label: Some(Cow::from(label)),
        }
    }

    /// Returns the diagnostic text, the actual "label", for this label.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

impl From<Label> for miette::SourceSpan {
    #[inline(always)]
    fn from(label: Label) -> Self {
        label.span
    }
}

impl From<Label> for LabeledSpan {
    #[inline]
    fn from(label: Label) -> LabeledSpan {
        if let Some(message) = label.label {
            LabeledSpan::at(label.span, message)
        } else {
            LabeledSpan::underline(label.span)
        }
    }
}
