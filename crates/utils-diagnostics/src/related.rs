use alloc::{borrow::Cow, sync::Arc, vec::Vec};
use core::{error::Error, fmt};

use miden_debug_types::{SourceFile, SourceSpan};

use crate::{Diagnostic, DiagnosticDetails, Label, Report, Severity};

// RELATED LABEL
// ================================================================================================

/// This type is used to associate a more complex label or set of labels with some other error.
///
/// In particular, it is used to reference related bits of source code distinct from that of the
/// original error. A related label can have a distinct severity, its own message, and its own
/// sub-labels, and may reference code in a completely different source file that the original
/// error.
#[derive(Debug, Clone)]
pub struct RelatedLabel {
    /// The severity for this related label
    pub severity: Severity,
    /// The message for this label
    pub message: Cow<'static, str>,
    /// The sub-labels for this label
    pub labels: Vec<Label>,
    /// If provided as a standalone diagnostic, the help message to provide
    pub help: Option<Cow<'static, str>>,
    /// The source file to use when rendering source spans of this label as snippets.
    pub file: Option<Arc<SourceFile>>,
}

impl fmt::Display for RelatedLabel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.message.as_ref())
    }
}

impl Error for RelatedLabel {}

impl RelatedLabel {
    pub fn new<S>(severity: Severity, message: S) -> Self
    where
        Cow<'static, str>: From<S>,
    {
        Self {
            severity,
            message: Cow::from(message),
            help: None,
            labels: Vec::new(),
            file: None,
        }
    }

    pub fn error<S>(message: S) -> Self
    where
        Cow<'static, str>: From<S>,
    {
        Self::new(Severity::Error, message)
    }

    pub fn warning<S>(message: S) -> Self
    where
        Cow<'static, str>: From<S>,
    {
        Self::new(Severity::Warning, message)
    }

    pub fn advice<S>(message: S) -> Self
    where
        Cow<'static, str>: From<S>,
    {
        Self::new(Severity::Advice, message)
    }

    pub fn with_source_file(mut self, file: Option<Arc<SourceFile>>) -> Self {
        self.file = file;
        self
    }

    pub fn with_labeled_span<S>(self, span: SourceSpan, message: S) -> Self
    where
        Cow<'static, str>: From<S>,
    {
        self.with_label(Label::new(span, message))
    }

    pub(crate) fn with_label(mut self, label: Label) -> Self {
        self.labels.push(label);
        self
    }

    pub fn with_labels<I>(mut self, labels: I) -> Self
    where
        I: IntoIterator<Item = Label>,
    {
        self.labels.extend(labels);
        self
    }

    pub fn with_help<S>(mut self, help: S) -> Self
    where
        Cow<'static, str>: From<S>,
    {
        self.help = Some(help.into());
        self
    }
}

impl Diagnostic for RelatedLabel {
    fn severity(&self) -> Severity {
        self.severity
    }

    fn details(&self) -> DiagnosticDetails<'_> {
        DiagnosticDetails {
            help: self.help.as_deref().map(Cow::Borrowed),
            source: self.file.as_deref(),
            labels: Cow::Borrowed(&self.labels),
            ..Default::default()
        }
    }
}

// RELATED ERROR
// ================================================================================================

/// This type allows rolling up a diagnostic into a parent error
///
/// This is necessary as [Report] cannot be used as the source error when deriving [Diagnostic].
#[derive(Debug)]
pub struct RelatedError(Report);

impl RelatedError {
    pub fn into_report(self) -> Report {
        self.0
    }
}

impl Diagnostic for RelatedError {
    fn severity(&self) -> Severity {
        self.0.severity()
    }

    fn details(&self) -> DiagnosticDetails<'_> {
        self.0.details()
    }
}

impl fmt::Display for RelatedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Error for RelatedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl From<Report> for RelatedError {
    fn from(report: Report) -> Self {
        Self(report)
    }
}

impl RelatedError {
    pub const fn new(report: Report) -> Self {
        Self(report)
    }

    pub fn wrap<E>(error: E) -> Self
    where
        E: Diagnostic + Send + Sync + 'static,
    {
        Self(Report::new(error))
    }
}
