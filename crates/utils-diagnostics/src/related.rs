use alloc::{borrow::Cow, boxed::Box, sync::Arc, vec::Vec};
use core::fmt;

use miden_debug_types::{SourceFile, SourceSpan};

use super::{Diagnostic, Label, LabeledSpan, Report, Severity, SourceCode};

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

#[cfg(feature = "std")]
impl std::error::Error for RelatedLabel {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(not(feature = "std"))]
impl miette::StdError for RelatedLabel {
    fn source(&self) -> Option<&(dyn miette::StdError + 'static)> {
        None
    }
}

impl RelatedLabel {
    pub fn new<S>(severity: Severity, message: S) -> Self
    where
        Cow<'static, str>: From<S>,
    {
        Self {
            severity,
            message: Cow::from(message),
            help: None,
            labels: vec![],
            file: None,
        }
    }

    pub fn error<S>(message: S) -> Self
    where
        Cow<'static, str>: From<S>,
    {
        Self::new(Severity::Error, message)
    }

    #[allow(unused)]
    pub fn warning<S>(message: S) -> Self
    where
        Cow<'static, str>: From<S>,
    {
        Self::new(Severity::Warning, message)
    }

    #[allow(unused)]
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
        let range = span.into_range();
        self.with_label(Label::new((range.start as usize)..(range.end as usize), message))
    }

    pub fn with_label(mut self, label: Label) -> Self {
        self.labels.push(label);
        self
    }

    #[allow(unused)]
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
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        None
    }
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.help.as_deref().map(|help| Box::new(help) as Box<_>)
    }
    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        None
    }
    fn source_code(&self) -> Option<&dyn SourceCode> {
        self.file.as_ref().map(|f| f as &dyn SourceCode)
    }
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        if self.labels.is_empty() {
            None
        } else {
            Some(Box::new(self.labels.iter().cloned().map(|l| l.into())))
        }
    }
    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        None
    }
    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        None
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

    #[inline(always)]
    pub fn as_diagnostic(&self) -> &dyn Diagnostic {
        self.0.as_ref()
    }
}

impl Diagnostic for RelatedError {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.as_diagnostic().code()
    }
    fn severity(&self) -> Option<Severity> {
        self.as_diagnostic().severity()
    }
    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.as_diagnostic().help()
    }
    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.as_diagnostic().url()
    }
    fn source_code(&self) -> Option<&dyn SourceCode> {
        self.as_diagnostic().source_code()
    }
    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        self.as_diagnostic().labels()
    }
    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.as_diagnostic().related()
    }
    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.as_diagnostic().diagnostic_source()
    }
}

impl fmt::Display for RelatedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RelatedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        AsRef::<dyn std::error::Error>::as_ref(&self.0).source()
    }
}

#[cfg(not(feature = "std"))]
impl miette::StdError for RelatedError {
    fn source(&self) -> Option<&(dyn miette::StdError + 'static)> {
        AsRef::<dyn miette::StdError>::as_ref(&self.0).source()
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
        Self(Report::new_boxed(Box::new(error)))
    }
}
