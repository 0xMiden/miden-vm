use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
};
use core::{error::Error, fmt, ops::Deref};

use miden_debug_types::SourceFile;

use crate::{Diagnostic, DiagnosticDetails, MessageDiagnostic, Severity, reporting};

type BoxedError = Box<dyn Error + Send + Sync>;
type BoxedDiagnostic = Box<dyn Diagnostic + Send + Sync>;

/// An owned diagnostic report with optional source text and error context.
pub struct Report(Box<ReportInner>);

#[derive(Debug)]
struct ReportInner {
    error: ReportError,
    source: Option<Arc<SourceFile>>,
}

#[derive(Debug)]
enum ReportError {
    Diagnostic(BoxedDiagnostic),
    Error(BoxedError),
    Context { message: String, cause: Report },
}

impl Report {
    pub fn new(error: impl Diagnostic + Send + Sync + 'static) -> Self {
        Self::with_error(ReportError::Diagnostic(Box::new(error)))
    }

    pub fn msg(message: impl fmt::Display) -> Self {
        Self::new(MessageDiagnostic::new(message.to_string()))
    }

    fn with_error(error: ReportError) -> Self {
        Self(Box::new(ReportInner { error, source: None }))
    }

    pub fn with_source_code(mut self, source: Arc<SourceFile>) -> Self {
        self.0.source.get_or_insert(source);
        self
    }

    pub fn wrap_err(self, message: impl fmt::Display) -> Self {
        Self::with_error(ReportError::Context {
            message: message.to_string(),
            cause: self,
        })
    }

    pub fn downcast_ref<E: Error + 'static>(&self) -> Option<&E> {
        self.0.original_error().downcast_ref()
    }

    pub fn downcast<E: Error + 'static>(self) -> core::result::Result<E, Self> {
        if self.downcast_ref::<E>().is_none() {
            return Err(self);
        }

        let mut inner = self.0;
        let error: BoxedError = loop {
            match inner.error {
                ReportError::Diagnostic(error) => break error,
                ReportError::Error(error) => break error,
                ReportError::Context { cause, .. } => inner = cause.0,
            }
        };
        Ok(*error.downcast::<E>().expect("checked the original error type"))
    }
}

impl ReportInner {
    fn as_error(&self) -> &(dyn Error + 'static) {
        match &self.error {
            ReportError::Diagnostic(error) => error.as_ref(),
            ReportError::Error(error) => error.as_ref(),
            ReportError::Context { .. } => self,
        }
    }

    fn original_error(&self) -> &(dyn Error + 'static) {
        let mut inner = self;
        loop {
            match &inner.error {
                ReportError::Diagnostic(error) => return error.as_ref(),
                ReportError::Error(error) => return error.as_ref(),
                ReportError::Context { cause, .. } => inner = &cause.0,
            }
        }
    }
}

impl fmt::Display for ReportInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error {
            ReportError::Diagnostic(error) => fmt::Display::fmt(error, f),
            ReportError::Error(error) => fmt::Display::fmt(error, f),
            ReportError::Context { message, .. } => f.write_str(message),
        }
    }
}

impl Error for ReportInner {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.error {
            ReportError::Context { cause, .. } => Some(cause.0.as_error()),
            _ => self.as_error().source(),
        }
    }
}

impl Diagnostic for ReportInner {
    fn severity(&self) -> Severity {
        match &self.error {
            ReportError::Diagnostic(error) => error.severity(),
            ReportError::Context { cause, .. } => cause.severity(),
            ReportError::Error(_) => Severity::Error,
        }
    }

    fn details(&self) -> DiagnosticDetails<'_> {
        let mut details = match &self.error {
            ReportError::Diagnostic(error) => error.details(),
            ReportError::Context { cause, .. } => cause.details(),
            ReportError::Error(_) => DiagnosticDetails::default(),
        };
        details.source = details.source.or(self.source.as_deref());
        details
    }
}

impl<E: Diagnostic + Send + Sync + 'static> From<E> for Report {
    fn from(error: E) -> Self {
        Self::new(error)
    }
}

impl Error for Report {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl Deref for Report {
    type Target = dyn Diagnostic + Send + Sync;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl AsRef<dyn Diagnostic> for Report {
    fn as_ref(&self) -> &(dyn Diagnostic + 'static) {
        self.0.as_ref()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        reporting::render(f, &*self.0)
    }
}

pub type Result<T, E = Report> = core::result::Result<T, E>;

pub trait IntoDiagnostic<T> {
    fn into_diagnostic(self) -> Result<T>;
}

impl<T, E: Error + Send + Sync + 'static> IntoDiagnostic<T> for Result<T, E> {
    fn into_diagnostic(self) -> Result<T> {
        self.map_err(|error| Report::with_error(ReportError::Error(Box::new(error))))
    }
}

pub trait WrapErr<T> {
    fn wrap_err(self, message: impl fmt::Display) -> Result<T>;
    fn wrap_err_with<M: fmt::Display>(self, message: impl FnOnce() -> M) -> Result<T>;

    fn context(self, message: impl fmt::Display) -> Result<T>
    where
        Self: Sized,
    {
        self.wrap_err(message)
    }
}

impl<T, E: Into<Report>> WrapErr<T> for Result<T, E> {
    fn wrap_err(self, message: impl fmt::Display) -> Result<T> {
        self.map_err(|error| error.into().wrap_err(message))
    }

    fn wrap_err_with<M: fmt::Display>(self, message: impl FnOnce() -> M) -> Result<T> {
        self.map_err(|error| error.into().wrap_err(message()))
    }
}
