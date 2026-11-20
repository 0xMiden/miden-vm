use alloc::{borrow::Cow, string::String, vec::Vec};
use core::{error::Error, fmt};

use miden_debug_types::SourceFile;

use crate::Label;

/// Metadata available for rendering an error or a parser diagnostic.
#[derive(Default)]
#[non_exhaustive]
pub struct DiagnosticDetails<'a> {
    pub code: Option<&'a str>,
    pub help: Option<Cow<'a, str>>,
    pub source: Option<&'a SourceFile>,
    pub labels: Cow<'a, [Label]>,
    pub related: Vec<&'a dyn Diagnostic>,
}

pub trait Diagnostic: Error {
    fn severity(&self) -> Severity {
        Severity::Error
    }

    fn details(&self) -> DiagnosticDetails<'_> {
        DiagnosticDetails::default()
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Advice,
    Warning,
    #[default]
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Advice => "advice",
            Self::Warning => "warning",
            Self::Error => "error",
        })
    }
}

/// An owned diagnostic for parser recovery and other errors built at runtime.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MessageDiagnostic {
    pub message: String,
    pub severity: Option<Severity>,
    pub labels: Option<Vec<Label>>,
    pub help: Option<String>,
}

impl MessageDiagnostic {
    pub fn new(message: String) -> Self {
        Self {
            message,
            severity: None,
            labels: None,
            help: None,
        }
    }
}

impl fmt::Display for MessageDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for MessageDiagnostic {}

impl Diagnostic for MessageDiagnostic {
    fn severity(&self) -> Severity {
        self.severity.unwrap_or_default()
    }

    fn details(&self) -> DiagnosticDetails<'_> {
        DiagnosticDetails {
            labels: Cow::Borrowed(self.labels.as_deref().unwrap_or_default()),
            help: self.help.as_deref().map(Cow::Borrowed),
            ..Default::default()
        }
    }
}
