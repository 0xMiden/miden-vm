mod blocks;
mod context;
mod forms;
mod fragments;
mod instructions;

use alloc::{collections::BTreeSet, string::String, sync::Arc, vec::Vec};

use miden_debug_types::SourceFile;
use miden_utils_diagnostics::LabeledSpan;

use self::{context::LoweringContext, forms::lower_source_file};
use crate::{
    Report, ast,
    diagnostics::{Diagnostic, Severity, miette, miette::MietteDiagnostic},
};

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum SyntaxError {
    #[error("{message}")]
    #[diagnostic(severity(Error))]
    Error {
        message: String,
        #[label(collection)]
        labels: Vec<LabeledSpan>,
        #[help]
        help: Option<String>,
    },
    #[error("{message}")]
    #[diagnostic(severity(Warning))]
    Warning {
        message: String,
        #[label(collection)]
        labels: Vec<LabeledSpan>,
        #[help]
        help: Option<String>,
    },
    #[error("{message}")]
    #[diagnostic(severity(Advice))]
    Advice {
        message: String,
        #[label(collection)]
        labels: Vec<LabeledSpan>,
        #[help]
        help: Option<String>,
    },
    #[error("invalid syntax")]
    #[diagnostic(help("Multiple syntax errors were identified, see diagnostics for more details"))]
    Multiple {
        #[related]
        diagnostics: Vec<SyntaxError>,
    },
}

/// Parse zero or more [ast::Form] from `source`, using `interned` for string interning.
pub fn parse_forms(
    source: Arc<SourceFile>,
    interned: &mut BTreeSet<Arc<str>>,
) -> Result<Vec<ast::Form>, Report> {
    let mut parse = miden_assembly_syntax_cst::parse_source_file(source.clone());
    let diagnostics = parse.take_diagnostics();
    if diagnostics.is_empty() {
        let mut context = LoweringContext::new(parse, interned);
        lower_source_file(&mut context).map_err(move |err| err.with_source_code(source))
    } else {
        Err(Report::from(SyntaxError::from(diagnostics)).with_source_code(source))
    }
}

impl From<Vec<MietteDiagnostic>> for SyntaxError {
    fn from(mut diagnostics: Vec<MietteDiagnostic>) -> Self {
        if diagnostics.len() == 1 {
            // If we have only a single diagnostic, flatten them for cleaner output
            Self::from(diagnostics.pop().unwrap())
        } else if let Some(first_error) = diagnostics.iter().position(|diagnostic| {
            diagnostic.severity.is_none_or(|severity| matches!(severity, Severity::Error))
        }) {
            // The legacy parser surfaced the primary syntax error and stopped. The CST parser
            // can recover and accumulate follow-on syntax diagnostics, but the user-facing
            // parser surface should still prefer the first real error to avoid noisy cascades.
            Self::from(diagnostics.remove(first_error))
        } else {
            Self::Multiple {
                diagnostics: diagnostics.into_iter().map(Self::from).collect(),
            }
        }
    }
}

impl From<MietteDiagnostic> for SyntaxError {
    fn from(value: MietteDiagnostic) -> Self {
        let MietteDiagnostic {
            message,
            code: _,
            severity,
            help,
            url: _,
            labels,
        } = value;

        let severity = severity.unwrap_or(Severity::Error);
        match severity {
            Severity::Error => Self::Error {
                message,
                labels: labels.unwrap_or_default(),
                help,
            },
            Severity::Warning => Self::Warning {
                message,
                labels: labels.unwrap_or_default(),
                help,
            },
            Severity::Advice => Self::Advice {
                message,
                labels: labels.unwrap_or_default(),
                help,
            },
        }
    }
}
