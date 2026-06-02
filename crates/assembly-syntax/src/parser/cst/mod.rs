mod blocks;
mod context;
mod forms;
mod fragments;
mod instructions;

use alloc::{collections::BTreeSet, string::String, sync::Arc, vec::Vec};

use miden_debug_types::{SourceFile, SourceSpan};
use miden_utils_diagnostics::LabeledSpan;

use self::{context::LoweringContext, forms::lower_source_file};
use crate::{
    Report, ast,
    diagnostics::{Diagnostic, Severity, miette, miette::MietteDiagnostic},
};

/// User-facing syntax diagnostics produced by the CST-backed parser entry point.
///
/// The CST parser itself can accumulate multiple recovery diagnostics; this wrapper converts those
/// diagnostics into the severity/label structure used by the existing `miden-assembly-syntax`
/// parser surface.
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

/// Parses zero or more AST forms from `source` using the CST-backed frontend.
///
/// This function is the public entry point for the CST backend. It first runs the lossless CST
/// parser, converts any CST diagnostics into the existing parser-facing report surface, and only
/// then lowers the recovered CST into the historic `Vec<Form>` boundary used by semantic analysis.
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

/// This is like `parse_forms`, but for parsing the content of inline MASM blocks in languages like
/// Rust.
///
/// Inline MASM is parsed as an [ast::Block], as if it was the body of a procedure definition. This
/// means that top-level items such as imports and constant declarations are not allowed.
///
/// An optional span can be provided, in which case only the contents of the span are parsed as the
/// inline MASM.
pub fn parse_inline_masm(
    source: Arc<SourceFile>,
    bounds: Option<SourceSpan>,
    interned: &mut BTreeSet<Arc<str>>,
) -> Result<ast::Block, Report> {
    use miden_assembly_syntax_cst::ast::AstNode;
    let mut parse = miden_assembly_syntax_cst::parse_inline_masm(source.clone(), bounds);
    let diagnostics = parse.take_diagnostics();
    if diagnostics.is_empty() {
        let mut context = LoweringContext::new(parse, interned);
        let cst_block = miden_assembly_syntax_cst::ast::Block::cast(context.parse().syntax())
            .expect("inline masm root kind should always be Block");
        blocks::lower_block(&mut context, &cst_block)
            .map_err(move |err| Report::from(err).with_source_code(source))
    } else {
        Err(Report::from(SyntaxError::from(diagnostics)).with_source_code(source))
    }
}

/// Converts recovered CST diagnostics into the user-facing syntax error surface.
impl From<Vec<MietteDiagnostic>> for SyntaxError {
    fn from(mut diagnostics: Vec<MietteDiagnostic>) -> Self {
        if diagnostics.len() == 1 {
            Self::from(diagnostics.pop().unwrap())
        } else {
            Self::Multiple {
                diagnostics: diagnostics.into_iter().map(Self::from).collect(),
            }
        }
    }
}

/// Converts a single CST diagnostic into the parser's severity-preserving syntax error wrapper.
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
