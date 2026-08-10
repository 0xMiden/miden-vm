mod blocks;
mod context;
mod forms;
mod fragments;
mod instructions;

use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};

use miden_debug_types::{SourceFile, SourceSpan};
use miden_diagnostics::{DiagnosticCollector, Outcome};

use self::{context::LoweringContext, forms::lower_source_file};
use crate::ast;

/// The result of parsing and lowering a source file.
///
/// A missing value means that syntax recovery or CST lowering produced an error diagnostic. Any
/// warnings remain available in the diagnostic set alongside a successfully lowered value.
pub type ParseFormsOutcome = Outcome<Option<Vec<ast::Form>>>;

/// The result of parsing and lowering an inline MASM block.
pub type ParseInlineMasmOutcome = Outcome<Option<ast::Block>>;

/// Parses zero or more AST forms from `source` using the CST-backed frontend.
///
/// Syntax diagnostics are retained as first-class output. Lowering proceeds when parsing emitted
/// warnings only, and a lowering error is added to the same diagnostic collection.
pub fn parse_forms(
    source: Arc<SourceFile>,
    interned: &mut BTreeSet<Arc<str>>,
) -> ParseFormsOutcome {
    let Outcome {
        value: parse,
        diagnostics: parse_diagnostics,
    } = miden_assembly_syntax_cst::parse_source_file(source);
    let parse_failed = parse_diagnostics.has_errors();
    let mut diagnostics = DiagnosticCollector::new();
    let _ = diagnostics.merge(parse_diagnostics);

    let value = if parse_failed {
        None
    } else {
        let mut context = LoweringContext::new(parse, interned);
        match lower_source_file(&mut context) {
            Ok(forms) => Some(forms),
            Err(error) => {
                let _ = diagnostics.add(error);
                None
            },
        }
    };

    Outcome { value, diagnostics: diagnostics.finish() }
}

/// Parses the content of an inline MASM block.
///
/// Inline MASM is parsed as an [ast::Block], as if it was the body of a procedure definition. An
/// optional span restricts parsing to that portion of `source`.
pub fn parse_inline_masm(
    source: Arc<SourceFile>,
    bounds: Option<SourceSpan>,
    interned: &mut BTreeSet<Arc<str>>,
) -> ParseInlineMasmOutcome {
    use miden_assembly_syntax_cst::ast::AstNode;

    let Outcome {
        value: parse,
        diagnostics: parse_diagnostics,
    } = miden_assembly_syntax_cst::parse_inline_masm(source, bounds);
    let parse_failed = parse_diagnostics.has_errors();
    let mut diagnostics = DiagnosticCollector::new();
    let _ = diagnostics.merge(parse_diagnostics);

    let value = if parse_failed {
        None
    } else {
        let mut context = LoweringContext::new(parse, interned);
        let cst_block = miden_assembly_syntax_cst::ast::Block::cast(context.parse().syntax())
            .expect("inline masm root kind should always be Block");
        match blocks::lower_block(&mut context, &cst_block, 0) {
            Ok(block) => Some(block),
            Err(error) => {
                let _ = diagnostics.add(*error);
                None
            },
        }
    };

    Outcome { value, diagnostics: diagnostics.finish() }
}
