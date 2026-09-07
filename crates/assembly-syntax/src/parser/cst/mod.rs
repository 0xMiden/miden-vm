mod blocks;
mod context;
mod forms;
mod fragments;
mod instructions;

use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};

use miden_diagnostics::{DiagnosticCollector, Outcome, SourceId, SourceSpan};

use self::{context::LoweringContext, forms::lower_source_file};
use crate::ast;

/// The result of parsing and lowering a source file.
///
/// A missing value means that syntax recovery or CST lowering produced an error diagnostic. Any
/// warnings remain available in the diagnostic set alongside a successfully lowered value.
pub type ParseFormsOutcome = Outcome<Vec<ast::Form>>;

/// The result of parsing and lowering an inline MASM block.
pub type ParseInlineMasmOutcome = Outcome<ast::Block>;

/// Parses zero or more AST forms from `source` using the CST-backed frontend.
///
/// Syntax diagnostics are retained as first-class output. Lowering proceeds when parsing emitted
/// warnings only, and a lowering error is added to the same diagnostic collection.
pub fn parse_forms(
    source_id: SourceId,
    source: &str,
    interned: &mut BTreeSet<Arc<str>>,
) -> ParseFormsOutcome {
    let Outcome {
        result: parse,
        diagnostics: parse_diagnostics,
    } = miden_assembly_syntax_cst::parse(source_id, source);
    let parse_failed = parse.is_err() || parse_diagnostics.has_errors();
    let mut diagnostics = DiagnosticCollector::new();
    let _ = diagnostics.merge(parse_diagnostics);

    let result = if parse_failed {
        Err(())
    } else {
        let mut context = LoweringContext::new(parse.unwrap(), source, interned);
        match lower_source_file(&mut context) {
            Ok(forms) => Ok(forms),
            Err(error) => {
                let _ = diagnostics.add(error);
                Err(())
            },
        }
    };

    Outcome {
        result,
        diagnostics: diagnostics.finish(),
    }
}

/// Parses the content of an inline MASM block.
///
/// Inline MASM is parsed as an [ast::Block], as if it was the body of a procedure definition. An
/// optional span restricts parsing to that portion of `source`.
pub fn parse_inline_masm(
    source_id: SourceId,
    source: &str,
    bounds: Option<SourceSpan>,
    interned: &mut BTreeSet<Arc<str>>,
) -> ParseInlineMasmOutcome {
    use miden_assembly_syntax_cst::ast::AstNode;

    let Outcome {
        result: parse,
        diagnostics: parse_diagnostics,
    } = miden_assembly_syntax_cst::parse_inline_masm(source_id, source, bounds);
    let parse_failed = parse.is_err() || parse_diagnostics.has_errors();
    let mut diagnostics = DiagnosticCollector::new();
    let _ = diagnostics.merge(parse_diagnostics);

    let result = if parse_failed {
        Err(())
    } else {
        let mut context = LoweringContext::new(parse.unwrap(), source, interned);
        let cst_block = miden_assembly_syntax_cst::ast::Block::cast(context.parse().syntax())
            .expect("inline masm root kind should always be Block");
        match blocks::lower_block(&mut context, &cst_block, 0) {
            Ok(block) => Ok(block),
            Err(error) => {
                let _ = diagnostics.add(*error);
                Err(())
            },
        }
    };

    Outcome {
        result,
        diagnostics: diagnostics.finish(),
    }
}
