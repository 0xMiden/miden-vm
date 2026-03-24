mod context;
mod diagnostics;

use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};

use miden_debug_types::SourceFile;

use self::{context::LoweringContext, diagnostics::lower_cst_diagnostics};
use crate::{ast, parser::ParsingError};

pub(super) fn parse_forms_from_cst(
    source: Arc<SourceFile>,
    interned: &mut BTreeSet<Arc<str>>,
) -> Result<Vec<ast::Form>, ParsingError> {
    let parse = miden_assembly_syntax_cst::parse_source_file(source.clone());
    if let Some(error) = lower_cst_diagnostics(source.id(), parse.diagnostics()) {
        return Err(error);
    }

    LoweringContext::new(source, parse, interned).lower_forms()
}
