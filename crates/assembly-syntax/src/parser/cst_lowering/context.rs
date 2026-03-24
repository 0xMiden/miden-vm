use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};

use miden_assembly_syntax_cst::Parse as CstParse;
use miden_debug_types::SourceFile;

use crate::{ast, parser::ParsingError};

pub(super) struct LoweringContext<'a> {
    source: Arc<SourceFile>,
    _parse: CstParse,
    interned: &'a mut BTreeSet<Arc<str>>,
}

impl<'a> LoweringContext<'a> {
    pub(super) fn new(
        source: Arc<SourceFile>,
        parse: CstParse,
        interned: &'a mut BTreeSet<Arc<str>>,
    ) -> Self {
        Self { source, _parse: parse, interned }
    }

    pub(super) fn lower_forms(self) -> Result<Vec<ast::Form>, ParsingError> {
        let Self { source, _parse: _, interned } = self;

        // Phase 1 only introduces the backend seam and CST validation path. Actual CST-to-Form
        // lowering lands in subsequent phases, so the experimental backend delegates form
        // construction to the legacy parser once the CST has been validated successfully.
        super::super::parse_forms_with_lalrpop(source, interned)
    }
}
