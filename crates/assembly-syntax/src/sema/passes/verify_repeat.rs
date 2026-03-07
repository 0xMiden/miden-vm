use core::ops::ControlFlow;

use miden_debug_types::Spanned;

use crate::{
    MAX_REPEAT_COUNT,
    ast::{Immediate, Op, VisitMut, visit::visit_mut_op},
    sema::{AnalysisContext, SemanticAnalysisError},
};

pub struct VerifyRepeatCounts<'a> {
    analyzer: &'a mut AnalysisContext,
}

impl<'a> VerifyRepeatCounts<'a> {
    pub fn new(analyzer: &'a mut AnalysisContext) -> Self {
        Self { analyzer }
    }
}

impl VisitMut for VerifyRepeatCounts<'_> {
    fn visit_mut_op(&mut self, op: &mut Op) -> ControlFlow<()> {
        if let Op::Repeat { count, .. } = op
            && let Immediate::Value(value) = count
        {
            let repeat_count = value.into_inner();
            if repeat_count == 0 || repeat_count > MAX_REPEAT_COUNT {
                self.analyzer.error(SemanticAnalysisError::InvalidRepeatCount {
                    span: count.span(),
                    min: 1,
                    max: MAX_REPEAT_COUNT,
                });
            }
        }

        visit_mut_op(self, op)
    }
}
