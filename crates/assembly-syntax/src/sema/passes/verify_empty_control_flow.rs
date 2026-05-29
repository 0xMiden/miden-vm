use core::ops::ControlFlow;

use crate::{
    ast::{Op, Visit, visit::visit_op},
    sema::{AnalysisContext, SemanticAnalysisError},
};

pub struct VerifyEmptyControlFlow<'a> {
    analyzer: &'a mut AnalysisContext,
}

impl<'a> VerifyEmptyControlFlow<'a> {
    pub fn new(analyzer: &'a mut AnalysisContext) -> Self {
        Self { analyzer }
    }
}

impl Visit for VerifyEmptyControlFlow<'_> {
    fn visit_op(&mut self, op: &Op) -> ControlFlow<()> {
        match op {
            Op::While { span, body } if body.is_empty() => {
                self.analyzer.error(SemanticAnalysisError::EmptyWhileBody { span: *span });
            },
            Op::Repeat { span, body, .. } if body.is_empty() => {
                self.analyzer.error(SemanticAnalysisError::EmptyRepeatBody { span: *span });
            },
            _ => (),
        }

        visit_op(self, op)
    }
}
