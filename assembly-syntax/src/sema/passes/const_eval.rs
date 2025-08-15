use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_debug_types::{Span, Spanned};

use crate::{
    Felt,
    ast::*,
    parser::IntValue,
    sema::{AnalysisContext, SemanticAnalysisError},
};

/// This visitor evaluates all constant expressions and folds them to literals.
pub struct ConstEvalVisitor<'analyzer> {
    analyzer: &'analyzer mut AnalysisContext,
}

impl<'analyzer> ConstEvalVisitor<'analyzer> {
    pub fn new(analyzer: &'analyzer mut AnalysisContext) -> Self {
        Self { analyzer }
    }
}

impl ConstEvalVisitor<'_> {
    fn eval_const<T>(&mut self, imm: &mut Immediate<T>) -> ControlFlow<()>
    where
        T: TryFrom<u64>,
    {
        match imm {
            Immediate::Value(_) => ControlFlow::Continue(()),
            Immediate::Constant(name) => {
                let span = name.span();
                match self.analyzer.get_constant(name) {
                    Ok(ConstantExpr::Literal(value)) => match T::try_from(value.as_int()) {
                        Ok(value) => {
                            *imm = Immediate::Value(Span::new(span, value));
                        },
                        Err(_) => {
                            self.analyzer.error(SemanticAnalysisError::ImmediateOverflow { span });
                        },
                    },
                    Err(error) => {
                        self.analyzer.error(error);
                    },
                    _ => self.analyzer.error(SemanticAnalysisError::InvalidConstant { span }),
                }
                ControlFlow::Continue(())
            },
        }
    }
}

impl VisitMut for ConstEvalVisitor<'_> {
    fn visit_mut_immediate_u8(&mut self, imm: &mut Immediate<u8>) -> ControlFlow<()> {
        self.eval_const(imm)
    }
    fn visit_mut_immediate_u16(&mut self, imm: &mut Immediate<u16>) -> ControlFlow<()> {
        self.eval_const(imm)
    }
    fn visit_mut_immediate_u32(&mut self, imm: &mut Immediate<u32>) -> ControlFlow<()> {
        self.eval_const(imm)
    }
    fn visit_mut_immediate_error_message(
        &mut self,
        imm: &mut Immediate<Arc<str>>,
    ) -> ControlFlow<()> {
        match imm {
            Immediate::Value(_) => ControlFlow::Continue(()),
            Immediate::Constant(name) => {
                let span = name.span();
                match self.analyzer.get_error(name) {
                    Ok(value) => {
                        *imm = Immediate::Value(Span::new(span, value));
                    },
                    Err(error) => {
                        self.analyzer.error(error);
                    },
                }
                ControlFlow::Continue(())
            },
        }
    }
    fn visit_mut_immediate_felt(&mut self, imm: &mut Immediate<Felt>) -> ControlFlow<()> {
        match imm {
            Immediate::Value(_) => ControlFlow::Continue(()),
            Immediate::Constant(name) => {
                let span = name.span();
                match self.analyzer.get_constant(name) {
                    Ok(ConstantExpr::Literal(value)) => {
                        *imm = Immediate::Value(Span::new(span, *value.inner()));
                    },
                    Err(error) => {
                        self.analyzer.error(error);
                    },
                    _ => self.analyzer.error(SemanticAnalysisError::InvalidConstant { span }),
                }
                ControlFlow::Continue(())
            },
        }
    }

    fn visit_mut_immediate_hex(&mut self, imm: &mut Immediate<IntValue>) -> ControlFlow<()> {
        match imm {
            Immediate::Value(_) => ControlFlow::Continue(()),
            Immediate::Constant(name) => {
                let span = name.span();
                match self.analyzer.get_constant(name) {
                    Ok(ConstantExpr::Literal(value)) => {
                        *imm = Immediate::Value(Span::new(span, IntValue::Felt(*value.inner())));
                    },
                    Ok(ConstantExpr::Word(value)) => {
                        *imm = Immediate::Value(Span::new(span, IntValue::Word(*value.inner())));
                    },
                    Ok(ConstantExpr::HashWord(_, hash_word)) => {
                        *imm = Immediate::Value(Span::new(span, IntValue::Word(*hash_word)));
                    },
                    Err(error) => {
                        self.analyzer.error(error);
                    },
                    _ => self.analyzer.error(SemanticAnalysisError::InvalidConstant { span }),
                }
                ControlFlow::Continue(())
            },
        }
    }
}
