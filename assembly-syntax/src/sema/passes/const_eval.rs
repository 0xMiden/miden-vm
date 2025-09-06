use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::utils::{hash_string_to_word, string_to_event_id};
use miden_debug_types::{Span, Spanned};

use crate::{
    Felt,
    ast::*,
    parser::{IntValue, WordValue},
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
                    Ok(ConstantExpr::Felt(value)) => match T::try_from(value.as_int()) {
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
    fn visit_mut_inst(&mut self, inst: &mut Span<Instruction>) -> ControlFlow<()> {
        use crate::ast::Instruction;
        if let Instruction::EmitImm(Immediate::Constant(name)) = &**inst {
            let span = name.span();
            match self.analyzer.get_constant(name) {
                Ok(ConstantExpr::Hash(HashKind::Event, _)) => {
                    // CHANGE: allow `emit.EVENT` when `EVENT` was defined via
                    //   const.EVENT = event("...")
                    // NOTE: This function only validates the kind; the actual resolution to a Felt
                    // happens below in `visit_mut_immediate_felt` just like other Felt immediates.
                    // Enabled syntax:
                    //   const.EVT = event("...")
                    //   emit.EVT
                },
                Ok(_) => {
                    // CHANGE: disallow `emit.CONST` unless CONST is defined via `event("...")`.
                    // Examples which now error:
                    //   const.BAD = 42
                    //   emit.BAD
                    //   const.W = word("foo")
                    //   emit.W
                    self.analyzer.error(SemanticAnalysisError::InvalidConstant { span });
                },
                Err(error) => self.analyzer.error(error),
            }
        }
        crate::ast::visit::visit_mut_inst(self, inst)
    }
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
                    Ok(ConstantExpr::Felt(value)) => {
                        *imm = Immediate::Value(Span::new(span, *value.inner()));
                    },
                    Ok(ConstantExpr::Hash(HashKind::Event, string)) => {
                        // CHANGE: resolve `event("...")` to a Felt when a Felt immediate is
                        // expected (e.g. enables `emit.EVENT`):
                        //   const.EVT = event("...")
                        //   emit.EVT
                        let event_id = string_to_event_id(string.as_str());
                        *imm = Immediate::Value(Span::new(span, event_id));
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
                    Ok(ConstantExpr::Felt(value)) => {
                        *imm = Immediate::Value(Span::new(span, IntValue::Felt(*value.inner())));
                    },
                    Ok(ConstantExpr::Word(value)) => {
                        *imm = Immediate::Value(Span::new(span, IntValue::Word(*value.inner())));
                    },
                    Ok(ConstantExpr::Hash(hash_kind, string)) => match hash_kind {
                        HashKind::Word => {
                            // Existing behavior for `const.W = word("...")`:
                            //   push.W    # pushes a Word
                            let hash_word = hash_string_to_word(string.as_str());
                            *imm = Immediate::Value(Span::new(
                                span,
                                IntValue::Word(WordValue(*hash_word)),
                            ));
                        },
                        HashKind::Event => {
                            // CHANGE: allow `const.EVT = event("...")` with IntValue contexts by
                            // reducing to a Felt via word()[0]. Enables:
                            //   const.EVT = event("...")
                            //   push.EVT                # pushes the Felt event id
                            let event_id = string_to_event_id(string.as_str());
                            *imm = Immediate::Value(Span::new(span, IntValue::Felt(event_id)));
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
