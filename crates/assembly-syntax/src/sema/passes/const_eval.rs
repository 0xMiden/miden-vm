use alloc::{sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_core::{EventId, utils::hash_string_to_word};
use miden_debug_types::{Span, Spanned};

use crate::{
    Felt,
    ast::{
        constants::{ConstEnvironment, ConstEvalError, eval::CachedConstantValue},
        *,
    },
    parser::{IntValue, PushValue, WordValue},
};

/// This visitor evaluates all constant expressions and folds them to literals.
///
/// This visitor is abstracted over the const-evaluation environment so that it's implementation
/// can be reused for both module-local rewrites, and link-time rewrites where we have all the
/// symbols available to resolve foreign constants.
pub struct ConstEvalVisitor<'env, Env>
where
    Env: ?Sized + ConstEnvironment,
{
    env: &'env mut Env,
    errors: Vec<<Env as ConstEnvironment>::Error>,
}

impl<'env, Env> ConstEvalVisitor<'env, Env>
where
    Env: ?Sized + ConstEnvironment,
    <Env as ConstEnvironment>::Error: From<ConstEvalError>,
{
    pub fn new(env: &'env mut Env) -> Self {
        Self { env, errors: Default::default() }
    }

    pub fn into_result(self) -> Result<(), Vec<<Env as ConstEnvironment>::Error>> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }

    fn eval_const<T>(&mut self, imm: &mut Immediate<T>) -> ControlFlow<()>
    where
        T: TryFrom<u64>,
    {
        match imm {
            Immediate::Value(_) => ControlFlow::Continue(()),
            Immediate::Constant(name) => {
                let span = name.span();
                let value = match self.env.get(name) {
                    Ok(Some(
                        CachedConstantValue::Hit(ConstantValue::Int(value))
                        | CachedConstantValue::Miss(ConstantExpr::Int(value)),
                    )) => *value,
                    Ok(Some(CachedConstantValue::Miss(
                        expr @ (ConstantExpr::Var(_) | ConstantExpr::BinaryOp { .. }),
                    ))) => {
                        // A reference to another constant was used, try to evaluate the expression
                        let expr = expr.clone();
                        match crate::ast::constants::eval::expr(&expr, self.env) {
                            Ok(ConstantExpr::Int(value)) => value,
                            // Unable to evaluate in the current context
                            Ok(ConstantExpr::Var(_) | ConstantExpr::BinaryOp { .. }) => {
                                return ControlFlow::Continue(());
                            },
                            Ok(_) => {
                                self.errors.push(
                                    ConstEvalError::InvalidConstant {
                                        span,
                                        expected: "an integer",
                                        source_file: self.env.get_source_file_for(span),
                                    }
                                    .into(),
                                );
                                return ControlFlow::Continue(());
                            },
                            Err(err) => {
                                self.errors.push(err);
                                return ControlFlow::Continue(());
                            },
                        }
                    },
                    Ok(Some(_)) => {
                        self.errors.push(
                            ConstEvalError::InvalidConstant {
                                span,
                                expected: core::any::type_name::<T>(),
                                source_file: self.env.get_source_file_for(span),
                            }
                            .into(),
                        );
                        return ControlFlow::Continue(());
                    },
                    Ok(None) => return ControlFlow::Continue(()),
                    Err(err) => {
                        self.errors.push(err);
                        return ControlFlow::Continue(());
                    },
                };
                match T::try_from(value.as_int()) {
                    Ok(value) => {
                        *imm = Immediate::Value(Span::new(span, value));
                    },
                    Err(_) => {
                        self.errors.push(
                            ConstEvalError::ImmediateOverflow {
                                span,
                                source_file: self.env.get_source_file_for(span),
                            }
                            .into(),
                        );
                    },
                }
                ControlFlow::Continue(())
            },
        }
    }
}

impl<'env, Env> VisitMut for ConstEvalVisitor<'env, Env>
where
    Env: ?Sized + ConstEnvironment,
    <Env as ConstEnvironment>::Error: From<ConstEvalError>,
{
    fn visit_mut_constant(&mut self, constant: &mut Constant) -> ControlFlow<()> {
        if constant.value.is_value() {
            return ControlFlow::Continue(());
        }

        match crate::ast::constants::eval::expr(&constant.value, self.env) {
            Ok(evaluated) => {
                constant.value = evaluated;
            },
            Err(err) => {
                self.errors.push(err);
            },
        }
        ControlFlow::Continue(())
    }
    fn visit_mut_inst(&mut self, inst: &mut Span<Instruction>) -> ControlFlow<()> {
        use crate::ast::Instruction;
        if let Instruction::EmitImm(Immediate::Constant(name)) = &**inst {
            let span = name.span();
            match self.env.get(name) {
                Ok(Some(
                    CachedConstantValue::Miss(ConstantExpr::Hash(HashKind::Event, _))
                    | CachedConstantValue::Hit(ConstantValue::Hash(HashKind::Event, _)),
                )) => {
                    // CHANGE: allow `emit.EVENT` when `EVENT` was defined via
                    //   const.EVENT = event("...")
                    // NOTE: This function only validates the kind; the actual resolution to a Felt
                    // happens below in `visit_mut_immediate_felt` just like other Felt immediates.
                    // Enabled syntax:
                    //   const.EVT = event("...")
                    //   emit.EVT
                },
                Ok(Some(CachedConstantValue::Miss(expr @ ConstantExpr::Var(_)))) => {
                    // A reference to another constant was used, try to evaluate the expression
                    let expr = expr.clone();
                    match crate::ast::constants::eval::expr(&expr, self.env) {
                        Ok(ConstantExpr::Hash(HashKind::Event, _)) => (),
                        // Unable to evaluate in the current context
                        Ok(ConstantExpr::Var(_)) => return ControlFlow::Continue(()),
                        Ok(_) => {
                            self.errors.push(
                                ConstEvalError::InvalidConstant {
                                    span,
                                    expected: "an event name",
                                    source_file: self.env.get_source_file_for(span),
                                }
                                .into(),
                            );
                        },
                        Err(err) => {
                            self.errors.push(err);
                        },
                    }
                },
                Ok(Some(_)) => {
                    // CHANGE: disallow `emit.CONST` unless CONST is defined via `event("...")`.
                    // Examples which now error:
                    //   const.BAD = 42
                    //   emit.BAD
                    //   const.W = word("foo")
                    //   emit.W
                    self.errors.push(
                        ConstEvalError::InvalidConstant {
                            span,
                            expected: "an event name",
                            source_file: self.env.get_source_file_for(span),
                        }
                        .into(),
                    );
                },
                // The value is not yet available, proceed for now
                Ok(None) => return ControlFlow::Continue(()),
                Err(err) => {
                    self.errors.push(err);
                },
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
                match self.env.get_error(name) {
                    Ok(Some(value)) => {
                        *imm = Immediate::Value(Span::new(span, value.clone()));
                    },
                    // The constant is externally-defined, and not available yet
                    Ok(None) => (),
                    Err(error) => {
                        self.errors.push(error);
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
                match self.env.get(name) {
                    Ok(Some(
                        CachedConstantValue::Miss(ConstantExpr::Int(value))
                        | CachedConstantValue::Hit(ConstantValue::Int(value)),
                    )) => {
                        *imm = Immediate::Value(Span::new(span, Felt::new(value.inner().as_int())));
                    },
                    Ok(Some(
                        CachedConstantValue::Miss(ConstantExpr::Hash(HashKind::Event, string))
                        | CachedConstantValue::Hit(ConstantValue::Hash(HashKind::Event, string)),
                    )) => {
                        // CHANGE: resolve `event("...")` to a Felt when a Felt immediate is
                        // expected (e.g. enables `emit.EVENT`):
                        //   const.EVT = event("...")
                        //   emit.EVT
                        let event_id = EventId::from_name(string.as_str()).as_felt();
                        *imm = Immediate::Value(Span::new(span, event_id));
                    },
                    Ok(Some(CachedConstantValue::Miss(
                        expr @ (ConstantExpr::Var(_) | ConstantExpr::BinaryOp { .. }),
                    ))) => {
                        // A reference to another constant was used, try to evaluate the expression
                        let expr = expr.clone();
                        match crate::ast::constants::eval::expr(&expr, self.env) {
                            Ok(ConstantExpr::Int(value)) => {
                                *imm = Immediate::Value(Span::new(
                                    span,
                                    Felt::new(value.inner().as_int()),
                                ));
                            },
                            Ok(ConstantExpr::Hash(HashKind::Event, value)) => {
                                // CHANGE: resolve `event("...")` to a Felt when a Felt immediate is
                                // expected (e.g. enables `emit.EVENT`):
                                //   const.EVT = event("...")
                                //   emit.EVT
                                let event_id = EventId::from_name(value.as_str()).as_felt();
                                *imm = Immediate::Value(Span::new(span, event_id));
                            },
                            // Unable to evaluate in the current context
                            Ok(ConstantExpr::Var(_) | ConstantExpr::BinaryOp { .. }) => (),
                            Ok(_) => {
                                self.errors.push(
                                    ConstEvalError::InvalidConstant {
                                        span,
                                        expected: "a felt",
                                        source_file: self.env.get_source_file_for(span),
                                    }
                                    .into(),
                                );
                            },
                            Err(err) => {
                                self.errors.push(err);
                            },
                        }
                    },
                    // Invalid value
                    Ok(Some(_)) => {
                        self.errors.push(
                            ConstEvalError::InvalidConstant {
                                span,
                                expected: "a felt",
                                source_file: self.env.get_source_file_for(span),
                            }
                            .into(),
                        );
                    },
                    // The constant expression references an externally-defined symbol which is
                    // not available yet, so ignore for now
                    Ok(None) => (),
                    Err(err) => {
                        self.errors.push(err);
                    },
                }
                ControlFlow::Continue(())
            },
        }
    }

    fn visit_mut_immediate_push_value(
        &mut self,
        imm: &mut Immediate<PushValue>,
    ) -> ControlFlow<()> {
        match imm {
            Immediate::Value(_) => ControlFlow::Continue(()),
            Immediate::Constant(name) => {
                let span = name.span();
                match self.env.get(name) {
                    Ok(Some(
                        CachedConstantValue::Miss(ConstantExpr::Int(value))
                        | CachedConstantValue::Hit(ConstantValue::Int(value)),
                    )) => {
                        *imm = Immediate::Value(Span::new(span, PushValue::Int(*value.inner())));
                    },
                    Ok(Some(
                        CachedConstantValue::Miss(ConstantExpr::Word(value))
                        | CachedConstantValue::Hit(ConstantValue::Word(value)),
                    )) => {
                        *imm = Immediate::Value(Span::new(span, PushValue::Word(*value.inner())));
                    },
                    Ok(Some(
                        CachedConstantValue::Miss(ConstantExpr::Hash(hash_kind, string))
                        | CachedConstantValue::Hit(ConstantValue::Hash(hash_kind, string)),
                    )) => match hash_kind {
                        HashKind::Word => {
                            // Existing behavior for `const.W = word("...")`:
                            //   push.W    # pushes a Word
                            let hash_word = hash_string_to_word(string.as_str());
                            *imm = Immediate::Value(Span::new(
                                span,
                                PushValue::Word(WordValue(*hash_word)),
                            ));
                        },
                        HashKind::Event => {
                            // CHANGE: allow `const.EVT = event("...")` with IntValue contexts by
                            // reducing to a Felt via word()[0]. Enables:
                            //   const.EVT = event("...")
                            //   push.EVT # pushes the Felt event id
                            let event_id = EventId::from_name(string.as_str()).as_felt();
                            *imm =
                                Immediate::Value(Span::new(span, IntValue::Felt(event_id).into()));
                        },
                    },
                    Ok(Some(CachedConstantValue::Miss(
                        expr @ (ConstantExpr::Var(_) | ConstantExpr::BinaryOp { .. }),
                    ))) => {
                        // A reference to another constant was used, try to evaluate the expression
                        let expr = expr.clone();
                        match crate::ast::constants::eval::expr(&expr, self.env) {
                            Ok(ConstantExpr::Int(value)) => {
                                *imm = Immediate::Value(Span::new(
                                    span,
                                    PushValue::Int(*value.inner()),
                                ));
                            },
                            Ok(ConstantExpr::Word(value)) => {
                                *imm = Immediate::Value(Span::new(
                                    span,
                                    PushValue::Word(*value.inner()),
                                ));
                            },
                            Ok(ConstantExpr::Hash(HashKind::Word, value)) => {
                                // Existing behavior for `const.W = word("...")`:
                                //   push.W    # pushes a Word
                                let hash_word = hash_string_to_word(value.as_str());
                                *imm = Immediate::Value(Span::new(
                                    span,
                                    PushValue::Word(WordValue(*hash_word)),
                                ));
                            },
                            Ok(ConstantExpr::Hash(HashKind::Event, value)) => {
                                // CHANGE: allow `const.EVT = event("...")` with IntValue contexts
                                // by reducing to a Felt via word()[0]. Enables:
                                //     const.EVT = event("...")
                                //     push.EVT # pushes the Felt event id
                                let event_id = EventId::from_name(value.as_str()).as_felt();
                                *imm = Immediate::Value(Span::new(
                                    span,
                                    IntValue::Felt(event_id).into(),
                                ));
                            },
                            // Unable to evaluate in the current context
                            Ok(ConstantExpr::Var(_) | ConstantExpr::BinaryOp { .. }) => (),
                            Ok(_) => {
                                self.errors.push(
                                    ConstEvalError::InvalidConstant {
                                        span,
                                        expected: "an integer or word",
                                        source_file: self.env.get_source_file_for(span),
                                    }
                                    .into(),
                                );
                            },
                            Err(err) => {
                                self.errors.push(err);
                            },
                        }
                    },
                    Ok(Some(_)) => {
                        self.errors.push(
                            ConstEvalError::InvalidConstant {
                                span,
                                expected: "an integer or word",
                                source_file: self.env.get_source_file_for(span),
                            }
                            .into(),
                        );
                    },
                    // The constant references an externally-defined symbol which is not yet
                    // available, so ignore for now
                    Ok(None) => (),
                    Err(err) => {
                        self.errors.push(err);
                    },
                }
                ControlFlow::Continue(())
            },
        }
    }

    fn visit_mut_immediate_word_value(
        &mut self,
        imm: &mut Immediate<WordValue>,
    ) -> ControlFlow<()> {
        match imm {
            Immediate::Value(_) => ControlFlow::Continue(()),
            Immediate::Constant(name) => {
                let span = name.span();
                match self.env.get(name) {
                    Ok(Some(
                        CachedConstantValue::Miss(ConstantExpr::Word(value))
                        | CachedConstantValue::Hit(ConstantValue::Word(value)),
                    )) => {
                        *imm = Immediate::Value(Span::new(span, *value.inner()));
                    },
                    Ok(Some(
                        CachedConstantValue::Miss(ConstantExpr::Hash(HashKind::Word, string))
                        | CachedConstantValue::Hit(ConstantValue::Hash(HashKind::Word, string)),
                    )) => {
                        // Existing behavior for `const.W = word("...")`:
                        //   push.W    # pushes a Word
                        let hash_word = hash_string_to_word(string.as_str());
                        *imm = Immediate::Value(Span::new(span, WordValue(*hash_word)));
                    },
                    Ok(Some(CachedConstantValue::Miss(expr @ ConstantExpr::Var(_)))) => {
                        // A reference to another constant was used, try to evaluate the expression
                        let expr = expr.clone();
                        match crate::ast::constants::eval::expr(&expr, self.env) {
                            Ok(ConstantExpr::Word(value)) => {
                                *imm = Immediate::Value(Span::new(span, *value.inner()));
                            },
                            Ok(ConstantExpr::Hash(HashKind::Word, value)) => {
                                // Existing behavior for `const.W = word("...")`:
                                //   push.W    # pushes a Word
                                let hash_word = hash_string_to_word(value.as_str());
                                *imm = Immediate::Value(Span::new(span, WordValue(*hash_word)));
                            },
                            // Unable to evaluate in the current context
                            Ok(ConstantExpr::Var(_)) => (),
                            Ok(_) => {
                                self.errors.push(
                                    ConstEvalError::InvalidConstant {
                                        span,
                                        expected: "a word",
                                        source_file: self.env.get_source_file_for(span),
                                    }
                                    .into(),
                                );
                            },
                            Err(err) => {
                                self.errors.push(err);
                            },
                        }
                    },
                    Ok(Some(_)) => {
                        self.errors.push(
                            ConstEvalError::InvalidConstant {
                                span,
                                expected: "a word",
                                source_file: self.env.get_source_file_for(span),
                            }
                            .into(),
                        );
                    },
                    // The constant references an externally-defined symbol which is not yet
                    // available, so ignore for now
                    Ok(None) => (),
                    Err(err) => {
                        self.errors.push(err);
                    },
                }
                ControlFlow::Continue(())
            },
        }
    }
}
