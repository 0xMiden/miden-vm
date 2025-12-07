use alloc::{sync::Arc, vec::Vec};

use smallvec::SmallVec;

use crate::{
    ast::*,
    debuginfo::{SourceFile, SourceSpan, Span, Spanned},
    diagnostics::{Diagnostic, RelatedLabel, miette},
};

/// An error raised during evaluation of a constant expression
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum ConstEvalError {
    #[error("undefined constant '{symbol}'")]
    #[diagnostic(help("are you missing an import?"))]
    UndefinedSymbol {
        #[label("the constant referenced here is not defined in the current scope")]
        symbol: Ident,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("undefined constant '{path}'")]
    #[diagnostic(help(
        "is the constant exported from its containing module? if the referenced module \
        is in another library, make sure you provided it to the assembler"
    ))]
    UndefinedPath {
        path: Arc<Path>,
        #[label("this reference is invalid: no such definition found")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("invalid immediate: value is larger than expected range")]
    #[diagnostic()]
    ImmediateOverflow {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("invalid constant expression: division by zero")]
    DivisionByZero {
        #[label]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("invalid constant")]
    #[diagnostic(help("this constant does not resolve to a value of the right type"))]
    InvalidConstant {
        expected: &'static str,
        #[label("expected {expected}")]
        span: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("constant evaluation failed")]
    #[diagnostic(help("this constant cannot be evaluated, due to operands of incorrect type"))]
    InvalidConstExprOperand {
        #[label]
        span: SourceSpan,
        #[label("expected this operand to produce an integer value, but it does not")]
        operand: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
    },
    #[error("constant evaluation terminated due to infinite recursion")]
    #[diagnostic(help("dependencies between constants must form an acyclic graph"))]
    ConstEvalCycle {
        #[label("occurs while evaluating this expression")]
        start: SourceSpan,
        #[source_code]
        source_file: Option<Arc<SourceFile>>,
        #[related]
        detected: [RelatedLabel; 1],
    },
}

impl ConstEvalError {
    #[inline]
    pub fn undefined<Env>(symbol: Ident, env: &Env) -> Self
    where
        Env: ?Sized + ConstEnvironment,
        <Env as ConstEnvironment>::Error: From<Self>,
    {
        let source_file = env.get_source_file_for(symbol.span());
        Self::UndefinedSymbol { symbol, source_file }
    }

    #[inline]
    pub fn invalid_constant<Env>(span: SourceSpan, expected: &'static str, env: &Env) -> Self
    where
        Env: ?Sized + ConstEnvironment,
        <Env as ConstEnvironment>::Error: From<Self>,
    {
        let source_file = env.get_source_file_for(span);
        Self::InvalidConstant { expected, span, source_file }
    }

    #[inline]
    pub fn eval_cycle<Env>(start: SourceSpan, detected: SourceSpan, env: &Env) -> Self
    where
        Env: ?Sized + ConstEnvironment,
        <Env as ConstEnvironment>::Error: From<Self>,
    {
        let start_file = env.get_source_file_for(start);
        let detected_file = env.get_source_file_for(start);
        let detected = [RelatedLabel::error("related error")
            .with_labeled_span(
                detected,
                "cycle occurs because we attempt to eval this constant recursively",
            )
            .with_source_file(detected_file)];
        Self::ConstEvalCycle { start, source_file: start_file, detected }
    }
}

#[derive(Debug)]
pub enum CachedConstantValue<'a> {
    /// We've already evaluated a constant to a concrete value
    Hit(&'a ConstantValue),
    /// We've not yet evaluated a constant expression to a value
    Miss(&'a ConstantExpr),
}

impl CachedConstantValue<'_> {
    pub fn into_expr(self) -> ConstantExpr {
        match self {
            Self::Hit(value) => value.clone().into(),
            Self::Miss(expr) => expr.clone(),
        }
    }
}

impl Spanned for CachedConstantValue<'_> {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Hit(value) => value.span(),
            Self::Miss(expr) => expr.span(),
        }
    }
}

/// There are two phases to constant evaluation, one during semantic analysis, and another phase
/// performed during linking of the final assembly, on any constant expressions that were left
/// partially or unevaluated during semantic analysis due to external references. This trait is
/// used to abstract over the environment in which the evaluator runs, so that we can use it in
/// both phases by simply providing a suitable implementation.
pub trait ConstEnvironment {
    /// The error type used in the current evaluation phase.
    ///
    /// The error type must support infallible conversions from [ConstEvalError].
    type Error: From<ConstEvalError>;

    /// Map a [SourceSpan] to the [SourceFile] to which it refers
    fn get_source_file_for(&self, span: SourceSpan) -> Option<Arc<SourceFile>>;

    /// Get the constant expression/value bound to `name` in the current scope.
    ///
    /// Implementations should return `Ok(None)` if the symbol is defined, but not yet resolvable to
    /// a concrete definition.
    fn get(&self, name: &Ident) -> Result<Option<CachedConstantValue<'_>>, Self::Error>;

    /// Get the constant expression/value defined at `path`, which is resolved using the imports
    /// and definitions in the current scope.
    ///
    /// This function should return `Ok(None)` if unresolvable external references should be left
    /// unevaluated, rather than treated as an undefined symbol error.
    ///
    /// This function should return `Err` if any of the following are true:
    ///
    /// * The path cannot be resolved, and the implementation wishes this to be treated as an error
    /// * The definition of the constant was found, but it does not have public visibility
    fn get_by_path(
        &self,
        path: Span<&Path>,
    ) -> Result<Option<CachedConstantValue<'_>>, Self::Error>;

    /// A specialized form of [ConstEnvironment::get], which validates that the constant expression
    /// returned by `get` evaluates to an error string, returning that string, or raising an error
    /// if invalid.
    fn get_error(&self, name: &Ident) -> Result<Option<Arc<str>>, Self::Error> {
        match self.get(name)? {
            Some(expr) => match expr {
                CachedConstantValue::Hit(ConstantValue::String(spanned)) => {
                    Ok(Some(spanned.clone().into_inner()))
                },
                CachedConstantValue::Miss(ConstantExpr::String(spanned)) => {
                    Ok(Some(spanned.clone().into_inner()))
                },
                CachedConstantValue::Miss(ConstantExpr::Var(_)) => Ok(None),
                other => {
                    Err(ConstEvalError::invalid_constant(other.span(), "a string", self).into())
                },
            },
            None => Ok(None),
        }
    }

    /// A specialized form of [ConstEnvironment::get_by_path], which validates that the constant
    /// expression returned by `get_by_path` evaluates to an error string, returning that string,
    /// or raising an error if invalid.
    fn get_error_by_path(&self, path: Span<&Path>) -> Result<Option<Arc<str>>, Self::Error> {
        match self.get_by_path(path)? {
            Some(expr) => match expr {
                CachedConstantValue::Hit(ConstantValue::String(spanned)) => {
                    Ok(Some(spanned.clone().into_inner()))
                },
                CachedConstantValue::Miss(ConstantExpr::String(spanned)) => {
                    Ok(Some(spanned.clone().into_inner()))
                },
                CachedConstantValue::Miss(ConstantExpr::Var(_)) => Ok(None),
                other => {
                    Err(ConstEvalError::invalid_constant(other.span(), "a string", self).into())
                },
            },
            None => Ok(None),
        }
    }

    /// This method is called when the evaluator begins to evaluate the constant at `path`
    #[inline]
    #[allow(unused_variables)]
    fn on_eval_start(&mut self, path: Span<&Path>) {}

    /// This method is called when the evaluator has finished evaluating the constant at `path`.
    ///
    /// The `value` here is the value produced as the result of evaluation.
    #[inline]
    #[allow(unused_variables)]
    fn on_eval_completed(&mut self, name: Span<&Path>, value: &ConstantExpr) {}
}

/// Evaluate `expr` in `env`, producing a new [ConstantExpr] representing the value produced as the
/// result of evaluation.
///
/// If `expr` could not be fully evaluated, e.g. due to external references which are not yet
/// available, the returned expression may be only partially evaluated, or even entirely
/// unevaluated.
///
/// It is up to `env` to determine how unresolved foreign symbols are to be handled. See the
/// [ConstEnvironment] trait for more details.
pub fn expr<Env>(
    value: &ConstantExpr,
    env: &mut Env,
) -> Result<ConstantExpr, <Env as ConstEnvironment>::Error>
where
    Env: ?Sized + ConstEnvironment,
    <Env as ConstEnvironment>::Error: From<ConstEvalError>,
{
    /// Represents the type of a continuation to apply during evaluation
    enum Cont {
        /// We have reached an anonymous expression to evaluate
        Eval(ConstantExpr),
        /// We have finished evaluating the operands of a constant op, and must now apply the
        /// operation to them, pushing the result on the operand stack.
        Apply(Span<ConstantOp>),
        /// We have finished evaluating a reference to another constant and are returning
        /// its value on the operand stack
        Return(Span<Arc<Path>>),
    }

    // If we don't require evaluation, we're done
    if let Some(value) = value.as_value() {
        return Ok(value.into());
    }

    // The operand stack
    let mut stack = Vec::with_capacity(8);
    // The continuation stack
    let mut continuations = Vec::with_capacity(8);
    // Start evaluation from the root expression
    continuations.push(Cont::Eval(value.clone()));
    // Keep track of the stack of constants being expanded during evaluation
    //
    // Any time we reach a reference to another constant that requires evaluation, we check if
    // we're already in the process of evaluating that constant. If so, then a cycle is present
    // and we must raise an eval error.
    let mut evaluating = SmallVec::<[_; 8]>::new_const();

    while let Some(next) = continuations.pop() {
        match next {
            Cont::Eval(
                expr @ (ConstantExpr::Int(_)
                | ConstantExpr::String(_)
                | ConstantExpr::Word(_)
                | ConstantExpr::Hash(..)),
            ) => {
                stack.push(expr);
            },
            Cont::Eval(ConstantExpr::Var(path)) => {
                if evaluating.contains(&path) {
                    return Err(
                        ConstEvalError::eval_cycle(evaluating[0].span(), path.span(), env).into()
                    );
                }

                if let Some(name) = path.as_ident() {
                    let name = name.with_span(path.span());
                    if let Some(expr) = env.get(&name)?.map(|e| e.into_expr()) {
                        env.on_eval_start(path.as_deref());
                        evaluating.push(path.clone());
                        continuations.push(Cont::Return(path.clone()));
                        continuations.push(Cont::Eval(expr));
                    } else {
                        stack.push(ConstantExpr::Var(path));
                    }
                } else if let Some(expr) = env.get_by_path(path.as_deref())? {
                    let expr = expr.into_expr();
                    env.on_eval_start(path.as_deref());
                    evaluating.push(path.clone());
                    continuations.push(Cont::Return(path.clone()));
                    continuations.push(Cont::Eval(expr));
                } else {
                    stack.push(ConstantExpr::Var(path));
                }
            },
            Cont::Eval(ConstantExpr::BinaryOp { span, op, lhs, rhs, .. }) => {
                continuations.push(Cont::Apply(Span::new(span, op)));
                continuations.push(Cont::Eval(*lhs));
                continuations.push(Cont::Eval(*rhs));
            },
            Cont::Apply(op) => {
                let lhs = stack.pop().unwrap();
                let rhs = stack.pop().unwrap();
                let (span, op) = op.into_parts();
                match (lhs, rhs) {
                    (ConstantExpr::Int(lhs), ConstantExpr::Int(rhs)) => {
                        let lhs = lhs.into_inner();
                        let rhs = rhs.into_inner();
                        let result = match op {
                            ConstantOp::Add => lhs.checked_add(rhs).ok_or_else(|| {
                                ConstEvalError::ImmediateOverflow {
                                    span,
                                    source_file: env.get_source_file_for(span),
                                }
                            })?,
                            ConstantOp::Sub => lhs.checked_sub(rhs).ok_or_else(|| {
                                ConstEvalError::ImmediateOverflow {
                                    span,
                                    source_file: env.get_source_file_for(span),
                                }
                            })?,
                            ConstantOp::Mul => lhs.checked_mul(rhs).ok_or_else(|| {
                                ConstEvalError::ImmediateOverflow {
                                    span,
                                    source_file: env.get_source_file_for(span),
                                }
                            })?,
                            ConstantOp::Div | ConstantOp::IntDiv => lhs
                                .checked_div(rhs)
                                .ok_or_else(|| ConstEvalError::DivisionByZero {
                                    span,
                                    source_file: env.get_source_file_for(span),
                                })?,
                        };
                        stack.push(ConstantExpr::Int(Span::new(span, result)));
                    },
                    operands @ ((ConstantExpr::Int(_), ConstantExpr::Var(_))
                    | (ConstantExpr::Var(_), ConstantExpr::Int(_))
                    | (ConstantExpr::Var(_), ConstantExpr::Var(_))) => {
                        let (lhs, rhs) = operands;
                        stack.push(ConstantExpr::BinaryOp {
                            span,
                            op,
                            lhs: lhs.into(),
                            rhs: rhs.into(),
                        });
                    },
                    (ConstantExpr::Int(_) | ConstantExpr::Var(_), rhs) => {
                        let operand = rhs.span();
                        return Err(ConstEvalError::InvalidConstExprOperand {
                            span,
                            operand,
                            source_file: env.get_source_file_for(operand),
                        }
                        .into());
                    },
                    (lhs, _) => {
                        let operand = lhs.span();
                        return Err(ConstEvalError::InvalidConstExprOperand {
                            span,
                            operand,
                            source_file: env.get_source_file_for(operand),
                        }
                        .into());
                    },
                }
            },
            Cont::Return(from) => {
                debug_assert!(
                    !stack.is_empty(),
                    "returning from evaluating a constant reference is expected to produce at least one output"
                );
                evaluating.pop();

                env.on_eval_completed(from.as_deref(), stack.last().unwrap());
            },
        }
    }

    // When we reach here, we should have exactly one expression on the operand stack
    assert_eq!(stack.len(), 1, "expected constant evaluation to produce exactly one output");
    // SAFETY: The above assertion guarantees that the stack has an element, and that `pop` will
    // always succeed, thus the safety requirements of `unwrap_unchecked` are upheld
    Ok(unsafe { stack.pop().unwrap_unchecked() })
}
