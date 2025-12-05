use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

use miden_debug_types::{SourceFile, Span, Spanned};
use miden_utils_diagnostics::{Diagnostic, Severity};
use smallvec::SmallVec;

use super::{SemanticAnalysisError, SyntaxError};
use crate::ast::*;

/// This maintains the state for semantic analysis of a single [Module].
pub struct AnalysisContext {
    constants: BTreeMap<Ident, Constant>,
    procedures: BTreeSet<ProcedureName>,
    errors: Vec<SemanticAnalysisError>,
    source_file: Arc<SourceFile>,
    warnings_as_errors: bool,
}

impl AnalysisContext {
    pub fn new(source_file: Arc<SourceFile>) -> Self {
        Self {
            constants: Default::default(),
            procedures: Default::default(),
            errors: Default::default(),
            source_file,
            warnings_as_errors: false,
        }
    }

    pub fn set_warnings_as_errors(&mut self, yes: bool) {
        self.warnings_as_errors = yes;
    }

    #[inline(always)]
    pub fn warnings_as_errors(&self) -> bool {
        self.warnings_as_errors
    }

    pub fn register_procedure_name(&mut self, name: ProcedureName) {
        self.procedures.insert(name);
    }

    /// Define a new constant `constant`
    ///
    /// Returns `Err` if a constant with the same name is already defined
    pub fn define_constant(&mut self, constant: Constant) -> Result<(), SyntaxError> {
        use alloc::collections::btree_map::Entry;

        // Handle symbol conflicts before eval to make sure we can catch self-referential
        // expressions.
        match self.constants.entry(constant.name.clone()) {
            Entry::Occupied(entry) => {
                self.errors.push(SemanticAnalysisError::SymbolConflict {
                    span: constant.span(),
                    prev_span: entry.get().span(),
                });
            },
            Entry::Vacant(entry) => {
                entry.insert(constant);
            },
        }
        Ok(())
    }

    /// Rewrite all constant declarations by performing const evaluation of their expressions.
    ///
    /// This also has the effect of validating that the constant expressions themselves are valid.
    pub fn simplify_constants(&mut self) {
        let constants = self.constants.keys().cloned().collect::<Vec<_>>();

        for constant in constants.iter() {
            let expr =
                ConstantExpr::Var(Span::new(constant.span(), PathBuf::from(constant.clone())));
            match self.const_eval(&expr) {
                Ok(value) => {
                    self.constants.get_mut(constant).unwrap().value = value;
                },
                Err(err) => {
                    self.errors.push(err);
                },
            }
        }
    }

    fn const_eval(&mut self, value: &ConstantExpr) -> Result<ConstantExpr, SemanticAnalysisError> {
        /// Represents the type of a continuation to apply during evaluation
        enum Cont {
            /// We have reached an anonymous expression to evaluate
            Eval(ConstantExpr),
            /// We have finished evaluating the operands of a constant op, and must now apply the
            /// operation to them, pushing the result on the operand stack.
            Apply(Span<ConstantOp>),
            /// We have finished evaluating a reference to another constant and are returning
            /// its value on the operand stack
            Return(Ident),
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
                        return Err(SemanticAnalysisError::ConstEvalCycle {
                            start: evaluating[0].span(),
                            detected: path.span(),
                        });
                    }
                    if let Some(name) = path.as_ident() {
                        let name = name.with_span(path.span());
                        evaluating.push(path.clone());
                        continuations.push(Cont::Return(name.clone()));
                        continuations.push(Cont::Eval(self.get_constant(&name)?.clone()));
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
                                ConstantOp::Add => lhs + rhs,
                                ConstantOp::Sub => lhs - rhs,
                                ConstantOp::Mul => lhs * rhs,
                                ConstantOp::Div | ConstantOp::IntDiv => lhs / rhs,
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
                            return Err(SemanticAnalysisError::InvalidConstExprOperand {
                                span,
                                operand: rhs.span(),
                            });
                        },
                        (lhs, _) => {
                            return Err(SemanticAnalysisError::InvalidConstExprOperand {
                                span,
                                operand: lhs.span(),
                            });
                        },
                    }
                },
                Cont::Return(from) => {
                    debug_assert!(
                        !stack.is_empty(),
                        "returning from evaluating a constant reference is expected to produce at least one output"
                    );
                    evaluating.pop();

                    // Rewrite the expression of the constant we just evaluated, if doing so would
                    // simplify it.
                    let original = &mut self.constants.get_mut(&from).unwrap().value;
                    let should_simplify = match original {
                        ConstantExpr::Hash(..)
                        | ConstantExpr::Int(_)
                        | ConstantExpr::String(_)
                        | ConstantExpr::Word(_) => false,
                        ConstantExpr::Var(_) | ConstantExpr::BinaryOp { .. } => true,
                    };
                    if should_simplify {
                        *original = stack.last().unwrap().clone();
                    }
                },
            }
        }

        // When we reach here, we should have exactly one expression on the operand stack
        assert_eq!(stack.len(), 1, "expected constant evaluation to produce exactly one output");
        // SAFETY: The above assertion guarantees that the stack has an element, and that `pop` will
        // always succeed, thus the safety requirements of `unwrap_unchecked` are upheld
        Ok(unsafe { stack.pop().unwrap_unchecked() })
    }

    /// Get the constant value bound to `name`
    ///
    /// Returns `Err` if the symbol is undefined
    pub fn get_constant(&self, name: &Ident) -> Result<&ConstantExpr, SemanticAnalysisError> {
        let span = name.span();
        if let Some(expr) = self.constants.get(name) {
            Ok(&expr.value)
        } else {
            Err(SemanticAnalysisError::SymbolUndefined { span, symbol: name.clone() })
        }
    }

    /// Get the error message bound to `name`
    ///
    /// Returns `Err` if the symbol is undefined
    pub fn get_error(&self, name: &Ident) -> Result<Arc<str>, SemanticAnalysisError> {
        let span = name.span();
        if let Some(expr) = self.constants.get(name) {
            Ok(expr.value.expect_string())
        } else {
            Err(SemanticAnalysisError::SymbolUndefined { span, symbol: name.clone() })
        }
    }

    pub fn error(&mut self, diagnostic: SemanticAnalysisError) {
        self.errors.push(diagnostic);
    }

    pub fn has_errors(&self) -> bool {
        if self.warnings_as_errors() {
            return !self.errors.is_empty();
        }
        self.errors
            .iter()
            .any(|err| matches!(err.severity().unwrap_or(Severity::Error), Severity::Error))
    }

    pub fn has_failed(&mut self) -> Result<(), SyntaxError> {
        if self.has_errors() {
            Err(SyntaxError {
                source_file: self.source_file.clone(),
                errors: core::mem::take(&mut self.errors),
            })
        } else {
            Ok(())
        }
    }

    pub fn into_result(self) -> Result<(), SyntaxError> {
        if self.has_errors() {
            Err(SyntaxError {
                source_file: self.source_file.clone(),
                errors: self.errors,
            })
        } else {
            self.emit_warnings();
            Ok(())
        }
    }

    #[cfg(feature = "std")]
    fn emit_warnings(self) {
        use crate::diagnostics::Report;

        if !self.errors.is_empty() {
            // Emit warnings to stderr
            let warning = Report::from(super::errors::SyntaxWarning {
                source_file: self.source_file,
                errors: self.errors,
            });
            std::eprintln!("{warning}");
        }
    }

    #[cfg(not(feature = "std"))]
    fn emit_warnings(self) {}
}
