use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

use miden_debug_types::{SourceFile, Span, Spanned};
use miden_utils_diagnostics::{Diagnostic, Severity};

use super::{SemanticAnalysisError, SyntaxError};
use crate::{Felt, ast::*};

/// This maintains the state for semantic analysis of a single [Module].
pub struct AnalysisContext {
    /// A map of constants to the value of that constant
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
    pub fn define_constant(&mut self, mut constant: Constant) -> Result<(), SyntaxError> {
        // Handle symbol conflicts before eval to make sure we can catch self-referential
        // expressions.
        if let Some(value) = self.constants.get(&constant.name) {
            self.errors.push(SemanticAnalysisError::SymbolConflict {
                span: constant.span(),
                prev_span: value.span(),
            });
            return Ok(());
        }
        match self.const_eval(&constant.value) {
            Ok(value) => {
                constant.value = value;
                self.constants.insert(constant.name.clone(), constant);
                Ok(())
            },
            Err(err) => {
                self.errors.push(err);
                let errors = core::mem::take(&mut self.errors);
                Err(SyntaxError {
                    source_file: self.source_file.clone(),
                    errors,
                })
            },
        }
    }

    fn const_eval(&self, value: &ConstantExpr) -> Result<ConstantExpr, SemanticAnalysisError> {
        match value {
            ConstantExpr::Literal(_) | ConstantExpr::String(_) => Ok((*value).clone()),
            ConstantExpr::Word(_) => Ok((*value).clone()),
            ConstantExpr::Var(name) => self.get_constant(name).cloned(),
            ConstantExpr::BinaryOp { op, lhs, rhs, .. } => {
                let rhs = self.const_eval(rhs)?.expect_literal();
                let lhs = self.const_eval(lhs)?.expect_literal();
                let felt = match op {
                    ConstantOp::Add => lhs + rhs,
                    ConstantOp::Sub => lhs - rhs,
                    ConstantOp::Mul => lhs * rhs,
                    ConstantOp::Div => lhs / rhs,
                    ConstantOp::IntDiv => Felt::new(lhs.as_int() / rhs.as_int()),
                };
                Ok(ConstantExpr::Literal(Span::unknown(felt)))
            },
        }
    }

    /// Get the constant value bound to `name`
    ///
    /// Returns `Err` if the symbol is undefined
    pub fn get_constant(&self, name: &Ident) -> Result<&ConstantExpr, SemanticAnalysisError> {
        let span = name.span();
        if let Some(expr) = self.constants.get(name) {
            Ok(&expr.value)
        } else {
            Err(SemanticAnalysisError::SymbolUndefined { span })
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
            Err(SemanticAnalysisError::SymbolUndefined { span })
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
