use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

use miden_debug_types::{SourceFile, SourceManager, SourceSpan, Span, Spanned};
use miden_utils_diagnostics::{Diagnostic, Severity};

use super::{SemanticAnalysisError, SyntaxError};
use crate::ast::{
    constants::{ConstEvalError, eval::CachedConstantValue},
    *,
};

/// This maintains the state for semantic analysis of a single [Module].
pub struct AnalysisContext {
    constants: BTreeMap<Ident, Constant>,
    cached_constant_values: BTreeMap<Ident, ConstantValue>,
    imported: BTreeSet<Ident>,
    procedures: BTreeSet<ProcedureName>,
    errors: Vec<SemanticAnalysisError>,
    source_file: Arc<SourceFile>,
    source_manager: Arc<dyn SourceManager>,
    warnings_as_errors: bool,
}

impl constants::ConstEnvironment for AnalysisContext {
    type Error = SemanticAnalysisError;

    fn get_source_file_for(&self, span: SourceSpan) -> Option<Arc<SourceFile>> {
        if span.source_id() == self.source_file.id() {
            Some(self.source_file.clone())
        } else {
            None
        }
    }
    #[inline]
    fn get(&mut self, name: &Ident) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
        if let Some(value) = self.cached_constant_values.get(name) {
            Ok(Some(CachedConstantValue::Hit(value)))
        } else if let Some(constant) = self.constants.get(name) {
            Ok(Some(CachedConstantValue::Miss(&constant.value)))
        } else if self.imported.contains(name) {
            // We don't have the definition available yet
            Ok(None)
        } else {
            Err(ConstEvalError::UndefinedSymbol {
                symbol: name.clone(),
                source_file: self.get_source_file_for(name.span()),
            }
            .into())
        }
    }
    #[inline(always)]
    fn get_by_path(
        &mut self,
        path: Span<&Path>,
    ) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
        if let Some(name) = path.as_ident() {
            self.get(&name)
        } else {
            Ok(None)
        }
    }

    #[inline]
    fn on_eval_completed(&mut self, name: Span<&Path>, value: &ConstantExpr) {
        let Some(name) = name.as_ident() else {
            return;
        };
        if let Some(value) = value.as_value() {
            self.cached_constant_values.insert(name, value);
        } else {
            self.cached_constant_values.remove(&name);
        }
    }
}

impl AnalysisContext {
    pub fn new(source_file: Arc<SourceFile>, source_manager: Arc<dyn SourceManager>) -> Self {
        Self {
            constants: Default::default(),
            cached_constant_values: Default::default(),
            imported: Default::default(),
            procedures: Default::default(),
            errors: Default::default(),
            source_file,
            source_manager,
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

    #[inline(always)]
    pub fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.source_manager.clone()
    }

    pub fn register_procedure_name(&mut self, name: ProcedureName) {
        self.procedures.insert(name);
    }

    pub fn register_imported_name(&mut self, name: Ident) {
        self.imported.insert(name);
    }

    /// Define a new constant `constant`
    ///
    /// Returns `Err` if a constant with the same name is already defined
    pub fn define_constant(&mut self, module: &mut Module, constant: Constant) {
        if let Err(err) = module.define_constant(constant.clone()) {
            self.errors.push(err);
        } else {
            let name = constant.name.clone();
            self.constants.insert(name, constant);
        }
    }

    /// Register a constant for semantic analysis without defining it in the module.
    ///
    /// This is used for enum variants so we can fold discriminants without
    /// attempting to define the same constant twice.
    pub fn register_constant(&mut self, constant: Constant) {
        let name = constant.name.clone();
        self.cached_constant_values.remove(&name);
        if let Some(prev) = self.constants.get(&name) {
            self.errors.push(SemanticAnalysisError::SymbolConflict {
                span: constant.span,
                prev_span: prev.span,
            });
        } else {
            self.constants.insert(name, constant);
        }
    }

    /// Rewrite all constant declarations by performing const evaluation of their expressions.
    ///
    /// This also has the effect of validating that the constant expressions themselves are valid.
    pub fn simplify_constants(&mut self) {
        self.cached_constant_values.clear();
        let constants = self.constants.keys().cloned().collect::<Vec<_>>();

        for constant in constants.iter() {
            let expr = ConstantExpr::Var(Span::new(
                constant.span(),
                PathBuf::from(constant.clone()).into(),
            ));
            match constants::eval::expr(&expr, self) {
                Ok(value) => {
                    if let Some(cached) = value.as_value() {
                        self.cached_constant_values.insert(constant.clone(), cached);
                    } else {
                        self.cached_constant_values.remove(constant);
                    }
                    self.constants.get_mut(constant).unwrap().value = value;
                },
                Err(err) => {
                    self.cached_constant_values.remove(constant);
                    self.errors.push(err);
                },
            }
        }
    }

    /// Get the constant value bound to `name`
    ///
    /// Returns `Err` if the symbol is undefined
    pub fn get_constant(&self, name: &Ident) -> Result<&ConstantExpr, SemanticAnalysisError> {
        if let Some(expr) = self.constants.get(name) {
            Ok(&expr.value)
        } else {
            Err(SemanticAnalysisError::SymbolResolutionError(Box::new(
                SymbolResolutionError::undefined(name.span(), &self.source_manager),
            )))
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

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, string::String, sync::Arc};
    use core::cell::Cell;

    use super::AnalysisContext;
    use crate::{
        Path, PathBuf,
        ast::{
            Constant, ConstantExpr, ConstantOp, ConstantValue, Ident, Visibility,
            constants::{self, eval::CachedConstantValue},
        },
        debuginfo::{
            DefaultSourceManager, SourceContent, SourceLanguage, SourceManager, SourceSpan, Span,
            Uri,
        },
        parser::IntValue,
    };

    struct CountingEnv<'a> {
        inner: &'a mut AnalysisContext,
        hits: Cell<usize>,
        misses: Cell<usize>,
    }

    impl<'a> CountingEnv<'a> {
        fn new(inner: &'a mut AnalysisContext) -> Self {
            Self {
                inner,
                hits: Cell::new(0),
                misses: Cell::new(0),
            }
        }

        fn hits(&self) -> usize {
            self.hits.get()
        }

        fn misses(&self) -> usize {
            self.misses.get()
        }
    }

    impl constants::ConstEnvironment for CountingEnv<'_> {
        type Error = super::SemanticAnalysisError;

        fn get_source_file_for(
            &self,
            span: SourceSpan,
        ) -> Option<Arc<crate::debuginfo::SourceFile>> {
            <AnalysisContext as constants::ConstEnvironment>::get_source_file_for(self.inner, span)
        }

        fn get(&mut self, name: &Ident) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
            let value = <AnalysisContext as constants::ConstEnvironment>::get(self.inner, name)?;
            if let Some(ref value) = value {
                match value {
                    CachedConstantValue::Hit(_) => self.hits.set(self.hits.get() + 1),
                    CachedConstantValue::Miss(_) => self.misses.set(self.misses.get() + 1),
                }
            }
            Ok(value)
        }

        fn get_by_path(
            &mut self,
            path: Span<&Path>,
        ) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
            if let Some(name) = path.as_ident() {
                self.get(&name)
            } else {
                <AnalysisContext as constants::ConstEnvironment>::get_by_path(self.inner, path)
            }
        }

        fn on_eval_completed(&mut self, name: Span<&Path>, value: &ConstantExpr) {
            <AnalysisContext as constants::ConstEnvironment>::on_eval_completed(
                self.inner, name, value,
            );
        }
    }

    fn make_name(i: usize) -> Ident {
        format!("C{i:05}").parse().expect("generated constant name must be valid")
    }

    fn make_ref(name: Ident) -> ConstantExpr {
        let path = Arc::<Path>::from(PathBuf::from(name));
        ConstantExpr::Var(Span::new(SourceSpan::default(), path))
    }

    fn make_shared_subexpression_chain(context: &mut AnalysisContext, depth: usize) {
        for i in 0..depth {
            let name = make_name(i);
            let next = make_name(i + 1);
            context.register_constant(Constant::new(
                SourceSpan::default(),
                Visibility::Public,
                name,
                ConstantExpr::BinaryOp {
                    span: SourceSpan::default(),
                    op: ConstantOp::Add,
                    lhs: Box::new(make_ref(next.clone())),
                    rhs: Box::new(make_ref(next)),
                },
            ));
        }

        context.register_constant(Constant::new(
            SourceSpan::default(),
            Visibility::Public,
            make_name(depth),
            ConstantExpr::Int(Span::new(SourceSpan::default(), IntValue::from(1_u32))),
        ));
    }

    #[test]
    fn semantic_const_eval_memoizes_shared_subexpressions() {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let uri =
            Uri::from(String::from("mem://const-eval-shared-subexpressions").into_boxed_str());
        let content = SourceContent::new(
            SourceLanguage::Masm,
            uri.clone(),
            String::from("begin\n    nop\nend\n").into_boxed_str(),
        );
        let source_file = source_manager.load_from_raw_parts(uri, content);
        let mut context = AnalysisContext::new(source_file, source_manager);

        // Each Ci references C(i+1) twice, so without memoization the number of misses would
        // grow exponentially with depth.
        let depth = 24;
        make_shared_subexpression_chain(&mut context, depth);

        let root_name = make_name(0);
        let mut env = CountingEnv::new(&mut context);
        let root = make_ref(root_name);
        let result = constants::eval::expr(&root, &mut env)
            .expect("shared-subexpression constant graph should evaluate");

        assert!(
            matches!(result.as_value(), Some(ConstantValue::Int(_))),
            "evaluation should produce a concrete integer constant value"
        );
        assert_eq!(env.misses(), depth + 1, "each constant in the chain should miss at most once");
        assert_eq!(
            env.hits(),
            depth,
            "the second reference to each dependency should be served from cache"
        );
    }
}
