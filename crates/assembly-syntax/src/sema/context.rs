use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
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
    module_path: PathBuf,
    constants: BTreeMap<Ident, Constant>,
    used_constants: BTreeSet<Ident>,
    /// Edges from a constant to the constants it references.
    /// Used to compute transitive usage from real roots.
    constant_deps: BTreeMap<Ident, BTreeSet<Ident>>,
    /// Edges from a constant to the imports it references.
    /// Used to avoid marking imports as used when only dead constants reference them.
    constant_import_refs: BTreeMap<Ident, BTreeSet<alloc::string::String>>,
    /// When set, references are recorded as constant-to-constant edges
    /// rather than marking the target as directly used.
    simplifying_constant: Option<Ident>,
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
        if self.constants.contains_key(name) {
            self.record_constant_ref(name);
            let constant = self.constants.get(name).expect("constant should exist");
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
        } else if let Some(name) = self.local_constant_name_for_path(path) {
            self.get(&name)
        } else {
            Ok(None)
        }
    }
}

impl AnalysisContext {
    pub fn new(
        module_path: impl AsRef<Path>,
        source_file: Arc<SourceFile>,
        source_manager: Arc<dyn SourceManager>,
    ) -> Self {
        Self {
            module_path: module_path.as_ref().to_relative().to_path_buf(),
            constants: Default::default(),
            used_constants: Default::default(),
            constant_deps: Default::default(),
            constant_import_refs: Default::default(),
            simplifying_constant: None,
            imported: Default::default(),
            procedures: Default::default(),
            errors: Default::default(),
            source_file,
            source_manager,
            warnings_as_errors: false,
        }
    }

    fn record_constant_ref(&mut self, name: &Ident) {
        let is_self_ref = self.simplifying_constant.as_ref() == Some(name);
        if is_self_ref {
            return;
        }

        if let Some(ref parent) = self.simplifying_constant {
            self.constant_deps.entry(parent.clone()).or_default().insert(name.clone());
        } else {
            self.used_constants.insert(name.clone());
        }
    }

    fn local_constant_name_for_path(&self, path: Span<&Path>) -> Option<Ident> {
        let (name, module_path) = path.split_last()?;
        if module_path.to_relative() != self.module_path.as_path() {
            return None;
        }

        let name = Ident::new_with_span(path.span(), name).ok()?;
        self.constants.contains_key(&name).then_some(name)
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

    /// Returns true if the constant has been referenced by another constant or
    /// by a procedure body, or is publicly visible.
    pub fn is_constant_used(&self, constant: &Constant) -> bool {
        constant.visibility.is_public() || self.used_constants.contains(&constant.name)
    }

    /// Mark a constant as used.
    ///
    /// This is used for constants created as a side effect of other declarations
    /// (e.g. advice map entries) that should not trigger unused constant warnings.
    pub fn mark_constant_used(&mut self, name: &Ident) {
        self.used_constants.insert(name.clone());
    }

    /// Record that constant `constant_name` references import `import_name`.
    ///
    /// These edges are used to defer import-usage bookkeeping until after
    /// constant liveness has been resolved, so that imports reached only from
    /// dead constants are correctly reported as unused.
    pub fn record_constant_import_ref(
        &mut self,
        constant_name: &Ident,
        import_name: alloc::string::String,
    ) {
        self.constant_import_refs
            .entry(constant_name.clone())
            .or_default()
            .insert(import_name);
    }

    /// Increment `alias.uses` only for imports that are referenced by live
    /// constants. Must be called after `resolve_constant_usage`.
    pub fn apply_live_constant_import_refs(&self, module: &mut Module) {
        for (constant_name, import_names) in &self.constant_import_refs {
            if !self.used_constants.contains(constant_name) {
                continue;
            }
            for import_name in import_names {
                if let Some(alias) =
                    module.aliases_mut().find(|a| a.name().as_str() == import_name.as_str())
                {
                    alias.uses += 1;
                }
            }
        }
    }

    /// Propagate usage from real roots through constant-to-constant edges.
    ///
    /// A constant is considered truly used if it is public, directly referenced
    /// by a procedure body, or transitively referenced by such a constant.
    /// This must be called before checking for unused constants.
    pub fn resolve_constant_usage(&mut self) {
        let mut worklist: VecDeque<Ident> = self.used_constants.iter().cloned().collect();
        for (name, constant) in &self.constants {
            if constant.visibility.is_public() && self.used_constants.insert(name.clone()) {
                worklist.push_back(name.clone());
            }
        }
        while let Some(name) = worklist.pop_front() {
            if let Some(deps) = self.constant_deps.get(&name) {
                for dep in deps {
                    if self.used_constants.insert(dep.clone()) {
                        worklist.push_back(dep.clone());
                    }
                }
            }
        }
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
        let constants = self.constants.keys().cloned().collect::<Vec<_>>();

        for constant in constants.iter() {
            self.simplifying_constant = Some(constant.clone());
            let expr = ConstantExpr::Var(Span::new(
                constant.span(),
                PathBuf::from(constant.clone()).into(),
            ));
            match crate::ast::constants::eval::expr(&expr, self) {
                Ok(value) => {
                    self.constants.get_mut(constant).unwrap().value = value;
                },
                Err(err) => {
                    self.errors.push(err);
                },
            }
            self.simplifying_constant = None;
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
