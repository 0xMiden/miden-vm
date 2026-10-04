use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::{String, ToString},
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
    symbol_resolver: LocalSymbolResolver,
    constants: BTreeMap<Ident, Constant>,
    cached_constant_values: BTreeMap<Ident, ConstantValue>,
    used_constants: BTreeSet<Ident>,
    constant_deps: BTreeMap<Ident, BTreeSet<Ident>>,
    constant_import_refs: BTreeMap<Ident, BTreeSet<String>>,
    qualified_type_refs: BTreeSet<PathBuf>,
    evaluating_constants: Vec<Ident>,
    evaluating_constant: Option<Ident>,
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
            if let Some(value) = self.cached_constant_values.get(name) {
                return Ok(Some(CachedConstantValue::Hit(value)));
            }
            Ok(Some(CachedConstantValue::Miss(
                &self.constants.get(name).expect("constant should exist").value,
            )))
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
        if let Some(name) = self.local_constant_name(path) {
            self.get(&name)
        } else {
            Ok(None)
        }
    }

    #[inline]
    fn on_eval_start(&mut self, path: Span<&Path>) {
        if let Some(name) = self.local_constant_name(path)
            && self.constants.contains_key(&name)
        {
            self.evaluating_constants.push(name);
        }
    }

    #[inline]
    fn on_eval_completed(&mut self, name: Span<&Path>, value: &ConstantExpr) {
        let Some(name) = self.local_constant_name(name) else {
            return;
        };
        if self.constants.contains_key(&name) {
            let current = self.evaluating_constants.pop();
            debug_assert_eq!(current.as_ref(), Some(&name));
        }
        if let Some(value) = value.as_value() {
            self.cached_constant_values.insert(name, value);
        } else {
            self.cached_constant_values.remove(&name);
        }
    }
}

impl AnalysisContext {
    pub fn new(
        module_path: impl AsRef<Path>,
        source_file: Arc<SourceFile>,
        source_manager: Arc<dyn SourceManager>,
    ) -> Self {
        let module_path = module_path.as_ref().to_relative().to_path_buf();
        let module = Module::new(ModuleKind::Library, &module_path);
        let symbol_resolver = LocalSymbolResolver::new(&module, source_manager.clone())
            .expect("an empty module has a valid symbol table");
        Self {
            module_path,
            symbol_resolver,
            constants: Default::default(),
            cached_constant_values: Default::default(),
            used_constants: Default::default(),
            constant_deps: Default::default(),
            constant_import_refs: Default::default(),
            qualified_type_refs: Default::default(),
            evaluating_constants: Default::default(),
            evaluating_constant: None,
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

    pub fn set_module(&mut self, module: &Module) -> Result<(), SemanticAnalysisError> {
        let resolver = LocalSymbolResolver::new(module, self.source_manager.clone())
            .map_err(|err| SemanticAnalysisError::SymbolResolutionError(Box::new(err)))?;
        self.module_path = module.path().to_relative().to_path_buf();
        self.symbol_resolver = resolver;
        Ok(())
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

    fn record_constant_ref(&mut self, name: &Ident) {
        let parent = self.evaluating_constants.last().or(self.evaluating_constant.as_ref());
        if parent == Some(name) {
            return;
        }
        if let Some(parent) = parent {
            self.constant_deps.entry(parent.clone()).or_default().insert(name.clone());
        } else {
            self.used_constants.insert(name.clone());
        }
    }

    fn local_constant_name(&self, path: Span<&Path>) -> Option<Ident> {
        path.as_ident().or_else(|| self.local_constant_name_for_path(path))
    }

    fn local_constant_name_for_path(&self, path: Span<&Path>) -> Option<Ident> {
        let name = self.local_item_name_for_path(path)?;
        self.constants.contains_key(&name).then_some(name)
    }

    pub fn is_constant_used(&self, constant: &Constant) -> bool {
        constant.visibility.is_public() || self.used_constants.contains(&constant.name)
    }

    pub fn mark_constant_used(&mut self, name: &Ident) {
        self.used_constants.insert(name.clone());
    }

    pub fn record_constant_import_ref(&mut self, constant: &Ident, import: String) {
        self.constant_import_refs.entry(constant.clone()).or_default().insert(import);
    }

    pub fn record_qualified_type_ref(&mut self, path: &Path) {
        self.qualified_type_refs.insert(path.to_path_buf());
    }

    fn local_item_name_for_path(&self, path: Span<&Path>) -> Option<Ident> {
        let (name, parent) = path.split_last()?;
        if parent == Path::new("self") {
            return Ident::new_with_span(path.span(), name).ok();
        }
        // Unresolved foreign references are checked by the linker when all modules are available.
        let SymbolResolution::External(resolved) = self.symbol_resolver.resolve_path(path).ok()?
        else {
            return None;
        };
        let (name, parent) = resolved.split_last()?;
        if parent.to_relative() == self.module_path.as_path() {
            Ident::new_with_span(path.span(), name).ok()
        } else {
            None
        }
    }

    pub fn resolve_constant_usage(&mut self, module: &Module, used_imports: &mut BTreeSet<String>) {
        let mut local_imports = BTreeMap::<String, Ident>::new();
        let mut pending_imports = VecDeque::from_iter(used_imports.iter().cloned());
        for import in module.imports() {
            let Import::Item(import) = import else {
                continue;
            };
            let path = import.module_path().into_inner();
            let is_local =
                path == Path::new("self") || path.to_relative() == self.module_path.as_path();
            if is_local {
                let local_name = import.local_name().as_str().to_string();
                local_imports.insert(local_name.clone(), import.source_name().clone());
                if import.is_used() && used_imports.insert(local_name.clone()) {
                    pending_imports.push_back(local_name);
                }
            }
        }

        for path in &self.qualified_type_refs {
            let Some(name) =
                self.local_item_name_for_path(Span::new(SourceSpan::UNKNOWN, path.as_path()))
            else {
                continue;
            };
            if used_imports.insert(name.as_str().to_string()) {
                pending_imports.push_back(name.as_str().to_string());
            }
        }

        let mut pending_constants = VecDeque::from_iter(self.used_constants.iter().cloned());
        for (name, constant) in &self.constants {
            if constant.visibility.is_public() && self.used_constants.insert(name.clone()) {
                pending_constants.push_back(name.clone());
            }
        }
        let mut enum_variants = BTreeMap::<String, Vec<Ident>>::new();
        for item in module.items() {
            let Item::Type(TypeDecl::Enum(ty)) = item else {
                continue;
            };
            enum_variants.insert(
                ty.name().as_str().to_string(),
                ty.variants().iter().map(|variant| variant.name.clone()).collect(),
            );
            if ty.visibility().is_public() || used_imports.contains(ty.name().as_str()) {
                for variant in ty.variants() {
                    if self.used_constants.insert(variant.name.clone()) {
                        pending_constants.push_back(variant.name.clone());
                    }
                }
            }
        }
        while !pending_constants.is_empty() || !pending_imports.is_empty() {
            if let Some(name) = pending_constants.pop_front() {
                if let Some(deps) = self.constant_deps.get(&name) {
                    for dep in deps {
                        if self.used_constants.insert(dep.clone()) {
                            pending_constants.push_back(dep.clone());
                        }
                    }
                }
                if let Some(imports) = self.constant_import_refs.get(&name) {
                    for import in imports {
                        if used_imports.insert(import.clone()) {
                            pending_imports.push_back(import.clone());
                        }
                    }
                }
            } else if let Some(alias) = pending_imports.pop_front()
                && let Some(source) = local_imports.get(&alias)
            {
                if self.constants.contains_key(source) {
                    if self.used_constants.insert(source.clone()) {
                        pending_constants.push_back(source.clone());
                    }
                } else if let Some(variants) = enum_variants.get(source.as_str()) {
                    for variant in variants {
                        if self.used_constants.insert(variant.clone()) {
                            pending_constants.push_back(variant.clone());
                        }
                    }
                } else if local_imports.contains_key(source.as_str())
                    && used_imports.insert(source.as_str().to_string())
                {
                    pending_imports.push_back(source.as_str().to_string());
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

    /// Evaluate constants for validation and cache their values without changing their expressions.
    pub fn evaluate_constants(&mut self) {
        self.cached_constant_values.clear();
        let constants = self.constants.keys().cloned().collect::<Vec<_>>();

        for constant in constants.iter() {
            self.evaluating_constant = Some(constant.clone());
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
                },
                Err(err) => {
                    self.cached_constant_values.remove(constant);
                    self.errors.push(err);
                },
            }
            self.evaluating_constant = None;
        }
    }

    /// Get the evaluated constant expression bound to `name`.
    ///
    /// Returns `Err` if the symbol is undefined
    pub fn get_evaluated_constant(
        &self,
        name: &Ident,
    ) -> Result<ConstantExpr, SemanticAnalysisError> {
        if let Some(value) = self.cached_constant_values.get(name) {
            Ok(value.clone().into())
        } else if let Some(constant) = self.constants.get(name) {
            Ok(constant.value.clone())
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
            if let Some(name) = self.inner.local_constant_name(path) {
                self.get(&name)
            } else {
                <AnalysisContext as constants::ConstEnvironment>::get_by_path(self.inner, path)
            }
        }

        fn on_eval_start(&mut self, path: Span<&Path>) {
            <AnalysisContext as constants::ConstEnvironment>::on_eval_start(self.inner, path);
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

    fn make_ref_at(name: Ident, module: &Path) -> ConstantExpr {
        let path = Arc::<Path>::from(module.join(Path::new(name.as_str())));
        ConstantExpr::Var(Span::new(SourceSpan::default(), path))
    }

    fn make_shared_subexpression_chain(
        context: &mut AnalysisContext,
        depth: usize,
        qualifier: Option<&Path>,
    ) {
        for i in 0..depth {
            let name = make_name(i);
            let next = make_name(i + 1);
            let make_next = || match qualifier {
                Some(module) => make_ref_at(next.clone(), module),
                None => make_ref(next.clone()),
            };
            context.register_constant(Constant::new(
                SourceSpan::default(),
                Visibility::Public,
                name,
                ConstantExpr::BinaryOp {
                    span: SourceSpan::default(),
                    op: ConstantOp::Add,
                    lhs: Box::new(make_next()),
                    rhs: Box::new(make_next()),
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

    fn assert_shared_subexpression_memoization(qualifier: Option<&Path>) {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let uri =
            Uri::from(String::from("mem://const-eval-shared-subexpressions").into_boxed_str());
        let content = SourceContent::new(
            SourceLanguage::Masm,
            uri.clone(),
            String::from("begin\n    nop\nend\n").into_boxed_str(),
        );
        let source_file = source_manager.load_from_raw_parts(uri, content);
        let mut context = AnalysisContext::new(Path::new("test::lib"), source_file, source_manager);

        // Each Ci references C(i+1) twice, so without memoization the number of misses would
        // grow exponentially with depth.
        let depth = 24;
        make_shared_subexpression_chain(&mut context, depth, qualifier);

        let root_name = make_name(0);
        let mut env = CountingEnv::new(&mut context);
        let root = match qualifier {
            Some(module) => make_ref_at(root_name, module),
            None => make_ref(root_name),
        };
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

    #[test]
    fn semantic_const_eval_memoizes_shared_subexpressions() {
        assert_shared_subexpression_memoization(None);
    }

    #[test]
    fn semantic_const_eval_memoizes_self_qualified_subexpressions() {
        assert_shared_subexpression_memoization(Some(Path::new("self")));
    }

    #[test]
    fn semantic_const_eval_memoizes_absolute_qualified_subexpressions() {
        assert_shared_subexpression_memoization(Some(Path::new("::test::lib")));
    }
}
