mod context;
mod errors;
mod passes;
#[cfg(test)]
mod tests;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::ToString,
    sync::Arc,
    vec::Vec,
};

use miden_core::{Word, crypto::hash::Poseidon2};
use miden_debug_types::{SourceFile, SourceManager, Span, Spanned};
use smallvec::SmallVec;

use self::passes::{LocalInvokeTarget, VerifyInvokeTargets};
pub use self::{
    context::AnalysisContext,
    errors::{LimitKind, SemanticAnalysisError, SyntaxError},
    passes::{ConstEvalVisitor, VerifyRepeatCounts},
};
use crate::{ast::*, parser::WordValue};

/// Constructs and validates a [Module], given the forms constituting the module body.
///
/// As part of this process, the following is also done:
///
/// * Documentation comments are attached to items they decorate
/// * Import table is constructed
/// * Symbol resolution is performed:
///   * Constants referenced by name are replaced with the value of that constant.
///   * Calls to imported procedures are resolved concretely
/// * Semantic analysis is performed on the module to validate it
pub fn analyze(
    source: Arc<SourceFile>,
    kind: Option<ModuleKind>,
    path: Option<&Path>,
    forms: Vec<Form>,
    warnings_as_errors: bool,
    source_manager: Arc<dyn SourceManager>,
) -> Result<Box<Module>, SyntaxError> {
    log::debug!(target: "sema", "starting semantic analysis for '{}' (kind = {kind:?})", path.map(Path::as_str).unwrap_or("None"));
    let mut analyzer = AnalysisContext::new(source.clone(), source_manager);
    analyzer.set_warnings_as_errors(warnings_as_errors);

    let expected_path = match path {
        Some(path) => Some(normalize_namespace_path(path).map_err(|err| SyntaxError {
            source_file: source.clone(),
            errors: vec![SemanticAnalysisError::InvalidNamespacePath {
                path: path.to_path_buf().into(),
                err,
            }],
        })?),
        None => None,
    };
    let module_path = expected_path.as_deref().unwrap_or(Path::new(""));
    let mut module = Box::new(
        Module::new(kind.unwrap_or_default(), module_path).with_span(source.source_span()),
    );

    let mut forms = VecDeque::from(forms);
    let mut enums = SmallVec::<[EnumType; 1]>::new_const();
    let mut docs = None;
    let mut module_docs = None;
    let mut has_doc_anchor = false;
    let mut namespace_allowed = true;
    let mut actual_kind = None;
    while let Some(form) = forms.pop_front() {
        if !matches!(form, Form::ModuleDoc(_) | Form::Doc(_)) {
            has_doc_anchor = true;
        }

        match form {
            Form::ModuleDoc(docstring) => {
                assert!(docs.is_none());
                module_docs = Some(docstring.span());
                module.set_docs(Some(docstring));
            },
            Form::Doc(docstring) => {
                if let Some(unused) = docs.replace(docstring) {
                    analyzer.error(SemanticAnalysisError::UnusedDocstring { span: unused.span() });
                }
                namespace_allowed = false;
            },
            Form::Namespace(ns) if !namespace_allowed => {
                analyzer.error(SemanticAnalysisError::MisplacedNamespaceDeclaration {
                    span: ns.span(),
                });
            },
            Form::Namespace(ns) => {
                if let Some(unused) = docs.take() {
                    analyzer.error(SemanticAnalysisError::UnusedDocstring { span: unused.span() });
                }
                let namespace =
                    normalize_namespace_path(ns.inner()).map_err(|err| SyntaxError {
                        source_file: source.clone(),
                        errors: vec![SemanticAnalysisError::InvalidNamespacePath {
                            path: ns.inner().clone(),
                            err,
                        }],
                    })?;
                if let Some(expected_path) = expected_path.as_deref()
                    && namespace.as_ref() != expected_path
                {
                    analyzer.error(SemanticAnalysisError::NamespaceConflict {
                        expected: expected_path.to_path_buf().into(),
                        actual: namespace.clone(),
                        span: ns.span(),
                    });
                }
                module.set_declared_namespace(Span::new(ns.span(), namespace));
            },
            Form::ExternPackage(package_id) => {
                namespace_allowed = false;
                if let Err(err) = module.declare_extern_package(package_id) {
                    analyzer.error(err);
                }
            },
            Form::Submodule(SubmoduleDecl { visibility, name }) => {
                namespace_allowed = false;
                if let Err(err) = module.declare_submodule(name, visibility) {
                    analyzer.error(err);
                }
            },
            Form::Type(ty) => {
                namespace_allowed = false;
                if let Err(err) = module.define_type(ty.with_docs(docs.take())) {
                    analyzer.error(err);
                }
            },
            Form::Enum(ty) => {
                namespace_allowed = false;
                // Ensure the constants defined by the enum are made known to the analyzer
                for variant in ty.variants() {
                    let Variant { span, name, discriminant, .. } = variant;
                    analyzer.register_constant(Constant {
                        span: *span,
                        docs: None,
                        visibility: ty.visibility(),
                        name: name.clone(),
                        value: discriminant.clone(),
                    });
                }

                // Defer definition of the enum until we discover all constants
                enums.push(ty.with_docs(docs.take()));
            },
            Form::Constant(constant) => {
                namespace_allowed = false;
                analyzer.define_constant(&mut module, constant.with_docs(docs.take()));
            },
            Form::Alias(item) => {
                namespace_allowed = false;
                define_alias(item.with_docs(docs.take()), &mut module, &mut analyzer)?
            },
            Form::Procedure(export) => {
                namespace_allowed = false;
                define_procedure(export.with_docs(docs.take()), &mut module, &mut analyzer)?;
            },
            Form::Begin(body)
                if actual_kind.is_none_or(|kind| matches!(kind, ModuleKind::Executable)) =>
            {
                namespace_allowed = false;
                actual_kind = Some(ModuleKind::Executable);
                let docs = docs.take();
                let procedure =
                    Procedure::new(body.span(), Visibility::Public, ProcedureName::main(), 0, body)
                        .with_docs(docs);
                define_procedure(procedure, &mut module, &mut analyzer)?;
            },
            Form::Begin(body) => {
                namespace_allowed = false;
                docs.take();
                analyzer.error(SemanticAnalysisError::UnexpectedEntrypoint { span: body.span() });
            },
            Form::AdviceMapEntry(entry) => {
                namespace_allowed = false;
                add_advice_map_entry(&mut module, entry.with_docs(docs.take()), &mut analyzer);
            },
        }
    }

    if !has_doc_anchor && let Some(span) = module_docs.take() {
        analyzer.error(SemanticAnalysisError::TrailingDocstring { span });
    }

    if let Some(unused) = docs.take() {
        analyzer.error(SemanticAnalysisError::TrailingDocstring { span: unused.span() });
    }

    // Verify that we have a concrete module name
    if path.is_none() && module.namespace_decl.is_none() {
        analyzer.error(SemanticAnalysisError::MissingNamespace);
        // If we don't have a namespace, we shouldn't proceed any further
        return Err(analyzer.into_result().unwrap_err());
    }

    // By now we know the actual module kind, or can use the default library kind
    let actual_kind = actual_kind.or(kind).unwrap_or_default();
    module.set_kind(actual_kind);

    // Check all forms that have kind-specific restrictions now that the kind is concrete
    if !actual_kind.is_library() {
        for item in module.items() {
            match item {
                // The sole allowed export from an executable is the entrypoint procedure
                item if item.visibility().is_public()
                    && actual_kind == ModuleKind::Executable
                    && !matches!(item, Item::Procedure(p) if p.is_entrypoint()) =>
                {
                    analyzer.error(SemanticAnalysisError::UnexpectedExport { span: item.span() });
                },
                Item::Alias(alias)
                    if item.visibility().is_public() && actual_kind == ModuleKind::Kernel =>
                {
                    analyzer
                        .error(SemanticAnalysisError::ReexportFromKernel { span: alias.span() });
                },
                _ => (),
            }
        }
    }

    // Simplify all constant declarations
    analyzer.simplify_constants();
    for item in module.items_mut() {
        let Item::Constant(constant) = item else {
            continue;
        };
        constant.value = analyzer
            .get_constant(&constant.name)
            .expect("semantic analysis tracks all module constants")
            .clone();
    }

    // Define enums now that all constant declarations have been discovered
    for mut ty in enums {
        for variant in ty.variants_mut() {
            variant.discriminant = analyzer.get_constant(&variant.name).unwrap().clone();
        }

        if let Err(err) = module.define_enum(ty) {
            analyzer.error(err);
        }
    }

    if matches!(actual_kind, ModuleKind::Executable) && !module.has_entrypoint() {
        analyzer.error(SemanticAnalysisError::MissingEntrypoint);
    }

    analyzer.has_failed()?;

    // Run item checks
    visit_items(&mut module, &mut analyzer);

    // Check unused imports
    for import in module.aliases() {
        if !import.is_used() {
            analyzer.error(SemanticAnalysisError::UnusedImport { span: import.span() });
        }
    }

    analyzer.into_result().map(move |_| module)
}

/// Visit all of the items of the current analysis context, and apply various transformation and
/// analysis passes.
///
/// When this function returns, all local analysis is complete, and all that remains is construction
/// of a module graph and global program analysis to perform any remaining transformations.
fn visit_items(module: &mut Module, analyzer: &mut AnalysisContext) {
    let is_kernel = module.is_kernel();
    let locals = BTreeMap::from_iter(
        module
            .items()
            .iter()
            .map(|item| (item.name().as_str().to_string(), LocalInvokeTarget::from(item))),
    );
    let mut used_aliases = BTreeSet::default();
    let mut items = VecDeque::from(module.take_items());
    while let Some(item) = items.pop_front() {
        match item {
            Item::Procedure(mut procedure) => {
                // Rewrite visibility for exported kernel procedures
                if is_kernel && procedure.visibility().is_public() {
                    procedure.set_syscall(true);
                }

                // Evaluate all named immediates to their concrete values
                log::debug!(target: "const-eval", "visiting procedure {}", procedure.name());
                {
                    let mut visitor = ConstEvalVisitor::new(analyzer);
                    let _ = visitor.visit_mut_procedure(&mut procedure);
                    if let Err(errs) = visitor.into_result() {
                        for err in errs {
                            log::error!(target: "const-eval", "error found in procedure {}: {err}", procedure.name());
                            analyzer.error(err);
                        }
                    }
                }

                // Ensure repeat counts are within acceptable bounds.
                log::debug!(target: "verify-repeat", "visiting procedure {}", procedure.name());
                {
                    let mut visitor = VerifyRepeatCounts::new(analyzer);
                    let _ = visitor.visit_procedure(&procedure);
                }

                // Next, verify invoke targets:
                //
                // * Mark imports as used if they have at least one call to a procedure defined in
                //   that module
                // * Verify that all external callees have a matching import
                log::debug!(target: "verify-invoke", "visiting procedure {}", procedure.name());
                {
                    let mut visitor = VerifyInvokeTargets::new(
                        analyzer,
                        module,
                        &locals,
                        &mut used_aliases,
                        Some(procedure.name().clone()),
                    );
                    let _ = visitor.visit_mut_procedure(&mut procedure);
                }
                if let Err(err) = module.push_export(Item::Procedure(procedure)) {
                    analyzer.error(err);
                }
            },
            Item::Alias(mut alias) => {
                log::debug!(target: "verify-invoke", "visiting alias {}", alias.target());
                {
                    let mut visitor = VerifyInvokeTargets::new(
                        analyzer,
                        module,
                        &locals,
                        &mut used_aliases,
                        None,
                    );
                    let _ = visitor.visit_mut_alias(&mut alias);
                }
                if let Err(err) = module.push_export(Item::Alias(alias)) {
                    analyzer.error(err);
                }
            },
            Item::Constant(mut constant) => {
                log::debug!(target: "verify-invoke", "visiting constant {}", constant.name());
                {
                    let mut visitor = VerifyInvokeTargets::new(
                        analyzer,
                        module,
                        &locals,
                        &mut used_aliases,
                        None,
                    );
                    let _ = visitor.visit_mut_constant(&mut constant);
                }
                if let Err(err) = module.push_export(Item::Constant(constant)) {
                    analyzer.error(err);
                }
            },
            Item::Type(mut ty) => {
                log::debug!(target: "verify-invoke", "visiting type {}", ty.name());
                {
                    let mut visitor = VerifyInvokeTargets::new(
                        analyzer,
                        module,
                        &locals,
                        &mut used_aliases,
                        None,
                    );
                    let _ = visitor.visit_mut_type_decl(&mut ty);
                }
                if let Err(err) = module.push_export(Item::Type(ty)) {
                    analyzer.error(err);
                }
            },
        }
    }

    for alias in module.aliases_mut() {
        if alias.uses == 0 && used_aliases.contains(alias.name().as_str()) {
            alias.uses = 1;
        }
    }
}

fn define_alias(
    item: Alias,
    module: &mut Module,
    context: &mut AnalysisContext,
) -> Result<(), SyntaxError> {
    let name = item.name().clone();
    if let Err(err) = module.define_alias(item, context.source_manager()) {
        match err {
            SemanticAnalysisError::SymbolConflict { .. } => {
                // Proceed anyway, to try and capture more errors
                context.error(err);
            },
            err => {
                // We can't proceed without producing a bunch of errors
                context.error(err);
                context.has_failed()?;
            },
        }
    }

    context.register_imported_name(name);

    Ok(())
}

fn define_procedure(
    procedure: Procedure,
    module: &mut Module,
    context: &mut AnalysisContext,
) -> Result<(), SyntaxError> {
    let name = procedure.name().clone();
    if let Err(err) = module.define_procedure(procedure, context.source_manager()) {
        match err {
            SemanticAnalysisError::SymbolConflict { .. } => {
                // Proceed anyway, to try and capture more errors
                context.error(err);
            },
            err => {
                // We can't proceed without producing a bunch of errors
                context.error(err);
                context.has_failed()?;
            },
        }
    }

    context.register_procedure_name(name);

    Ok(())
}

/// Inserts a new entry in the Advice Map and defines a constant corresposnding to the entry's
/// key.
fn add_advice_map_entry(module: &mut Module, entry: AdviceMapEntry, context: &mut AnalysisContext) {
    let key = match entry.key {
        Some(key) => Word::from(key.inner().0),
        None => Poseidon2::hash_elements(&entry.value),
    };
    let cst = Constant::new(
        entry.span,
        Visibility::Private,
        entry.name.clone(),
        ConstantExpr::Word(Span::new(entry.span, WordValue(*key))),
    );
    context.define_constant(module, cst);
    match module.advice_map.get(&key) {
        Some(_) => {
            context.error(SemanticAnalysisError::AdvMapKeyAlreadyDefined { span: entry.span });
        },
        None => {
            module.advice_map.insert(key, entry.value);
        },
    }
}
