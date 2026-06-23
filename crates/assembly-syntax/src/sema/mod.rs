mod context;
mod errors;
mod passes;
#[cfg(test)]
mod tests;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_core::{Word, crypto::hash::Poseidon2};
use miden_debug_types::{SourceFile, SourceManager, SourceSpan, Span, Spanned};
use smallvec::SmallVec;

use self::passes::{LocalInvokeTarget, VerifyInvokeTargets};
pub use self::{
    context::AnalysisContext,
    errors::{ExportedTypeUse, LimitKind, SemanticAnalysisError, SyntaxError},
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
                namespace_allowed = false;
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
            Form::Import(import) => {
                namespace_allowed = false;
                if let Some(unused) = docs.take() {
                    analyzer.error(SemanticAnalysisError::ImportDocstring { span: unused.span() });
                }
                define_import(import, &mut module, &mut analyzer)?;
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

    // By now we know the actual module kind, or can use the default library kind
    let actual_kind = actual_kind.or(kind).unwrap_or_default();
    module.set_kind(actual_kind);

    // Verify that we have a concrete module name
    if path.is_none() && module.namespace_decl.is_none() {
        if actual_kind.is_executable() {
            module.set_path(Path::EXEC);
        } else {
            analyzer.error(SemanticAnalysisError::MissingNamespace);
            // If we don't have a namespace, we shouldn't proceed any further
            return Err(analyzer.into_result().unwrap_err());
        }
    }

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
                _ => (),
            }
        }
        for import in module.imports() {
            match import {
                Import::Module(import) if import.visibility().is_public() => {
                    analyzer.error(SemanticAnalysisError::ReexportedModule { span: import.span() });
                },
                import
                    if import.visibility().is_public() && actual_kind == ModuleKind::Executable =>
                {
                    analyzer.error(SemanticAnalysisError::UnexpectedExport { span: import.span() });
                },
                Import::Item(import)
                    if import.visibility().is_public() && actual_kind == ModuleKind::Kernel =>
                {
                    analyzer
                        .error(SemanticAnalysisError::ReexportFromKernel { span: import.span() });
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

    verify_exported_signature_type_visibility(&module, &mut analyzer);

    analyzer.has_failed()?;

    // Run item checks
    visit_items(&mut module, &mut analyzer);

    // Check unused imports
    for import in module.imports() {
        if !import.is_used() {
            analyzer.error(SemanticAnalysisError::UnusedImport { span: import.unused_span() });
        }
    }

    analyzer.into_result().map(move |_| module)
}

fn normalize_namespace_path(path: &Path) -> Result<Arc<Path>, PathError> {
    use alloc::borrow::Cow;
    path.canonicalize()
        .and_then(|path| path.to_absolute().map(Cow::into_owned))
        .map(Arc::<Path>::from)
}

fn verify_exported_signature_type_visibility(module: &Module, analyzer: &mut AnalysisContext) {
    for procedure in module.procedures() {
        if !procedure.visibility().is_public() {
            continue;
        }

        let Some(signature) = procedure.signature() else {
            continue;
        };

        for ty in signature.args.iter().chain(signature.results.iter()) {
            let mut visiting_types = BTreeSet::default();
            verify_exported_type_expr(
                module,
                analyzer,
                ty,
                &mut visiting_types,
                ExportedTypeUse::ProcedureSignature,
            );
        }
    }

    for item in module.items() {
        let Item::Type(type_decl) = item else {
            continue;
        };
        if !type_decl.visibility().is_public() {
            continue;
        }

        let mut visiting_types = BTreeSet::default();
        verify_exported_type_decl(
            module,
            analyzer,
            type_decl,
            &mut visiting_types,
            ExportedTypeUse::TypeDeclaration,
        );
    }
}

fn verify_exported_type_decl(
    module: &Module,
    analyzer: &mut AnalysisContext,
    type_decl: &TypeDecl,
    visiting_types: &mut BTreeSet<ItemIndex>,
    usage: ExportedTypeUse,
) {
    match type_decl {
        TypeDecl::Alias(alias) => {
            verify_exported_type_expr(module, analyzer, &alias.ty, visiting_types, usage);
        },
        TypeDecl::Enum(ty) => {
            for variant in ty.variants() {
                if let Some(payload_ty) = variant.value_ty.as_ref() {
                    verify_exported_type_expr(module, analyzer, payload_ty, visiting_types, usage);
                }
            }
        },
    }
}

fn verify_exported_type_expr(
    module: &Module,
    analyzer: &mut AnalysisContext,
    ty: &TypeExpr,
    visiting_types: &mut BTreeSet<ItemIndex>,
    usage: ExportedTypeUse,
) {
    match ty {
        TypeExpr::Primitive(_) => (),
        TypeExpr::Ptr(ty) => {
            verify_exported_type_expr(module, analyzer, &ty.pointee, visiting_types, usage);
        },
        TypeExpr::Array(ty) => {
            verify_exported_type_expr(module, analyzer, &ty.elem, visiting_types, usage);
        },
        TypeExpr::Struct(ty) => {
            for field in ty.fields.iter() {
                verify_exported_type_expr(module, analyzer, &field.ty, visiting_types, usage);
            }
        },
        TypeExpr::Ref(path) => {
            let resolver = match LocalSymbolResolver::new(module, analyzer.source_manager()) {
                Ok(resolver) => resolver,
                Err(_) => return,
            };
            let resolution = match resolver.resolve_path(path.as_deref()) {
                Ok(resolution) => resolution,
                Err(_) => return,
            };
            let item = match resolution {
                SymbolResolution::Local(item) => Some(item.into_inner()),
                SymbolResolution::External(path)
                    if path.parent().is_some_and(|parent| parent == module.path()) =>
                {
                    let Some(local_name) = path.last() else {
                        return;
                    };
                    module.index_of(|item| item.name().as_str() == local_name)
                },
                SymbolResolution::External(_)
                | SymbolResolution::MastRoot(_)
                | SymbolResolution::Exact { .. }
                | SymbolResolution::Module { .. } => None,
            };
            let Some(item) = item else {
                return;
            };
            let Some(export) = module.get(item) else {
                return;
            };
            let Item::Type(type_decl) = export else {
                return;
            };

            if !type_decl.visibility().is_public() {
                analyzer.error(usage.private_type_error(path.span(), type_decl.name().span()));
                return;
            }

            if !visiting_types.insert(item) {
                return;
            }

            verify_exported_type_decl(module, analyzer, type_decl, visiting_types, usage);

            visiting_types.remove(&item);
        },
    }
}

/// Visit all of the items of the current analysis context, and apply various transformation and
/// analysis passes.
///
/// When this function returns, all local analysis is complete, and all that remains is construction
/// of a module graph and global program analysis to perform any remaining transformations.
fn visit_items(module: &mut Module, analyzer: &mut AnalysisContext) {
    let is_kernel = module.is_kernel();
    let mut locals = BTreeMap::from_iter(
        module
            .items()
            .iter()
            .map(|item| (item.name().as_str().to_string(), LocalInvokeTarget::from(item))),
    );
    locals.extend(
        module.imports().map(|import| {
            (import.local_name().as_str().to_string(), LocalInvokeTarget::from(import))
        }),
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

    for import in module.imports_mut() {
        if import.is_used() || !used_aliases.contains(import.local_name().as_str()) {
            continue;
        }
        match import {
            Import::Module(import) => import.uses = 1,
            Import::Item(import) => import.uses = 1,
        }
    }
}

fn define_import(
    import: ImportDecl,
    module: &mut Module,
    context: &mut AnalysisContext,
) -> Result<(), SyntaxError> {
    match import {
        ImportDecl::Module(import) => {
            if import.visibility().is_public() {
                context.error(SemanticAnalysisError::ReexportedModule { span: import.span() });
                context.has_failed()?;
            }
            if let Err(err) = module.define_import(Import::Module(import)) {
                match err {
                    SemanticAnalysisError::SymbolConflict { .. } => context.error(err),
                    err => {
                        context.error(err);
                        context.has_failed()?;
                    },
                }
            }
        },
        ImportDecl::Items(group) => {
            preflight_item_import_group(&group, module, context)?;
            let visibility = group.visibility();
            let group_module_path = group.module_path();
            let module_path: Span<Arc<Path>> =
                Span::new(group_module_path.span(), Arc::from(*group_module_path));
            for spec in group.specs() {
                let name = spec.local_name().clone();
                let import = Import::Item(ItemImport::new(
                    spec.local_name().span(),
                    visibility,
                    module_path.clone(),
                    spec.source_name().clone(),
                    name.clone(),
                ));
                if let Err(err) = module.define_import(import) {
                    match err {
                        SemanticAnalysisError::SymbolConflict { .. } => context.error(err),
                        err => {
                            context.error(err);
                            context.has_failed()?;
                        },
                    }
                }
                context.register_imported_name(name);
            }
        },
    }

    Ok(())
}

fn preflight_item_import_group(
    group: &ItemImportGroup,
    module: &Module,
    context: &mut AnalysisContext,
) -> Result<(), SyntaxError> {
    let mut seen = BTreeMap::<String, SourceSpan>::new();
    let mut failed = false;
    for spec in group.specs() {
        let local_name = spec.local_name();
        if let Some(prev_span) = seen.insert(local_name.to_string(), local_name.span()) {
            failed = true;
            context.error(SemanticAnalysisError::SymbolConflict {
                span: local_name.span(),
                prev_span,
            });
            continue;
        }
        if let Some(prev) = module.get_declaration(local_name.as_str()) {
            failed = true;
            context.error(SemanticAnalysisError::SymbolConflict {
                span: local_name.span(),
                prev_span: prev.span(),
            });
        }
    }

    if failed {
        context.has_failed()?;
    }

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
