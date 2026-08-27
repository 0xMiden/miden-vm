mod symbol_resolver;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::ToString,
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{
    Report,
    ast::{
        self, GlobalItemIndex, Ident, ItemIndex, ModuleIndex, Path, SymbolResolution,
        SymbolResolutionError,
        constants::{ConstEnvironment, ConstEvalError, eval::CachedConstantValue},
        types,
    },
    debuginfo::{SourceFile, SourceManager, SourceSpan, Span, Spanned},
    diagnostics::{LabeledSpan, RelatedError, Severity, diagnostic},
    module::ItemInfo,
};

pub use self::symbol_resolver::{SymbolResolutionContext, SymbolResolver};
use super::SymbolItem;
use crate::LinkerError;

/// A [Resolver] is used to perform symbol resolution in the context of a specific module.
///
/// It is instantiated along with a [ResolverCache] to cache frequently-referenced symbols, and a
/// [SymbolResolver] for resolving externally-defined symbols.
pub struct Resolver<'a, 'b: 'a> {
    pub resolver: &'a SymbolResolver<'b>,
    pub cache: &'a mut ResolverCache,
    pub current_module: ModuleIndex,
}

/// An aggregate declaration awaiting group construction.
struct PendingTypeDef {
    gid: GlobalItemIndex,
    key: Arc<str>,
    kind: types::AggregateKind,
    template: types::TypeTemplate,
}

/// A type declaration currently being resolved.
struct EvaluatingType {
    gid: GlobalItemIndex,
    /// Where resolution of this declaration began, for cycle diagnostics.
    span: SourceSpan,
    /// Whether this declaration defines an aggregate, and so can carry a back-reference.
    is_aggregate: bool,
}

/// A [ResolverCache] is used to cache resolutions of type and constant expressions to concrete
/// values that contain no references to other symbols. Since these resolutions can be expensive
/// to compute, and often represent items which are referenced multiple times, we cache them to
/// avoid recomputing the same information over and over again.
#[derive(Default)]
pub struct ResolverCache {
    pub types: BTreeMap<GlobalItemIndex, types::Type>,
    pub constants: BTreeMap<GlobalItemIndex, ast::ConstantValue>,
    pub evaluating_constants: BTreeMap<GlobalItemIndex, SourceSpan>,
    /// Aggregate declarations collected while resolving one outermost type expression.
    ///
    /// These are handed to the recursive type builder together, so that a group spanning several
    /// declarations is built as a unit. Non-recursive declarations in the set simply come back
    /// out as ordinary types.
    pending_types: Vec<PendingTypeDef>,
    /// Type declarations currently being resolved, and where resolution of each began.
    ///
    /// Type references are expanded structurally, so this allows us to catch declaration cycles
    /// such as `type A = B` / `type B = A` which would otherwise infinitely recurse.
    /// Ordered, so that on re-entering a declaration it can be seen what was entered after it.
    evaluating_types: Vec<EvaluatingType>,
    /// Aliases currently being re-expanded.
    ///
    /// An alias cannot hold a back-reference, so a cycle through one is broken by expanding the
    /// alias again and letting it terminate at an enclosing aggregate. This is per path, not per
    /// resolution: the same alias may legitimately be reached from several fields of one
    /// aggregate, and each is a separate cycle broken by the same pointer. Refusing to re-expand
    /// an alias already being re-expanded *on this path* is what bounds the work, since each
    /// alias can then appear on the path at most once.
    reexpanding_types: BTreeSet<GlobalItemIndex>,
}

impl<'a, 'b: 'a> Resolver<'a, 'b> {
    fn invalid_constant_ref(&self, span: SourceSpan) -> LinkerError {
        LinkerError::InvalidConstantRef {
            span,
            source_file: self.get_source_file_for(span),
        }
    }

    pub(super) fn materialize_constant_by_gid(
        &mut self,
        gid: GlobalItemIndex,
        span: SourceSpan,
    ) -> Result<(), LinkerError> {
        if self.cache.constants.contains_key(&gid) {
            return Ok(());
        }

        match self.resolver.linker()[gid].item() {
            SymbolItem::Compiled(ItemInfo::Constant(_)) => return Ok(()),
            SymbolItem::Constant(item) => {
                let expr = item.value.clone();
                let eval_span = item.value.span();
                if let Some(start) = self.cache.evaluating_constants.get(&gid).copied() {
                    return Err(ConstEvalError::eval_cycle(start, span, self).into());
                }

                self.cache.evaluating_constants.insert(gid, eval_span);
                let value = self.resolver.linker().const_eval(gid, &expr, self.cache);
                self.cache.evaluating_constants.remove(&gid);

                let value = value?;
                self.cache.constants.insert(gid, value);
                return Ok(());
            },
            SymbolItem::Compiled(_) | SymbolItem::Procedure(_) | SymbolItem::Type(_) => (),
        }

        Err(self.invalid_constant_ref(span))
    }

    fn get_constant_by_gid(
        &mut self,
        gid: GlobalItemIndex,
        span: SourceSpan,
    ) -> Result<Option<CachedConstantValue<'_>>, LinkerError> {
        self.materialize_constant_by_gid(gid, span)?;

        if let Some(cached) = self.cache.constants.get(&gid) {
            return Ok(Some(CachedConstantValue::Hit(cached)));
        }

        match self.resolver.linker()[gid].item() {
            SymbolItem::Compiled(ItemInfo::Constant(info)) => {
                Ok(Some(CachedConstantValue::Hit(&info.value)))
            },
            SymbolItem::Compiled(_)
            | SymbolItem::Constant(_)
            | SymbolItem::Procedure(_)
            | SymbolItem::Type(_) => Err(self.invalid_constant_ref(span)),
        }
    }
}

impl<'a, 'b: 'a> ConstEnvironment for Resolver<'a, 'b> {
    type Error = LinkerError;

    fn get_source_file_for(&self, span: SourceSpan) -> Option<Arc<SourceFile>> {
        self.resolver.source_manager().get(span.source_id()).ok()
    }

    fn get(&mut self, name: &Ident) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
        let context = SymbolResolutionContext {
            span: name.span(),
            module: self.current_module,
            kind: None,
        };
        let path = Path::from_ident(name);
        let gid = self
            .resolver
            .resolve_constant_path(&context, Span::new(name.span(), path.as_ref()))?;

        self.get_constant_by_gid(gid, name.span())
    }

    fn get_by_path(
        &mut self,
        path: Span<&Path>,
    ) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
        let context = SymbolResolutionContext {
            span: path.span(),
            module: self.current_module,
            kind: None,
        };
        let gid = self.resolver.resolve_constant_path(&context, path)?;

        self.get_constant_by_gid(gid, path.span())
    }

    /// Cache evaluated constants so long as they evaluated to a ConstantValue, and we can resolve
    /// the path to a known GlobalItemIndex
    fn on_eval_completed(&mut self, path: Span<&Path>, value: &ast::ConstantExpr) {
        let Some(value) = value.as_value() else {
            return;
        };
        let context = SymbolResolutionContext {
            span: path.span(),
            module: self.current_module,
            kind: None,
        };
        let gid = match self.resolver.resolve_path(&context, path) {
            Ok(SymbolResolution::Exact { gid, .. }) => gid,
            _ => return,
        };
        self.cache.constants.insert(gid, value);
    }
}

impl<'a, 'b: 'a> ast::TypeResolver<LinkerError> for Resolver<'a, 'b> {
    #[inline]
    fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.resolver.source_manager_arc()
    }
    #[inline]
    fn resolve_local_failed(&self, err: SymbolResolutionError) -> LinkerError {
        LinkerError::from(err)
    }

    fn get_type(
        &mut self,
        context: SourceSpan,
        gid: GlobalItemIndex,
    ) -> Result<Option<types::TypeTemplate>, LinkerError> {
        if let Some(cached) = self.cache.types.get(&gid) {
            return Ok(Some(types::TypeTemplate::Type(cached.clone())));
        }

        let key = self.type_key(gid);

        // Already being resolved: this reference closes a cycle.
        if let Some(position) = self.cache.evaluating_types.iter().position(|e| e.gid == gid) {
            let start = self.cache.evaluating_types[position].span;

            // An aggregate carries the cycle directly, as a back-reference.
            if self.aggregate_kind(gid).is_some() {
                return Ok(Some(types::TypeTemplate::Rec(key)));
            }

            // An alias cannot carry a back-reference, but the cycle may still be finite if an
            // aggregate was entered after this alias: expanding the alias once more terminates
            // at that aggregate's back-reference. With no aggregate in between, the cycle is
            // between aliases alone and has no finite representation.
            let broken_by_aggregate =
                self.cache.evaluating_types[position + 1..].iter().any(|e| e.is_aggregate);
            if broken_by_aggregate && self.cache.reexpanding_types.insert(gid) {
                let expanded = self.expand_alias_body(context, gid);
                self.cache.reexpanding_types.remove(&gid);
                return expanded;
            }

            return Err(LinkerError::RecursiveType {
                span: start,
                cycle_span: context,
                source_file: self.get_source_file_for(start),
            });
        }

        // An aggregate declaration becomes a definition of the group under construction, and is
        // referred to by key until the group is built. Anything else is expanded in place, as it
        // always was.
        let Some(kind) = self.aggregate_kind(gid) else {
            return self.resolve_alias_template(context, gid);
        };

        if self.cache.pending_types.iter().any(|def| def.gid == gid) {
            return Ok(Some(types::TypeTemplate::Rec(key)));
        }

        self.cache
            .evaluating_types
            .push(EvaluatingType { gid, span: context, is_aggregate: true });
        let resolved = self.resolve_aggregate_template(context, gid);
        self.cache.evaluating_types.pop();

        let template = resolved?;
        self.cache
            .pending_types
            .push(PendingTypeDef { gid, key: key.clone(), kind, template });
        Ok(Some(types::TypeTemplate::Rec(key)))
    }

    fn get_local_type(
        &mut self,
        context: SourceSpan,
        id: ItemIndex,
    ) -> Result<Option<types::TypeTemplate>, LinkerError> {
        self.get_type(context, self.current_module + id)
    }

    fn resolve_type_ref(&mut self, ty: Span<&Path>) -> Result<SymbolResolution, LinkerError> {
        let context = SymbolResolutionContext {
            span: ty.span(),
            module: self.current_module,
            kind: None,
        };
        let gid = self.resolver.resolve_type_path(&context, ty)?;
        Ok(SymbolResolution::Exact {
            gid,
            path: Span::new(ty.span(), self.resolver.item_path(gid)),
        })
    }

    fn finalize(
        &mut self,
        context: SourceSpan,
        template: types::TypeTemplate,
    ) -> Result<types::Type, LinkerError> {
        let pending = core::mem::take(&mut self.cache.pending_types);
        if pending.is_empty() {
            // Nothing referred to an aggregate declaration, so the template is already closed.
            return types::close_template(&template, |_| None)
                .map_err(|err| self.recursive_type_error(context, err));
        }

        let mut builder = types::RecursiveTypeBuilder::new();
        for def in &pending {
            match (def.kind, &def.template) {
                (types::AggregateKind::Struct, types::TypeTemplate::Struct(body)) => {
                    builder.define_struct(def.key.clone(), (*body.clone()).clone());
                },
                (types::AggregateKind::Enum, types::TypeTemplate::Enum(body)) => {
                    builder.define_enum(def.key.clone(), (*body.clone()).clone());
                },
                _ => {
                    return Err(LinkerError::InvalidTypeRef {
                        span: context,
                        source_file: self.get_source_file_for(context),
                    });
                },
            }
        }

        // The builder partitions the definitions into strongly connected components, so
        // declarations which turned out not to be recursive come back out as ordinary types, and
        // a cycle that crosses no pointer is rejected here.
        let built = builder.build().map_err(|err| self.recursive_type_error(context, err))?;

        for def in &pending {
            if let Some(ty) = built.get(&def.key) {
                self.cache.types.insert(def.gid, ty.clone());
            }
        }

        types::close_template(&template, |key| built.get(key).cloned())
            .map_err(|err| self.recursive_type_error(context, err))
    }
}

impl<'a, 'b: 'a> Resolver<'a, 'b> {
    /// The binding key for a type declaration: its fully qualified path, which is unique across
    /// the link and therefore usable as a group ordering key.
    fn type_key(&self, gid: GlobalItemIndex) -> Arc<str> {
        Arc::from(alloc::format!("{}", self.resolver.item_path(gid)))
    }

    /// Whether a declaration defines an aggregate, and which kind, determined syntactically so
    /// that it can be answered while the declaration is still being resolved.
    fn aggregate_kind(&self, gid: GlobalItemIndex) -> Option<types::AggregateKind> {
        match self.resolver.linker()[gid].item() {
            SymbolItem::Type(ast::TypeDecl::Enum(_)) => Some(types::AggregateKind::Enum),
            SymbolItem::Type(ast::TypeDecl::Alias(ty)) => {
                matches!(ty.ty, ast::TypeExpr::Struct(_)).then_some(types::AggregateKind::Struct)
            },
            _ => None,
        }
    }

    fn recursive_type_error(
        &self,
        context: SourceSpan,
        err: types::RecursiveTypeError,
    ) -> LinkerError {
        LinkerError::Related {
            errors: vec![RelatedError::from(Report::from(diagnostic!(
                severity = Severity::Error,
                labels = vec![LabeledSpan::at(context, err.to_string())],
                "invalid recursive type"
            )))]
            .into_boxed_slice(),
        }
    }

    /// Expand an alias declaration's body in place.
    ///
    /// Kept separate from [`Self::resolve_alias_template`] so that re-entering an alias which is
    /// already in progress can expand it again without pushing it onto the stack twice.
    fn expand_alias_body(
        &mut self,
        context: SourceSpan,
        gid: GlobalItemIndex,
    ) -> Result<Option<types::TypeTemplate>, LinkerError> {
        match self.resolver.linker()[gid].item() {
            SymbolItem::Type(ast::TypeDecl::Alias(ty)) => {
                let body = ty.ty.clone();
                body.resolve_template(self)
            },
            _ => Err(LinkerError::InvalidTypeRef {
                span: context,
                source_file: self.get_source_file_for(context),
            }),
        }
    }

    /// Resolve a non-aggregate declaration, expanding it in place.
    fn resolve_alias_template(
        &mut self,
        context: SourceSpan,
        gid: GlobalItemIndex,
    ) -> Result<Option<types::TypeTemplate>, LinkerError> {
        match self.resolver.linker()[gid].item() {
            SymbolItem::Compiled(ItemInfo::Type(info)) => {
                Ok(Some(types::TypeTemplate::Type(info.ty.clone())))
            },
            SymbolItem::Type(ast::TypeDecl::Alias(_)) => {
                self.cache.evaluating_types.push(EvaluatingType {
                    gid,
                    span: context,
                    is_aggregate: false,
                });
                let resolved = self.expand_alias_body(context, gid);
                self.cache.evaluating_types.pop();
                resolved
            },
            SymbolItem::Type(ast::TypeDecl::Enum(_))
            | SymbolItem::Compiled(_)
            | SymbolItem::Constant(_)
            | SymbolItem::Procedure(_) => Err(LinkerError::InvalidTypeRef {
                span: context,
                source_file: self.get_source_file_for(context),
            }),
        }
    }

    /// Resolve an aggregate declaration to the template for its body.
    fn resolve_aggregate_template(
        &mut self,
        context: SourceSpan,
        gid: GlobalItemIndex,
    ) -> Result<types::TypeTemplate, LinkerError> {
        match self.resolver.linker()[gid].item() {
            SymbolItem::Type(ast::TypeDecl::Enum(ty)) => {
                let mut variants = Vec::with_capacity(ty.variants().len());
                for variant in ty.variants() {
                    let discriminant_value = match self.resolver.linker().const_eval(
                        gid,
                        &variant.discriminant,
                        self.cache,
                    )? {
                        ast::ConstantValue::Int(v) => Some(v.as_canonical_u64() as u128),
                        invalid => {
                            return Err(LinkerError::Related {
                                errors: vec![RelatedError::new(Report::from(diagnostic!(
                                    severity = Severity::Error,
                                    labels = vec![LabeledSpan::at(
                                        invalid.span(),
                                        "invalid enum discriminant: expected an integer"
                                    )],
                                    "invalid enum type"
                                )))]
                                .into_boxed_slice(),
                            });
                        },
                    };
                    variants.push(types::VariantTemplate {
                        name: variant.name.clone().into_inner(),
                        value: match variant.value_ty.as_ref() {
                            Some(t) => t.resolve_template(self)?,
                            None => None,
                        },
                        discriminant_value,
                    });
                }
                Ok(types::TypeTemplate::Enum(Box::new(types::EnumTemplate {
                    name: ty.name().clone().into_inner(),
                    discriminant: ty.ty().clone(),
                    variants,
                })))
            },
            SymbolItem::Type(ast::TypeDecl::Alias(ty)) => {
                let body = ty.ty.clone();
                body.resolve_template(self)?.ok_or_else(|| LinkerError::UndefinedType {
                    span: context,
                    source_file: self.get_source_file_for(context),
                })
            },
            _ => Err(LinkerError::InvalidTypeRef {
                span: context,
                source_file: self.get_source_file_for(context),
            }),
        }
    }
}
