mod symbol_resolver;

use alloc::{collections::BTreeMap, string::ToString, sync::Arc};

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
    library::ItemInfo,
};
use smallvec::SmallVec;

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

/// A [ResolverCache] is used to cache resolutions of type and constant expressions to concrete
/// values that contain no references to other symbols. Since these resolutions can be expensive
/// to compute, and often represent items which are referenced multiple times, we cache them to
/// avoid recomputing the same information over and over again.
#[derive(Default)]
pub struct ResolverCache {
    pub types: BTreeMap<GlobalItemIndex, types::Type>,
    pub constants: BTreeMap<GlobalItemIndex, ast::ConstantValue>,
    pub evaluating_constants: BTreeMap<GlobalItemIndex, SourceSpan>,
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
            SymbolItem::Alias { .. } => unreachable!("resolver should have expanded all aliases"),
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
            SymbolItem::Alias { .. } => unreachable!("resolver should have expanded all aliases"),
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
        let gid = match self.resolver.resolve_local(&context, name)? {
            SymbolResolution::Exact { gid, .. } => gid,
            SymbolResolution::Local(index) => self.current_module + index.into_inner(),
            SymbolResolution::MastRoot(_) | SymbolResolution::Module { .. } => {
                return Err(self.invalid_constant_ref(context.span));
            },
            SymbolResolution::External(path) => {
                return Err(LinkerError::UndefinedSymbol {
                    span: context.span,
                    source_file: self.get_source_file_for(context.span),
                    path: path.into_inner(),
                });
            },
        };

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
        let gid = match self.resolver.resolve_path(&context, path)? {
            SymbolResolution::Exact { gid, .. } => gid,
            SymbolResolution::Local(index) => self.current_module + index.into_inner(),
            SymbolResolution::MastRoot(_) | SymbolResolution::Module { .. } => {
                return Err(self.invalid_constant_ref(context.span));
            },
            SymbolResolution::External(path) => {
                return Err(LinkerError::UndefinedSymbol {
                    span: context.span,
                    source_file: self.get_source_file_for(context.span),
                    path: path.into_inner(),
                });
            },
        };

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
            Ok(SymbolResolution::Local(index)) => self.current_module + index.into_inner(),
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
    ) -> Result<types::Type, LinkerError> {
        match self.resolver.linker()[gid].item() {
            SymbolItem::Compiled(ItemInfo::Type(info)) => Ok(info.ty.clone()),
            SymbolItem::Type(ast::TypeDecl::Enum(ty)) => {
                // When resolving an EnumType, we must do three things:
                //
                // * Resolve the discriminant type
                // * Resolve the discriminant value and payload type for each variant
                // * Construct the midenc_hir_type::EnumType, and validate that the enum is valid
                //   according to the rules it enforces
                let mut variants = SmallVec::<[types::Variant; 4]>::new_const();
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
                    variants.push(types::Variant {
                        name: variant.name.clone().into_inner(),
                        value: match variant.value_ty.as_ref() {
                            Some(t) => t.resolve_type(self)?,
                            None => None,
                        },
                        discriminant_value,
                    });
                }
                types::EnumType::new(ty.name().clone().into_inner(), ty.ty().clone(), variants)
                    .map(|t| types::Type::Enum(Arc::new(t)))
                    .map_err(|err| LinkerError::Related {
                        errors: vec![RelatedError::from(Report::from(diagnostic!(
                            severity = Severity::Error,
                            labels = vec![LabeledSpan::at(context, err.to_string())],
                            "invalid enum type"
                        )))]
                        .into_boxed_slice(),
                    })
            },
            SymbolItem::Type(ast::TypeDecl::Alias(ty)) => {
                Ok(ty.ty.resolve_type(self)?.expect("unreachable"))
            },
            SymbolItem::Compiled(_) | SymbolItem::Constant(_) | SymbolItem::Procedure(_) => {
                Err(LinkerError::InvalidTypeRef {
                    span: context,
                    source_file: self.get_source_file_for(context),
                })
            },
            SymbolItem::Alias { .. } => unreachable!("resolver should have expanded all aliases"),
        }
    }

    fn get_local_type(
        &mut self,
        context: SourceSpan,
        id: ItemIndex,
    ) -> Result<Option<types::Type>, LinkerError> {
        self.get_type(context, self.current_module + id).map(Some)
    }

    fn resolve_type_ref(&mut self, ty: Span<&Path>) -> Result<SymbolResolution, LinkerError> {
        let context = SymbolResolutionContext {
            span: ty.span(),
            module: self.current_module,
            kind: None,
        };
        match self.resolver.resolve_path(&context, ty)? {
            exact @ SymbolResolution::Exact { .. } => Ok(exact),
            SymbolResolution::Local(index) => {
                let (span, index) = index.into_parts();
                let current_module = &self.resolver.linker()[self.current_module];
                let item = current_module[index].name();
                let path = Span::new(span, current_module.path().join(item).into());
                Ok(SymbolResolution::Exact { gid: self.current_module + index, path })
            },
            SymbolResolution::MastRoot(_) | SymbolResolution::Module { .. } => {
                Err(LinkerError::InvalidTypeRef {
                    span: ty.span(),
                    source_file: self.get_source_file_for(ty.span()),
                })
            },
            SymbolResolution::External(path) => Err(LinkerError::UndefinedSymbol {
                span: ty.span(),
                source_file: self.get_source_file_for(ty.span()),
                path: path.into_inner(),
            }),
        }
    }
}
