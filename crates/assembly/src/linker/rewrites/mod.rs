mod module;

use miden_assembly_syntax::{ast::GlobalItemIndex, library::ItemInfo};

pub use self::module::ModuleRewriter;
use super::*;

/// Rewrite `symbol` such that all unresolved references to other symbols have been resolved.
///
/// This function will use `resolver` to resolve references to other symbols, using `cache` to cache
/// resolutions.
pub fn rewrite_symbol(
    gid: GlobalItemIndex,
    symbol: &Symbol,
    resolver: &SymbolResolver<'_>,
    cache: &mut ResolverCache,
) -> Result<(), LinkerError> {
    use ast::visit::VisitMut;

    if matches!(symbol.status(), LinkStatus::Linked) {
        return Ok(());
    }

    log::trace!(target: "linker::rewrite_symbol", "rewriting {}", symbol.name());
    match symbol.item() {
        SymbolItem::Compiled(item) => match item {
            ItemInfo::Constant(value) => {
                cache.constants.insert(gid, value.value.clone());
            },
            ItemInfo::Type(ty) => {
                cache.types.insert(gid, ty.ty.clone());
            },
            ItemInfo::Procedure(_) => (),
        },
        SymbolItem::Alias { alias, resolved: resolved_gid } => {
            let context = SymbolResolutionContext {
                span: alias.span(),
                module: gid.module,
                kind: None,
            };
            match resolver.resolve_alias_target(&context, alias.target())? {
                SymbolResolution::Exact { gid, .. } => {
                    resolved_gid.set(Some(gid));
                },
                SymbolResolution::Local(local) => {
                    resolved_gid.set(Some(gid.module + local.into_inner()));
                },
                SymbolResolution::MastRoot(root) => {
                    if let Some(gid) = resolver.linker().get_procedure_index_by_digest(&root) {
                        resolved_gid.set(Some(gid));
                    }
                },
                SymbolResolution::Module { .. } => (),
                SymbolResolution::External(path) => {
                    let (span, path) = path.into_parts();
                    return Err(LinkerError::UndefinedSymbol {
                        span,
                        source_file: resolver.source_manager().get(span.source_id()).ok(),
                        path,
                    });
                },
            }
        },
        SymbolItem::Procedure(proc) => {
            let mut rewriter = ModuleRewriter::new(gid.module, resolver);
            let mut proc = proc.borrow_mut();
            if let ControlFlow::Break(err) = rewriter.visit_mut_procedure(&mut proc) {
                return Err(err);
            }
        },
        SymbolItem::Constant(item) => {
            let mut resolver = Resolver {
                resolver,
                cache,
                current_module: gid.module,
            };
            let value = ast::constants::eval::expr(&item.value, &mut resolver)?
                .into_value()
                .expect("value or error to have been raised");
            resolver.cache.constants.insert(gid, value);
        },
        SymbolItem::Type(item) => {
            let resolver = Resolver {
                resolver,
                cache,
                current_module: gid.module,
            };
            let ty = item.ty().resolve_type(&resolver)?.expect("type or error to have been raised");
            resolver.cache.types.insert(gid, ty);
        },
    }

    symbol.set_status(LinkStatus::Linked);

    Ok(())
}
