mod module;

use miden_assembly_syntax::{ast::GlobalItemIndex, module::ItemInfo};

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
        SymbolItem::Procedure(proc) => {
            let mut rewriter = ModuleRewriter::new(gid.module, resolver, cache);
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
            let mut resolver = Resolver {
                resolver,
                cache,
                current_module: gid.module,
            };
            let ty = item
                .ty()
                .resolve_type(&mut resolver)?
                .expect("type or error to have been raised");
            resolver.cache.types.insert(gid, ty);
        },
    }

    symbol.set_status(LinkStatus::Linked);

    Ok(())
}
