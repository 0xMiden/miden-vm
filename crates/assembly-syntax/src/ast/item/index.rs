/// Represents the index of an item within its respective storage vector in some module
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ItemIndex(u16);

#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid item index: too many items")]
pub struct ItemIndexError {
    attempted: usize,
}

impl ItemIndex {
    pub const MAX_ITEMS: usize = u16::MAX as usize + 1;

    pub fn new(id: usize) -> Self {
        Self::try_new(id).expect("invalid item index: too many items")
    }

    pub fn try_new(id: usize) -> Result<Self, ItemIndexError> {
        let raw = id.try_into().map_err(|_| ItemIndexError { attempted: id })?;
        Ok(Self(raw))
    }

    #[inline(always)]
    pub const fn const_new(id: u16) -> Self {
        Self(id)
    }

    /// Get the raw index value of this item
    #[inline(always)]
    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl core::fmt::Display for ItemIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", &self.as_usize())
    }
}

/// Uniquely identifies an item in a set of [crate::ast::Module]
///
/// A [GlobalItemIndex] is assigned to an item when it is added to the linker's module
/// graph. The index uniquely identifies that item in the graph, and provides a unique,
/// copyable, machine-word sized handle that can be trivially stored, passed around, and later used
/// to perform constant-complexity operations against that item.
///
/// <div class="warning">
/// As a result of this being just an index into a specific instance of a [super::ModuleGraph],
/// it does not provide any guarantees about uniqueness or stability when the same module is stored
/// in multiple graphs - each graph may assign it a unique index. You must ensure that you do not
/// store these indices and attempt to use them with just any module graph - it is only valid with
/// the one it was assigned from.
/// </div>
///
/// In addition to the linker's module graph, these indices are also used with an instance of a
/// `MastForestBuilder`. This is because the linker and `MastForestBuilder` instances
/// are paired, i.e. the linker stores the syntax trees and call graph analysis for a program, while
/// the `MastForestBuilder` caches the compiled procedures for the same program, as derived from
/// the corresponding graph.
///
/// This is intended for use when we are doing global inter-procedural analysis on a (possibly
/// growable) set of modules. It is expected that the index of a module in the set, as well as the
/// index of an item in a module, are stable once allocated in the graph. The set of modules and
/// items can grow, as long as growing the set only allocates unused identifiers.
///
/// NOTE: This struct is the same size as a u32
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GlobalItemIndex {
    /// The index of the containing module in the global set of modules
    pub module: ModuleIndex,
    /// The local index of the procedure in the module
    pub index: ItemIndex,
}

impl core::fmt::Display for GlobalItemIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", &self.module, &self.index)
    }
}

/// A strongly-typed index into a set of [crate::ast::Module]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ModuleIndex(u16);
impl ModuleIndex {
    pub fn new(index: usize) -> Self {
        Self(index.try_into().expect("invalid module index: too many modules"))
    }

    pub const fn const_new(index: u16) -> Self {
        Self(index)
    }

    #[inline(always)]
    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl core::ops::Add<ItemIndex> for ModuleIndex {
    type Output = GlobalItemIndex;

    fn add(self, rhs: ItemIndex) -> Self::Output {
        GlobalItemIndex { module: self, index: rhs }
    }
}

impl core::fmt::Display for ModuleIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", &self.as_usize())
    }
}

#[cfg(test)]
mod regression_tests {
    use std::{string::String, sync::Arc};

    use miden_debug_types::{DefaultSourceManager, SourceSpan, Span};

    use super::ItemIndex;
    use crate::{
        Parse, ParseOptions, Path,
        ast::{
            Constant, ConstantExpr, Export, Ident, Module, ModuleKind, SymbolResolutionError,
            Visibility,
        },
        parser::IntValue,
        sema::{LimitKind, SemanticAnalysisError, SyntaxError},
    };

    fn huge_library_masm() -> String {
        let num_consts = usize::from(u16::MAX) + 2;
        let mut masm = String::with_capacity(num_consts * 16);
        for i in 0..num_consts {
            masm.push_str("const A");
            masm.push_str(&format!("{i}"));
            masm.push_str(" = 0\n");
        }
        masm
    }

    fn oversized_module_for_resolver() -> Module {
        let mut module = Module::new(ModuleKind::Library, Path::new("::m::huge"));
        for i in 0..=ItemIndex::MAX_ITEMS {
            module.items.push(Export::Constant(Constant::new(
                SourceSpan::UNKNOWN,
                Visibility::Private,
                Ident::new(format!("A{i}")).expect("valid identifier"),
                ConstantExpr::Int(Span::unknown(IntValue::from(0u8))),
            )));
        }
        module
    }

    #[test]
    fn too_many_items_in_module_is_rejected_during_analysis() {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let err = huge_library_masm()
            .parse_with_options(
                source_manager,
                ParseOptions::new(ModuleKind::Library, Path::new("::m::huge")),
            )
            .expect_err("expected oversized module to be rejected during analysis");

        let syntax_error = err.downcast_ref::<SyntaxError>().expect("expected SyntaxError report");
        assert!(
            syntax_error.errors.iter().any(|error| {
                matches!(error, SemanticAnalysisError::LimitExceeded { kind: LimitKind::Items, .. })
            }),
            "expected item-limit error, got {:?}",
            syntax_error.errors
        );
    }

    #[test]
    fn resolving_name_in_too_large_module_returns_structured_error() {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let module = oversized_module_for_resolver();
        let result = module.resolve(Span::unknown("A0"), source_manager);

        assert!(matches!(result, Err(SymbolResolutionError::TooManyItemsInModule { .. })));
    }

    #[test]
    fn resolver_construction_for_too_large_module_returns_structured_error() {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let module = oversized_module_for_resolver();

        let result = module.resolver(source_manager);

        assert!(matches!(result, Err(SymbolResolutionError::TooManyItemsInModule { .. })));
    }
}
