use alloc::{sync::Arc, vec::Vec};
use core::ops::Index;

use midenc_hir_type::FunctionType;

use crate::{
    Path, Word,
    ast::{
        self, AttributeSet, ConstantExpr, GlobalItemIndex, Ident, ItemIndex,
        LocalSymbolResolutionError, LocalSymbolResolver, ProcedureName, SymbolResolution,
        TypeResolver,
    },
    debuginfo::{SourceSpan, Span, Spanned},
};

// MODULE INFO
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    path: Arc<Path>,
    items: Vec<ItemInfo>,
}

impl ModuleInfo {
    /// Returns a new [`ModuleInfo`] instantiated library path.
    pub fn new(path: Arc<Path>) -> Self {
        Self { path, items: Vec::new() }
    }

    /// Get a type resolver for this module
    pub fn type_resolver(&self) -> impl TypeResolver<LocalSymbolResolutionError> {
        ModuleInfoTypeResolver::new(self)
    }

    /// Get a local symbol resolver for this module
    pub fn resolver(&self) -> LocalSymbolResolver {
        LocalSymbolResolver::from(self)
    }

    /// Adds a procedure to the module.
    pub fn add_procedure(
        &mut self,
        name: ProcedureName,
        digest: Word,
        signature: Option<Arc<FunctionType>>,
        attributes: AttributeSet,
    ) {
        self.items
            .push(ItemInfo::Procedure(ProcedureInfo { name, digest, signature, attributes }));
    }

    /// Adds a constant to the module.
    pub fn add_constant(&mut self, name: Ident, value: ConstantExpr) {
        self.items.push(ItemInfo::Constant(ConstantInfo { name, value }));
    }

    /// Adds a type declaration to the module.
    pub fn add_type(&mut self, name: Ident, ty: ast::types::Type) {
        self.items.push(ItemInfo::Type(TypeInfo { name, ty }));
    }

    /// Returns the module's library path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the number of procedures in the module.
    pub fn num_procedures(&self) -> usize {
        self.items.iter().filter(|item| matches!(item, ItemInfo::Procedure(_))).count()
    }

    /// Returns the [`ItemInfo`] of the item at the provided index, if any.
    pub fn get_item_by_index(&self, index: ItemIndex) -> Option<&ItemInfo> {
        self.items.get(index.as_usize())
    }

    /// Returns the [ItemIndex] of an item by its local name
    pub fn get_item_index_by_name(&self, name: &str) -> Option<ItemIndex> {
        self.items.iter().enumerate().find_map(|(idx, info)| {
            if info.name().as_str() == name {
                Some(ItemIndex::new(idx))
            } else {
                None
            }
        })
    }

    /// Returns the digest of the procedure with the provided name, if any.
    pub fn get_procedure_digest_by_name(&self, name: &str) -> Option<Word> {
        self.items.iter().find_map(|info| match info {
            ItemInfo::Procedure(proc) if proc.name.as_str() == name => Some(proc.digest),
            _ => None,
        })
    }

    /// Returns an iterator over the items in the module with their corresponding item index in the
    /// module.
    pub fn items(&self) -> impl ExactSizeIterator<Item = (ItemIndex, &ItemInfo)> {
        self.items.iter().enumerate().map(|(idx, item)| (ItemIndex::new(idx), item))
    }

    /// Returns an iterator over the procedure infos in the module with their corresponding
    /// item index in the module.
    pub fn procedures(&self) -> impl Iterator<Item = (ItemIndex, &ProcedureInfo)> {
        self.items.iter().enumerate().filter_map(|(idx, item)| match item {
            ItemInfo::Procedure(proc) => Some((ItemIndex::new(idx), proc)),
            _ => None,
        })
    }

    /// Returns an iterator over the MAST roots of procedures defined in this module.
    pub fn procedure_digests(&self) -> impl Iterator<Item = Word> + '_ {
        self.items.iter().filter_map(|item| match item {
            ItemInfo::Procedure(proc) => Some(proc.digest),
            _ => None,
        })
    }

    /// Access the constants associated with this module
    pub fn constants(&self) -> impl Iterator<Item = (ItemIndex, &ConstantInfo)> {
        self.items.iter().enumerate().filter_map(|(idx, item)| match item {
            ItemInfo::Constant(info) => Some((ItemIndex::new(idx), info)),
            _ => None,
        })
    }

    /// Access the type declarations associated with this module
    pub fn types(&self) -> impl Iterator<Item = (ItemIndex, &TypeInfo)> {
        self.items.iter().enumerate().filter_map(|(idx, item)| match item {
            ItemInfo::Type(info) => Some((ItemIndex::new(idx), info)),
            _ => None,
        })
    }
}

impl Index<ItemIndex> for ModuleInfo {
    type Output = ItemInfo;

    fn index(&self, index: ItemIndex) -> &Self::Output {
        &self.items[index.as_usize()]
    }
}

/// Stores information about an item
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemInfo {
    Procedure(ProcedureInfo),
    Constant(ConstantInfo),
    Type(TypeInfo),
}

impl ItemInfo {
    pub fn name(&self) -> &Ident {
        match self {
            Self::Procedure(info) => info.name.as_ref(),
            Self::Constant(info) => &info.name,
            Self::Type(info) => &info.name,
        }
    }

    pub fn attributes(&self) -> Option<&AttributeSet> {
        match self {
            Self::Procedure(info) => Some(&info.attributes),
            Self::Constant(_) | Self::Type(_) => None,
        }
    }

    pub fn unwrap_procedure(&self) -> &ProcedureInfo {
        match self {
            Self::Procedure(info) => info,
            Self::Constant(_) | Self::Type(_) => panic!("expected item to be a procedure"),
        }
    }
}

/// Stores the name and digest of a procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureInfo {
    pub name: ProcedureName,
    pub digest: Word,
    pub signature: Option<Arc<FunctionType>>,
    pub attributes: AttributeSet,
}

/// Stores the name and value of a constant
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstantInfo {
    pub name: Ident,
    pub value: ConstantExpr,
}

/// Stores the name and concrete type of a type declaration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeInfo {
    pub name: Ident,
    pub ty: ast::types::Type,
}

struct ModuleInfoTypeResolver<'a> {
    module: &'a ModuleInfo,
    resolver: LocalSymbolResolver,
}

impl<'a> ModuleInfoTypeResolver<'a> {
    pub fn new(module: &'a ModuleInfo) -> Self {
        let resolver = module.resolver();
        Self { module, resolver }
    }
}

impl TypeResolver<LocalSymbolResolutionError> for ModuleInfoTypeResolver<'_> {
    fn get_type(
        &self,
        context: SourceSpan,
        _gid: GlobalItemIndex,
    ) -> Result<ast::types::Type, LocalSymbolResolutionError> {
        Err(LocalSymbolResolutionError::UndefinedSymbol { span: context })
    }
    fn get_local_type(
        &self,
        context: SourceSpan,
        id: ItemIndex,
    ) -> Result<Option<ast::types::Type>, LocalSymbolResolutionError> {
        let item = self.module.get_item_by_index(id).unwrap();
        match item {
            ItemInfo::Type(ty) => Ok(Some(ty.ty.clone())),
            item @ (ItemInfo::Constant(_) | ItemInfo::Procedure(_)) => Err(self
                .resolve_local_failed(LocalSymbolResolutionError::InvalidSymbolType {
                    expected: "type",
                    span: context,
                    actual: item.name().span(),
                })),
        }
    }
    #[inline(always)]
    fn resolve_local_failed(&self, err: LocalSymbolResolutionError) -> LocalSymbolResolutionError {
        err
    }
    fn resolve_type_ref(
        &self,
        path: Span<&Path>,
    ) -> Result<Option<SymbolResolution>, LocalSymbolResolutionError> {
        self.resolver.resolve_path(path)
    }
}
