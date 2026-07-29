//! Abstract syntax tree (AST) components of Miden programs, modules, and procedures.

mod advice_map_entry;
mod attribute;
mod block;
pub mod constants;
mod docstring;
mod form;
pub(crate) mod ident;
mod immediate;
mod import;
mod instruction;
mod invocation_target;
mod item;
mod module;
mod op;
pub mod path;
mod procedure;
#[cfg(test)]
mod tests;
mod r#type;
mod visibility;
pub mod visit;

pub use self::{
    advice_map_entry::AdviceMapEntry,
    attribute::{
        Attribute, AttributeSet, AttributeSetEntry, BorrowedMeta, Meta, MetaExpr, MetaItem,
        MetaKeyValue, MetaList,
    },
    block::Block,
    constants::{Constant, ConstantExpr, ConstantOp, ConstantValue, HashKind},
    docstring::DocString,
    form::Form,
    ident::{CaseKindError, Ident, IdentError},
    immediate::{ErrorMsg, ImmFelt, ImmU8, ImmU16, ImmU32, Immediate},
    import::{
        Import, ImportDecl, ImportKind, ImportSpec, ItemImport, ItemImportGroup, ModuleImport,
    },
    instruction::{DebugVarInfo, DebugVarLocation, Instruction, SystemEventNode},
    invocation_target::{InvocationTarget, Invoke, InvokeKind},
    item::*,
    module::{Module, ModuleKind},
    op::Op,
    path::{Path, PathBuf, PathComponent, PathError},
    procedure::*,
    r#type::*,
    visibility::Visibility,
    visit::{Visit, VisitMut},
};

/// Maximum stack index at which a full word can start.
pub const MAX_STACK_WORD_OFFSET: u8 = 12;
