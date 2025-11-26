//! Abstract syntax tree (AST) components of Miden programs, modules, and procedures.

mod advice_map_entry;
mod alias;
mod attribute;
mod block;
mod constants;
mod docstring;
mod form;
pub(crate) mod ident;
mod immediate;
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
    alias::{Alias, AliasTarget},
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
    instruction::{DebugOptions, Instruction, SystemEventNode},
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

pub(crate) type SmallOpsVec = smallvec::SmallVec<[Op; 1]>;

/// Maximum stack index at which a full word can start.
pub const MAX_STACK_WORD_OFFSET: u8 = 12;
