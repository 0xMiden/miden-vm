use alloc::vec::Vec;
use core::fmt;

use miden_core::{
    Word,
    mast::{MastNode, OpBatch},
    utils::Idx,
};

/// Content-equivalence key used while interning pending MAST nodes.
///
/// In the decorator-free model this is the MAST root. It remains distinct from [`MastNodeRef`],
/// which is a builder-local handle, and [`MastNodeId`], which is a final forest position.
pub(super) type MastNodeKey = Word;

/// Stable assembly-time reference to a MAST node.
///
/// This is a builder-local dense arena handle, not a positional [`MastNodeId`] in the final
/// [`miden_core::mast::MastForest`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub(crate) struct MastNodeRef(u32);

impl From<u32> for MastNodeRef {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<MastNodeRef> for u32 {
    fn from(value: MastNodeRef) -> Self {
        value.0
    }
}

impl fmt::Display for MastNodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MastNodeRef({})", self.0)
    }
}

impl Idx for MastNodeRef {}

/// Stable assembly-time reference to a source/debug occurrence of a MAST node.
///
/// Multiple source occurrences may point at the same [`MastNodeRef`] when they have identical
/// execution content but distinct source metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub(crate) struct SourceNodeRef(u32);

impl From<u32> for SourceNodeRef {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SourceNodeRef> for u32 {
    fn from(value: SourceNodeRef) -> Self {
        value.0
    }
}

impl fmt::Display for SourceNodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SourceNodeRef({})", self.0)
    }
}

impl Idx for SourceNodeRef {}

/// Stable assembly-time reference to assembly operation metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub(crate) struct AsmOpRef(u32);

impl From<u32> for AsmOpRef {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<AsmOpRef> for u32 {
    fn from(value: AsmOpRef) -> Self {
        value.0
    }
}

impl Idx for AsmOpRef {}

/// Stable assembly-time reference to debug variable metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub(crate) struct DebugVarRef(u32);

impl From<u32> for DebugVarRef {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<DebugVarRef> for u32 {
    fn from(value: DebugVarRef) -> Self {
        value.0
    }
}

impl Idx for DebugVarRef {}

/// Builder-owned node record used before final [`MastNodeId`]s exist.
///
/// The record keeps the node content, child refs, and debug metadata refs together so
/// cloning, merging, and finalization do not need to coordinate side tables.
#[derive(Clone, Debug)]
pub(super) struct PendingMastNode {
    pub(super) key: MastNodeKey,
    pub(super) digest: Word,
    pub(super) kind: PendingMastNodeKind,
    pub(super) child_refs: Vec<MastNodeRef>,
    pub(super) asm_ops: Vec<(usize, AsmOpRef)>,
    pub(super) debug_vars: Vec<(usize, DebugVarRef)>,
}

/// Builder-owned source/debug occurrence record used before final source IDs exist.
#[derive(Clone, Debug)]
pub(super) struct PendingSourceNode {
    pub(super) exec_ref: MastNodeRef,
    pub(super) child_refs: Vec<SourceNodeRef>,
    pub(super) op_start: usize,
    pub(super) op_end: usize,
    pub(super) asm_ops: Vec<(usize, AsmOpRef)>,
    pub(super) debug_vars: Vec<(usize, DebugVarRef)>,
}

/// Compact representation of a pending node's structural variant.
///
/// Child and metadata references live on [`PendingMastNode`]; this enum stores only the data
/// needed to materialize the final node variant.
#[derive(Clone, Debug)]
pub(super) enum PendingMastNodeKind {
    BasicBlock { op_batches: Vec<OpBatch> },
    Join,
    Split,
    Loop,
    Call { is_syscall: bool },
    Dyn { is_dyncall: bool },
    External,
}

impl PendingMastNodeKind {
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::BasicBlock { .. } => "basic block",
            Self::Join => "join",
            Self::Split => "split",
            Self::Loop => "loop",
            Self::Call { .. } => "call",
            Self::Dyn { .. } => "dyn",
            Self::External => "external",
        }
    }

    pub(super) fn from_node(node: MastNode) -> Self {
        match node {
            MastNode::Block(node) => Self::BasicBlock { op_batches: node.op_batches().to_vec() },
            MastNode::Join(_) => Self::Join,
            MastNode::Split(_) => Self::Split,
            MastNode::Loop(_) => Self::Loop,
            MastNode::Call(node) => Self::Call { is_syscall: node.is_syscall() },
            MastNode::Dyn(node) => Self::Dyn { is_dyncall: node.is_dyncall() },
            MastNode::External(_) => Self::External,
        }
    }

    pub(super) fn basic_block_op_batches(&self) -> Option<&[OpBatch]> {
        match self {
            Self::BasicBlock { op_batches } => Some(op_batches),
            _ => None,
        }
    }

    pub(super) fn is_basic_block(&self) -> bool {
        matches!(self, Self::BasicBlock { .. })
    }

    pub(super) fn is_external(&self) -> bool {
        matches!(self, Self::External)
    }
}

/// Mutable node record used while deriving a new pending node from an existing one.
///
/// A draft becomes immutable once it is interned as a [`PendingMastNode`].
#[derive(Clone)]
pub(super) struct PendingMastNodeDraft {
    pub(super) digest: Word,
    pub(super) kind: PendingMastNodeKind,
    pub(super) child_refs: Vec<MastNodeRef>,
    pub(super) asm_ops: Vec<(usize, AsmOpRef)>,
    pub(super) debug_vars: Vec<(usize, DebugVarRef)>,
}

impl PendingMastNodeDraft {
    pub(super) fn new(
        kind: PendingMastNodeKind,
        digest: Word,
        child_refs: Vec<MastNodeRef>,
    ) -> Self {
        Self {
            digest,
            kind,
            child_refs,
            asm_ops: Vec::new(),
            debug_vars: Vec::new(),
        }
    }
}
