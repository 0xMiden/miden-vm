mod basic_block_node;
use alloc::{boxed::Box, vec::Vec};
use core::fmt;

pub use basic_block_node::{
    BATCH_SIZE as OP_BATCH_SIZE, BasicBlockNode, BasicBlockNodeBuilder, DecoratorOpLinkIterator,
    GROUP_SIZE as OP_GROUP_SIZE, OpBatch, OperationOrDecorator,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod call_node;
pub use call_node::{CallNode, CallNodeBuilder};

mod dyn_node;
pub use dyn_node::{DynNode, DynNodeBuilder};

mod external;
pub use external::{ExternalNode, ExternalNodeBuilder};

mod join_node;
pub use join_node::{JoinNode, JoinNodeBuilder};

mod split_node;
use miden_crypto::{Felt, Word};
use miden_formatting::prettier::PrettyPrint;
pub use split_node::{SplitNode, SplitNodeBuilder};

mod loop_node;
#[cfg(any(test, feature = "arbitrary"))]
pub use basic_block_node::arbitrary;
pub use loop_node::{LoopNode, LoopNodeBuilder};

mod mast_forest_contributor;
pub use mast_forest_contributor::{MastForestContributor, MastNodeBuilder};

use super::DecoratorId;
use crate::{
    AssemblyOp, Decorator,
    mast::{MastForest, MastNodeId, Remapping},
};

pub trait MastNodeExt {
    /// Returns a commitment/hash of the node.
    fn digest(&self) -> Word;

    /// Returns the decorators to be executed before this node is executed.
    fn before_enter(&self) -> &[DecoratorId];

    /// Returns the decorators to be executed after this node is executed.
    fn after_exit(&self) -> &[DecoratorId];

    /// Sets the list of decorators to be executed before this node.
    fn append_before_enter(&mut self, decorator_ids: &[DecoratorId]);

    /// Sets the list of decorators to be executed after this node.
    fn append_after_exit(&mut self, decorator_ids: &[DecoratorId]);

    /// Removes all decorators from this node.
    fn remove_decorators(&mut self);

    /// Returns a display formatter for this node.
    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a>;

    /// Returns a pretty printer for this node.
    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a>;

    /// Remap the node children to their new positions indicated by the given [`Remapping`].
    fn remap_children(&self, remapping: &Remapping) -> Self;

    /// Returns true if the this node has children.
    fn has_children(&self) -> bool;

    /// Appends the NodeIds of the children of this node, if any, to the vector.
    fn append_children_to(&self, target: &mut Vec<MastNodeId>);

    /// Executes the given closure for each child of this node.
    fn for_each_child<F>(&self, f: F)
    where
        F: FnMut(MastNodeId);

    /// Returns the domain of this node.
    fn domain(&self) -> Felt;

    /// Converts this node into its corresponding builder, reusing allocated data where possible.
    type Builder: MastForestContributor;

    fn to_builder(self) -> Self::Builder;
}

// MAST NODE
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MastNode {
    Block(BasicBlockNode),
    Join(JoinNode),
    Split(SplitNode),
    Loop(LoopNode),
    Call(CallNode),
    Dyn(DynNode),
    External(ExternalNode),
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl MastNode {
    /// Returns true if this node is an external node.
    pub fn is_external(&self) -> bool {
        matches!(self, MastNode::External(_))
    }

    /// Returns true if this node is a Dyn node.
    pub fn is_dyn(&self) -> bool {
        matches!(self, MastNode::Dyn(_))
    }

    /// Returns true if this node is a basic block.
    pub fn is_basic_block(&self) -> bool {
        matches!(self, Self::Block(_))
    }

    /// Returns the inner basic block node if the [`MastNode`] wraps a [`BasicBlockNode`]; `None`
    /// otherwise.
    pub fn get_basic_block(&self) -> Option<&BasicBlockNode> {
        match self {
            MastNode::Block(basic_block_node) => Some(basic_block_node),
            _ => None,
        }
    }

    /// Unwraps the inner basic block node if the [`MastNode`] wraps a [`BasicBlockNode`]; panics
    /// otherwise.
    ///
    /// # Panics
    /// Panics if the [`MastNode`] does not wrap a [`BasicBlockNode`].
    pub fn unwrap_basic_block(&self) -> &BasicBlockNode {
        match self {
            Self::Block(basic_block_node) => basic_block_node,
            other => unwrap_failed(other, "basic block"),
        }
    }

    /// Unwraps the inner join node if the [`MastNode`] wraps a [`JoinNode`]; panics otherwise.
    ///
    /// # Panics
    /// - if the [`MastNode`] does not wrap a [`JoinNode`].
    pub fn unwrap_join(&self) -> &JoinNode {
        match self {
            Self::Join(join_node) => join_node,
            other => unwrap_failed(other, "join"),
        }
    }

    /// Unwraps the inner split node if the [`MastNode`] wraps a [`SplitNode`]; panics otherwise.
    ///
    /// # Panics
    /// - if the [`MastNode`] does not wrap a [`SplitNode`].
    pub fn unwrap_split(&self) -> &SplitNode {
        match self {
            Self::Split(split_node) => split_node,
            other => unwrap_failed(other, "split"),
        }
    }

    /// Unwraps the inner loop node if the [`MastNode`] wraps a [`LoopNode`]; panics otherwise.
    ///
    /// # Panics
    /// - if the [`MastNode`] does not wrap a [`LoopNode`].
    pub fn unwrap_loop(&self) -> &LoopNode {
        match self {
            Self::Loop(loop_node) => loop_node,
            other => unwrap_failed(other, "loop"),
        }
    }

    /// Unwraps the inner call node if the [`MastNode`] wraps a [`CallNode`]; panics otherwise.
    ///
    /// # Panics
    /// - if the [`MastNode`] does not wrap a [`CallNode`].
    pub fn unwrap_call(&self) -> &CallNode {
        match self {
            Self::Call(call_node) => call_node,
            other => unwrap_failed(other, "call"),
        }
    }

    /// Unwraps the inner dynamic node if the [`MastNode`] wraps a [`DynNode`]; panics otherwise.
    ///
    /// # Panics
    /// - if the [`MastNode`] does not wrap a [`DynNode`].
    pub fn unwrap_dyn(&self) -> &DynNode {
        match self {
            Self::Dyn(dyn_node) => dyn_node,
            other => unwrap_failed(other, "dyn"),
        }
    }

    /// Unwraps the inner external node if the [`MastNode`] wraps a [`ExternalNode`]; panics
    /// otherwise.
    ///
    /// # Panics
    /// - if the [`MastNode`] does not wrap a [`ExternalNode`].
    pub fn unwrap_external(&self) -> &ExternalNode {
        match self {
            Self::External(external_node) => external_node,
            other => unwrap_failed(other, "external"),
        }
    }
}

// Manual implementation of MastNodeExt for MastNode
// TODO: This should be replaced with a proc-macro.
// enum_dispatch doesn't support associated types yet : https://gitlab.com/antonok/enum_dispatch/-/issues/50
// but there's no reason this can't be macro-generated at all.
impl MastNodeExt for MastNode {
    type Builder = MastNodeBuilder;

    fn digest(&self) -> Word {
        match self {
            MastNode::Block(node) => node.digest(),
            MastNode::Join(node) => node.digest(),
            MastNode::Split(node) => node.digest(),
            MastNode::Loop(node) => node.digest(),
            MastNode::Call(node) => node.digest(),
            MastNode::Dyn(node) => node.digest(),
            MastNode::External(node) => node.digest(),
        }
    }

    fn before_enter(&self) -> &[DecoratorId] {
        match self {
            MastNode::Block(node) => node.before_enter(),
            MastNode::Join(node) => node.before_enter(),
            MastNode::Split(node) => node.before_enter(),
            MastNode::Loop(node) => node.before_enter(),
            MastNode::Call(node) => node.before_enter(),
            MastNode::Dyn(node) => node.before_enter(),
            MastNode::External(node) => node.before_enter(),
        }
    }

    fn after_exit(&self) -> &[DecoratorId] {
        match self {
            MastNode::Block(node) => node.after_exit(),
            MastNode::Join(node) => node.after_exit(),
            MastNode::Split(node) => node.after_exit(),
            MastNode::Loop(node) => node.after_exit(),
            MastNode::Call(node) => node.after_exit(),
            MastNode::Dyn(node) => node.after_exit(),
            MastNode::External(node) => node.after_exit(),
        }
    }

    fn append_before_enter(&mut self, decorator_ids: &[DecoratorId]) {
        match self {
            MastNode::Block(node) => node.append_before_enter(decorator_ids),
            MastNode::Join(node) => node.append_before_enter(decorator_ids),
            MastNode::Split(node) => node.append_before_enter(decorator_ids),
            MastNode::Loop(node) => node.append_before_enter(decorator_ids),
            MastNode::Call(node) => node.append_before_enter(decorator_ids),
            MastNode::Dyn(node) => node.append_before_enter(decorator_ids),
            MastNode::External(node) => node.append_before_enter(decorator_ids),
        }
    }

    fn append_after_exit(&mut self, decorator_ids: &[DecoratorId]) {
        match self {
            MastNode::Block(node) => node.append_after_exit(decorator_ids),
            MastNode::Join(node) => node.append_after_exit(decorator_ids),
            MastNode::Split(node) => node.append_after_exit(decorator_ids),
            MastNode::Loop(node) => node.append_after_exit(decorator_ids),
            MastNode::Call(node) => node.append_after_exit(decorator_ids),
            MastNode::Dyn(node) => node.append_after_exit(decorator_ids),
            MastNode::External(node) => node.append_after_exit(decorator_ids),
        }
    }

    fn remove_decorators(&mut self) {
        match self {
            MastNode::Block(node) => node.remove_decorators(),
            MastNode::Join(node) => node.remove_decorators(),
            MastNode::Split(node) => node.remove_decorators(),
            MastNode::Loop(node) => node.remove_decorators(),
            MastNode::Call(node) => node.remove_decorators(),
            MastNode::Dyn(node) => node.remove_decorators(),
            MastNode::External(node) => node.remove_decorators(),
        }
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        match self {
            MastNode::Block(node) => Box::new(node.to_display(mast_forest)),
            MastNode::Join(node) => Box::new(node.to_display(mast_forest)),
            MastNode::Split(node) => Box::new(node.to_display(mast_forest)),
            MastNode::Loop(node) => Box::new(node.to_display(mast_forest)),
            MastNode::Call(node) => Box::new(node.to_display(mast_forest)),
            MastNode::Dyn(node) => Box::new(node.to_display(mast_forest)),
            MastNode::External(node) => Box::new(node.to_display(mast_forest)),
        }
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        match self {
            MastNode::Block(node) => Box::new(node.to_pretty_print(mast_forest)),
            MastNode::Join(node) => Box::new(node.to_pretty_print(mast_forest)),
            MastNode::Split(node) => Box::new(node.to_pretty_print(mast_forest)),
            MastNode::Loop(node) => Box::new(node.to_pretty_print(mast_forest)),
            MastNode::Call(node) => Box::new(node.to_pretty_print(mast_forest)),
            MastNode::Dyn(node) => Box::new(node.to_pretty_print(mast_forest)),
            MastNode::External(node) => Box::new(node.to_pretty_print(mast_forest)),
        }
    }

    fn remap_children(&self, remapping: &Remapping) -> Self {
        match self {
            MastNode::Block(node) => MastNode::Block(node.remap_children(remapping)),
            MastNode::Join(node) => MastNode::Join(node.remap_children(remapping)),
            MastNode::Split(node) => MastNode::Split(node.remap_children(remapping)),
            MastNode::Loop(node) => MastNode::Loop(node.remap_children(remapping)),
            MastNode::Call(node) => MastNode::Call(node.remap_children(remapping)),
            MastNode::Dyn(node) => MastNode::Dyn(node.remap_children(remapping)),
            MastNode::External(node) => MastNode::External(node.remap_children(remapping)),
        }
    }

    fn has_children(&self) -> bool {
        match self {
            MastNode::Block(node) => node.has_children(),
            MastNode::Join(node) => node.has_children(),
            MastNode::Split(node) => node.has_children(),
            MastNode::Loop(node) => node.has_children(),
            MastNode::Call(node) => node.has_children(),
            MastNode::Dyn(node) => node.has_children(),
            MastNode::External(node) => node.has_children(),
        }
    }

    fn append_children_to(&self, target: &mut Vec<MastNodeId>) {
        match self {
            MastNode::Block(node) => node.append_children_to(target),
            MastNode::Join(node) => node.append_children_to(target),
            MastNode::Split(node) => node.append_children_to(target),
            MastNode::Loop(node) => node.append_children_to(target),
            MastNode::Call(node) => node.append_children_to(target),
            MastNode::Dyn(node) => node.append_children_to(target),
            MastNode::External(node) => node.append_children_to(target),
        }
    }

    fn for_each_child<F>(&self, f: F)
    where
        F: FnMut(MastNodeId),
    {
        match self {
            MastNode::Block(node) => node.for_each_child(f),
            MastNode::Join(node) => node.for_each_child(f),
            MastNode::Split(node) => node.for_each_child(f),
            MastNode::Loop(node) => node.for_each_child(f),
            MastNode::Call(node) => node.for_each_child(f),
            MastNode::Dyn(node) => node.for_each_child(f),
            MastNode::External(node) => node.for_each_child(f),
        }
    }

    fn domain(&self) -> Felt {
        match self {
            MastNode::Block(node) => node.domain(),
            MastNode::Join(node) => node.domain(),
            MastNode::Split(node) => node.domain(),
            MastNode::Loop(node) => node.domain(),
            MastNode::Call(node) => node.domain(),
            MastNode::Dyn(node) => node.domain(),
            MastNode::External(node) => node.domain(),
        }
    }

    fn to_builder(self) -> Self::Builder {
        match self {
            MastNode::Block(node) => MastNodeBuilder::BasicBlock(node.to_builder()),
            MastNode::Join(node) => MastNodeBuilder::Join(node.to_builder()),
            MastNode::Split(node) => MastNodeBuilder::Split(node.to_builder()),
            MastNode::Loop(node) => MastNodeBuilder::Loop(node.to_builder()),
            MastNode::Call(node) => MastNodeBuilder::Call(node.to_builder()),
            MastNode::Dyn(node) => MastNodeBuilder::Dyn(node.to_builder()),
            MastNode::External(node) => MastNodeBuilder::External(node.to_builder()),
        }
    }
}

// From implementations for converting individual node types to MastNode
impl From<BasicBlockNode> for MastNode {
    fn from(node: BasicBlockNode) -> Self {
        MastNode::Block(node)
    }
}

impl From<JoinNode> for MastNode {
    fn from(node: JoinNode) -> Self {
        MastNode::Join(node)
    }
}

impl From<SplitNode> for MastNode {
    fn from(node: SplitNode) -> Self {
        MastNode::Split(node)
    }
}

impl From<LoopNode> for MastNode {
    fn from(node: LoopNode) -> Self {
        MastNode::Loop(node)
    }
}

impl From<CallNode> for MastNode {
    fn from(node: CallNode) -> Self {
        MastNode::Call(node)
    }
}

impl From<DynNode> for MastNode {
    fn from(node: DynNode) -> Self {
        MastNode::Dyn(node)
    }
}

impl From<ExternalNode> for MastNode {
    fn from(node: ExternalNode) -> Self {
        MastNode::External(node)
    }
}

// MAST INNER NODE EXT
// ===============================================================================================

/// A trait for extending the functionality of all [`MastNode`]s.
pub trait MastNodeErrorContext: Send + Sync {
    // REQUIRED METHODS
    // -------------------------------------------------------------------------------------------

    /// The list of decorators tied to this node, along with their associated index.
    ///
    /// The index is only meaningful for [`BasicBlockNode`]s, where it corresponds to the index of
    /// the operation in the basic block to which the decorator is attached.
    fn decorators(&self) -> impl Iterator<Item = DecoratedOpLink>;

    // PROVIDED METHODS
    // -------------------------------------------------------------------------------------------

    /// Returns the [`AssemblyOp`] associated with this node and operation (if provided), if any.
    ///
    /// If the `target_op_idx` is provided, the method treats the wrapped node as a basic block will
    /// return the assembly op associated with the operation at the corresponding index in the basic
    /// block. If no `target_op_idx` is provided, the method will return the first assembly op found
    /// (effectively assuming that the node has at most one associated [`AssemblyOp`]).
    fn get_assembly_op<'m>(
        &self,
        mast_forest: &'m MastForest,
        target_op_idx: Option<usize>,
    ) -> Option<&'m AssemblyOp> {
        match target_op_idx {
            // If a target operation index is provided, return the assembly op associated with that
            // operation.
            Some(target_op_idx) => {
                for (op_idx, decorator_id) in self.decorators() {
                    if let Some(Decorator::AsmOp(assembly_op)) =
                        mast_forest.get_decorator_by_id(decorator_id)
                    {
                        // when an instruction compiles down to multiple operations, only the first
                        // operation is associated with the assembly op. We need to check if the
                        // target operation index falls within the range of operations associated
                        // with the assembly op.
                        if target_op_idx >= op_idx
                            && target_op_idx < op_idx + assembly_op.num_cycles() as usize
                        {
                            return Some(assembly_op);
                        }
                    }
                }
            },
            // If no target operation index is provided, return the first assembly op found.
            None => {
                for (_, decorator_id) in self.decorators() {
                    if let Some(Decorator::AsmOp(assembly_op)) =
                        mast_forest.get_decorator_by_id(decorator_id)
                    {
                        return Some(assembly_op);
                    }
                }
            },
        }

        None
    }
}

// Links an operation index in a block to a decoratorid, to be executed right before this
// operation's position
pub type DecoratedOpLink = (usize, DecoratorId);

// HELPERS
// ===============================================================================================

/// This function is analogous to the `unwrap_failed()` function used in the implementation of
/// `core::result::Result` `unwrap_*()` methods.
#[cold]
#[inline(never)]
#[track_caller]
fn unwrap_failed(node: &MastNode, expected: &str) -> ! {
    let actual = match node {
        MastNode::Block(_) => "basic block",
        MastNode::Join(_) => "join",
        MastNode::Split(_) => "split",
        MastNode::Loop(_) => "loop",
        MastNode::Call(_) => "call",
        MastNode::Dyn(_) => "dynamic",
        MastNode::External(_) => "external",
    };
    panic!("tried to unwrap {expected} node, but got {actual}");
}
