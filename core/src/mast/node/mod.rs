mod basic_block_node;
use alloc::{boxed::Box, vec::Vec};
use core::fmt;

pub use basic_block_node::{
    BATCH_SIZE as OP_BATCH_SIZE, BasicBlockNode, BasicBlockNodeBuilder, DecoratorOpLinkIterator,
    GROUP_SIZE as OP_GROUP_SIZE, OpBatch, OperationOrDecorator,
};
use derive_more::From;
use miden_utils_core_derive::MastNodeExt;

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

mod decorator_store;
pub use decorator_store::DecoratorStore;

use super::DecoratorId;
use crate::{
    AssemblyOp, Decorator,
    mast::{MastForest, MastNodeId},
};

pub trait MastNodeExt {
    /// Returns a commitment/hash of the node.
    fn digest(&self) -> Word;

    /// Returns the decorators to be executed before this node is executed.
    fn before_enter<'a>(&'a self, forest: &'a MastForest) -> &'a [DecoratorId];

    /// Returns the decorators to be executed after this node is executed.
    fn after_exit<'a>(&'a self, forest: &'a MastForest) -> &'a [DecoratorId];

    /// Removes all decorators from this node.
    fn remove_decorators(&mut self);

    /// Returns a display formatter for this node.
    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a>;

    /// Returns a pretty printer for this node.
    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a>;

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

    fn to_builder(self, forest: &MastForest) -> Self::Builder;
}

// MAST NODE
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq, From, MastNodeExt)]
#[mast_node_ext(builder = "MastNodeBuilder")]
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
    fn decorators<'a>(
        &'a self,
        forest: &'a MastForest,
    ) -> impl Iterator<Item = DecoratedOpLink> + 'a;

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
                for (op_idx, decorator_id) in self.decorators(mast_forest) {
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
                for (_, decorator_id) in self.decorators(mast_forest) {
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
