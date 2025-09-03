mod basic_block_node;
use alloc::{boxed::Box, vec::Vec};
use core::fmt;

pub use basic_block_node::{
    BATCH_SIZE as OP_BATCH_SIZE, BasicBlockNode, GROUP_SIZE as OP_GROUP_SIZE, OpBatch,
    OperationOrDecorator,
};

mod call_node;
pub use call_node::CallNode;

mod dyn_node;
pub use dyn_node::DynNode;

mod external;
pub use external::ExternalNode;

mod join_node;
pub use join_node::JoinNode;

mod split_node;
use miden_crypto::{Felt, Word};
use miden_formatting::prettier::{Document, PrettyPrint};
pub use split_node::SplitNode;

mod loop_node;
pub use loop_node::LoopNode;

use super::{DecoratorId, MastForestError};
use crate::{
    AssemblyOp, Decorator, DecoratorList, Operation,
    mast::{MastForest, MastNodeId, Remapping},
};

// MAST NODE
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
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
/// Constructors
impl MastNode {
    pub fn new_basic_block(
        operations: Vec<Operation>,
        decorators: Option<DecoratorList>,
    ) -> Result<Self, MastForestError> {
        let block = BasicBlockNode::new(operations, decorators)?;
        Ok(Self::Block(block))
    }

    pub fn new_join(
        left_child: MastNodeId,
        right_child: MastNodeId,
        mast_forest: &MastForest,
    ) -> Result<Self, MastForestError> {
        let join = JoinNode::new([left_child, right_child], mast_forest)?;
        Ok(Self::Join(join))
    }

    pub fn new_split(
        if_branch: MastNodeId,
        else_branch: MastNodeId,
        mast_forest: &MastForest,
    ) -> Result<Self, MastForestError> {
        let split = SplitNode::new([if_branch, else_branch], mast_forest)?;
        Ok(Self::Split(split))
    }

    pub fn new_loop(body: MastNodeId, mast_forest: &MastForest) -> Result<Self, MastForestError> {
        let loop_node = LoopNode::new(body, mast_forest)?;
        Ok(Self::Loop(loop_node))
    }

    pub fn new_call(callee: MastNodeId, mast_forest: &MastForest) -> Result<Self, MastForestError> {
        let call = CallNode::new(callee, mast_forest)?;
        Ok(Self::Call(call))
    }

    pub fn new_syscall(
        callee: MastNodeId,
        mast_forest: &MastForest,
    ) -> Result<Self, MastForestError> {
        let syscall = CallNode::new_syscall(callee, mast_forest)?;
        Ok(Self::Call(syscall))
    }

    pub fn new_dyn() -> Self {
        Self::Dyn(DynNode::new_dyn())
    }
    pub fn new_dyncall() -> Self {
        Self::Dyn(DynNode::new_dyncall())
    }

    pub fn new_external(mast_root: Word) -> Self {
        Self::External(ExternalNode::new(mast_root))
    }

    #[cfg(test)]
    pub fn new_basic_block_with_raw_decorators(
        operations: Vec<Operation>,
        decorators: Vec<(usize, crate::Decorator)>,
        mast_forest: &mut MastForest,
    ) -> Result<Self, MastForestError> {
        let block = BasicBlockNode::new_with_raw_decorators(operations, decorators, mast_forest)?;
        Ok(Self::Block(block))
    }
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

    /// Remap the node children to their new positions indicated by the given [`Remapping`].
    pub fn remap_children(&self, remapping: &Remapping) -> Self {
        use MastNode::*;
        match self {
            Join(join_node) => Join(join_node.remap_children(remapping)),
            Split(split_node) => Split(split_node.remap_children(remapping)),
            Loop(loop_node) => Loop(loop_node.remap_children(remapping)),
            Call(call_node) => Call(call_node.remap_children(remapping)),
            Block(_) | Dyn(_) | External(_) => self.clone(),
        }
    }

    /// Returns true if the this node has children.
    pub fn has_children(&self) -> bool {
        match &self {
            MastNode::Join(_) | MastNode::Split(_) | MastNode::Loop(_) | MastNode::Call(_) => true,
            MastNode::Block(_) | MastNode::Dyn(_) | MastNode::External(_) => false,
        }
    }

    /// Appends the NodeIds of the children of this node, if any, to the vector.
    pub fn append_children_to(&self, target: &mut Vec<MastNodeId>) {
        match &self {
            MastNode::Join(join_node) => {
                target.push(join_node.first());
                target.push(join_node.second())
            },
            MastNode::Split(split_node) => {
                target.push(split_node.on_true());
                target.push(split_node.on_false())
            },
            MastNode::Loop(loop_node) => target.push(loop_node.body()),
            MastNode::Call(call_node) => target.push(call_node.callee()),
            MastNode::Block(_) | MastNode::Dyn(_) | MastNode::External(_) => (),
        }
    }

    pub fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> impl PrettyPrint + 'a {
        match self {
            MastNode::Block(basic_block_node) => {
                MastNodePrettyPrint::new(Box::new(basic_block_node.to_pretty_print(mast_forest)))
            },
            MastNode::Join(join_node) => {
                MastNodePrettyPrint::new(Box::new(join_node.to_pretty_print(mast_forest)))
            },
            MastNode::Split(split_node) => {
                MastNodePrettyPrint::new(Box::new(split_node.to_pretty_print(mast_forest)))
            },
            MastNode::Loop(loop_node) => {
                MastNodePrettyPrint::new(Box::new(loop_node.to_pretty_print(mast_forest)))
            },
            MastNode::Call(call_node) => {
                MastNodePrettyPrint::new(Box::new(call_node.to_pretty_print(mast_forest)))
            },
            MastNode::Dyn(dyn_node) => {
                MastNodePrettyPrint::new(Box::new(dyn_node.to_pretty_print(mast_forest)))
            },
            MastNode::External(external_node) => {
                MastNodePrettyPrint::new(Box::new(external_node.to_pretty_print(mast_forest)))
            },
        }
    }

    pub fn domain(&self) -> Felt {
        match self {
            MastNode::Block(_) => BasicBlockNode::DOMAIN,
            MastNode::Join(_) => JoinNode::DOMAIN,
            MastNode::Split(_) => SplitNode::DOMAIN,
            MastNode::Loop(_) => LoopNode::DOMAIN,
            MastNode::Call(call_node) => call_node.domain(),
            MastNode::Dyn(dyn_node) => dyn_node.domain(),
            MastNode::External(_) => panic!("Can't fetch domain for an `External` node."),
        }
    }

    pub fn digest(&self) -> Word {
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

    pub fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        match self {
            MastNode::Block(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
            MastNode::Join(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
            MastNode::Split(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
            MastNode::Loop(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
            MastNode::Call(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
            MastNode::Dyn(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
            MastNode::External(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
        }
    }

    /// Returns the decorators to be executed before this node is executed.
    pub fn before_enter(&self) -> &[DecoratorId] {
        use MastNode::*;
        match self {
            Block(_) => &[],
            Join(node) => node.before_enter(),
            Split(node) => node.before_enter(),
            Loop(node) => node.before_enter(),
            Call(node) => node.before_enter(),
            Dyn(node) => node.before_enter(),
            External(node) => node.before_enter(),
        }
    }

    /// Returns the decorators to be executed after this node is executed.
    pub fn after_exit(&self) -> &[DecoratorId] {
        use MastNode::*;
        match self {
            Block(_) => &[],
            Join(node) => node.after_exit(),
            Split(node) => node.after_exit(),
            Loop(node) => node.after_exit(),
            Call(node) => node.after_exit(),
            Dyn(node) => node.after_exit(),
            External(node) => node.after_exit(),
        }
    }
}

//-------------------------------------------------------------------------------------------------
/// Mutators
impl MastNode {
    /// Sets the list of decorators to be executed before this node.
    pub fn append_before_enter(&mut self, decorator_ids: &[DecoratorId]) {
        match self {
            MastNode::Block(node) => node.prepend_decorators(decorator_ids),
            MastNode::Join(node) => node.append_before_enter(decorator_ids),
            MastNode::Split(node) => node.append_before_enter(decorator_ids),
            MastNode::Loop(node) => node.append_before_enter(decorator_ids),
            MastNode::Call(node) => node.append_before_enter(decorator_ids),
            MastNode::Dyn(node) => node.append_before_enter(decorator_ids),
            MastNode::External(node) => node.append_before_enter(decorator_ids),
        }
    }

    /// Sets the list of decorators to be executed after this node.
    pub fn append_after_exit(&mut self, decorator_ids: &[DecoratorId]) {
        match self {
            MastNode::Block(node) => node.append_decorators(decorator_ids),
            MastNode::Join(node) => node.append_after_exit(decorator_ids),
            MastNode::Split(node) => node.append_after_exit(decorator_ids),
            MastNode::Loop(node) => node.append_after_exit(decorator_ids),
            MastNode::Call(node) => node.append_after_exit(decorator_ids),
            MastNode::Dyn(node) => node.append_after_exit(decorator_ids),
            MastNode::External(node) => node.append_after_exit(decorator_ids),
        }
    }

    pub fn remove_decorators(&mut self) {
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
}

// PRETTY PRINTING
// ================================================================================================

struct MastNodePrettyPrint<'a> {
    node_pretty_print: Box<dyn PrettyPrint + 'a>,
}

impl<'a> MastNodePrettyPrint<'a> {
    pub fn new(node_pretty_print: Box<dyn PrettyPrint + 'a>) -> Self {
        Self { node_pretty_print }
    }
}

impl PrettyPrint for MastNodePrettyPrint<'_> {
    fn render(&self) -> Document {
        self.node_pretty_print.render()
    }
}

struct MastNodeDisplay<'a> {
    node_display: Box<dyn fmt::Display + 'a>,
}

impl<'a> MastNodeDisplay<'a> {
    pub fn new(node: impl fmt::Display + 'a) -> Self {
        Self { node_display: Box::new(node) }
    }
}

impl fmt::Display for MastNodeDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.node_display.fmt(f)
    }
}

// MAST INNER NODE EXT
// ===============================================================================================

/// A trait for extending the functionality of all [`MastNode`]s.
pub trait MastNodeExt: Send + Sync {
    // REQUIRED METHODS
    // -------------------------------------------------------------------------------------------

    /// The list of decorators tied to this node, along with their associated index.
    ///
    /// The index is only meaningful for [`BasicBlockNode`]s, where it corresponds to the index of
    /// the operation in the basic block to which the decorator is attached.
    fn decorators(&self) -> impl Iterator<Item = (usize, DecoratorId)>;

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
