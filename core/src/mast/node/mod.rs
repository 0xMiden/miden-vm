mod basic_block_node;
use alloc::{boxed::Box, string::ToString, vec::Vec};
use core::fmt;

pub use basic_block_node::{
    BasicBlockNode, OpBatch, OperationOrDecorator, BATCH_SIZE as OP_BATCH_SIZE,
    GROUP_SIZE as OP_GROUP_SIZE,
};
use num_traits::ToBytes;

mod call_node;
pub use call_node::CallNode;

mod dyn_node;
pub use dyn_node::DynNode;

mod external;
pub use external::ExternalNode;

mod join_node;
pub use join_node::JoinNode;

mod split_node;
use miden_crypto::{
    hash::{
        blake::{Blake3Digest, Blake3_256},
        rpo::RpoDigest,
    },
    Felt,
};
use miden_formatting::prettier::{Document, PrettyPrint};
pub use split_node::SplitNode;

mod loop_node;
pub use loop_node::LoopNode;

use super::{DecoratorId, MastForestError};
use crate::{
    mast::{MastForest, MastNodeId},
    Decorator, DecoratorList, Operation,
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
        Self::Dyn(DynNode::default())
    }

    pub fn new_external(mast_root: RpoDigest) -> Self {
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

    pub fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> impl PrettyPrint + 'a {
        match self {
            MastNode::Block(basic_block_node) => {
                MastNodePrettyPrint::new(Box::new(basic_block_node))
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
            MastNode::Dyn(dyn_node) => MastNodePrettyPrint::new(Box::new(dyn_node)),
            MastNode::External(external_node) => MastNodePrettyPrint::new(Box::new(external_node)),
        }
    }

    pub fn domain(&self) -> Felt {
        match self {
            MastNode::Block(_) => BasicBlockNode::DOMAIN,
            MastNode::Join(_) => JoinNode::DOMAIN,
            MastNode::Split(_) => SplitNode::DOMAIN,
            MastNode::Loop(_) => LoopNode::DOMAIN,
            MastNode::Call(call_node) => call_node.domain(),
            MastNode::Dyn(_) => DynNode::DOMAIN,
            MastNode::External(_) => panic!("Can't fetch domain for an `External` node."),
        }
    }

    pub fn digest(&self) -> RpoDigest {
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
            MastNode::Block(node) => MastNodeDisplay::new(node),
            MastNode::Join(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
            MastNode::Split(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
            MastNode::Loop(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
            MastNode::Call(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
            MastNode::Dyn(node) => MastNodeDisplay::new(node),
            MastNode::External(node) => MastNodeDisplay::new(node.to_display(mast_forest)),
        }
    }

    /// Returns the Blake3 hash of this node, to be used for equality testing.
    ///
    /// Specifically, two nodes with the same MAST root but different decorators will have a
    /// different hash.
    pub fn eq_hash(&self) -> Blake3Digest<32> {
        match self {
            MastNode::Block(node) => {
                let mut bytes_to_hash = node.digest().as_bytes().to_vec();

                for (idx, decorator) in node.decorators() {
                    bytes_to_hash.extend(idx.to_le_bytes());

                    match decorator {
                        Decorator::Advice(advice) => {
                            bytes_to_hash.extend(advice.to_string().as_bytes())
                        },
                        Decorator::AsmOp(asm_op) => {
                            bytes_to_hash.extend(asm_op.context_name().as_bytes());
                            bytes_to_hash.extend(asm_op.op().as_bytes());
                            bytes_to_hash.push(asm_op.num_cycles());
                        },
                        Decorator::Debug(debug) => {
                            bytes_to_hash.extend(debug.to_string().as_bytes())
                        },
                        Decorator::Event(event) => {
                            bytes_to_hash.extend(event.to_le_bytes());
                        },
                        Decorator::Trace(trace) => {
                            bytes_to_hash.extend(trace.to_le_bytes());
                        },
                    }
                }

                Blake3_256::hash(&bytes_to_hash)
            },
            MastNode::Join(node) => Blake3_256::hash(&node.digest().as_bytes()),
            MastNode::Split(node) => Blake3_256::hash(&node.digest().as_bytes()),
            MastNode::Loop(node) => Blake3_256::hash(&node.digest().as_bytes()),
            MastNode::Call(node) => Blake3_256::hash(&node.digest().as_bytes()),
            MastNode::Dyn(node) => Blake3_256::hash(&node.digest().as_bytes()),
            MastNode::External(node) => Blake3_256::hash(&node.digest().as_bytes()),
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

/// Mutators
impl MastNode {
    pub fn set_before_enter(&mut self, decorator_ids: Vec<DecoratorId>) {
        todo!()
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

impl<'a> PrettyPrint for MastNodePrettyPrint<'a> {
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

impl<'a> fmt::Display for MastNodeDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.node_display.fmt(f)
    }
}
