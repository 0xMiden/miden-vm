use alloc::vec::Vec;

use super::{NodeDataOffset, basic_blocks::BasicBlockDataDecoder, read_u32_varint};
use crate::{
    mast::{
        MastForestContributor, MastNode, MastNodeId, Word,
        node::{MastNodeBuilder, MastNodeExt},
    },
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// MAST NODE INFO
// ================================================================================================

/// Represents a serialized [`MastNode`], with some data inlined in its [`MastNodeType`].
#[derive(Debug)]
pub struct MastNodeInfo {
    ty: MastNodeType,
    digest: Word,
}

impl MastNodeInfo {
    /// Constructs a new [`MastNodeInfo`] from a [`MastNode`], along with an `ops_offset`
    ///
    /// For non-basic block nodes, `ops_offset` is ignored, and should be set to 0.
    pub fn new(mast_node: &MastNode, ops_offset: NodeDataOffset) -> Self {
        if !matches!(mast_node, &MastNode::Block(_)) {
            debug_assert_eq!(ops_offset, 0);
        }

        let ty = MastNodeType::new(mast_node, ops_offset);

        Self { ty, digest: mast_node.digest() }
    }

    /// Attempts to convert this [`MastNodeInfo`] into a [`MastNodeBuilder`].
    ///
    /// The `node_count` is the total expected number of nodes in the [`MastForest`] **after
    /// deserialization**.
    pub fn try_into_mast_node_builder(
        self,
        node_count: usize,
        basic_block_data_decoder: &BasicBlockDataDecoder,
    ) -> Result<MastNodeBuilder, DeserializationError> {
        match self.ty {
            MastNodeType::Block { ops_offset } => {
                let op_batches = basic_block_data_decoder.decode_operations(ops_offset)?;
                let builder = crate::mast::node::BasicBlockNodeBuilder::from_op_batches(
                    op_batches,
                    Vec::new(), // decorators set later
                    self.digest,
                );
                Ok(MastNodeBuilder::BasicBlock(builder))
            },
            MastNodeType::Join { left_child_id, right_child_id } => {
                let left_child = MastNodeId::from_u32_with_node_count(left_child_id, node_count)?;
                let right_child = MastNodeId::from_u32_with_node_count(right_child_id, node_count)?;
                let builder = crate::mast::node::JoinNodeBuilder::new([left_child, right_child])
                    .with_digest(self.digest);
                Ok(MastNodeBuilder::Join(builder))
            },
            MastNodeType::Split { if_branch_id, else_branch_id } => {
                let if_branch = MastNodeId::from_u32_with_node_count(if_branch_id, node_count)?;
                let else_branch = MastNodeId::from_u32_with_node_count(else_branch_id, node_count)?;
                let builder = crate::mast::node::SplitNodeBuilder::new([if_branch, else_branch])
                    .with_digest(self.digest);
                Ok(MastNodeBuilder::Split(builder))
            },
            MastNodeType::Loop { body_id } => {
                let body_id = MastNodeId::from_u32_with_node_count(body_id, node_count)?;
                let builder =
                    crate::mast::node::LoopNodeBuilder::new(body_id).with_digest(self.digest);
                Ok(MastNodeBuilder::Loop(builder))
            },
            MastNodeType::Call { callee_id } => {
                let callee_id = MastNodeId::from_u32_with_node_count(callee_id, node_count)?;
                let builder =
                    crate::mast::node::CallNodeBuilder::new(callee_id).with_digest(self.digest);
                Ok(MastNodeBuilder::Call(builder))
            },
            MastNodeType::SysCall { callee_id } => {
                let callee_id = MastNodeId::from_u32_with_node_count(callee_id, node_count)?;
                let builder = crate::mast::node::CallNodeBuilder::new_syscall(callee_id)
                    .with_digest(self.digest);
                Ok(MastNodeBuilder::Call(builder))
            },
            MastNodeType::Dyn => {
                let builder = crate::mast::node::DynNodeBuilder::new_dyn().with_digest(self.digest);
                Ok(MastNodeBuilder::Dyn(builder))
            },
            MastNodeType::Dyncall => {
                let builder =
                    crate::mast::node::DynNodeBuilder::new_dyncall().with_digest(self.digest);
                Ok(MastNodeBuilder::Dyn(builder))
            },
            MastNodeType::External => {
                let builder = crate::mast::node::ExternalNodeBuilder::new(self.digest);
                Ok(MastNodeBuilder::External(builder))
            },
        }
    }
}

impl Serializable for MastNodeInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { ty, digest } = self;

        ty.write_into(target);
        digest.write_into(target);
    }
}

impl Deserializable for MastNodeInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let ty = Deserializable::read_from(source)?;
        let digest = Word::read_from(source)?;

        Ok(Self { ty, digest })
    }

    /// Returns the minimum serialized size: 1 byte for MastNodeType + 32 bytes for Word digest.
    fn min_serialized_size() -> usize {
        33
    }
}

// MAST NODE TYPE
// ================================================================================================

const JOIN: u8 = 0;
const SPLIT: u8 = 1;
const LOOP: u8 = 2;
const BLOCK: u8 = 3;
const CALL: u8 = 4;
const SYSCALL: u8 = 5;
const DYN: u8 = 6;
const DYNCALL: u8 = 7;
const EXTERNAL: u8 = 8;

/// Represents the variant of a [`MastNode`], as well as any additional data. For example, for more
/// efficient decoding, and because of the frequency with which these node types appear, we directly
/// represent the child indices for `Join`, `Split`, and `Loop`, `Call` and `SysCall` inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MastNodeType {
    Join {
        left_child_id: u32,
        right_child_id: u32,
    } = JOIN,
    Split {
        if_branch_id: u32,
        else_branch_id: u32,
    } = SPLIT,
    Loop {
        body_id: u32,
    } = LOOP,
    Block {
        // offset of operations in node data
        ops_offset: u32,
    } = BLOCK,
    Call {
        callee_id: u32,
    } = CALL,
    SysCall {
        callee_id: u32,
    } = SYSCALL,
    Dyn = DYN,
    Dyncall = DYNCALL,
    External = EXTERNAL,
}

/// Constructors
impl MastNodeType {
    /// Constructs a new [`MastNodeType`] from a [`MastNode`].
    pub fn new(mast_node: &MastNode, ops_offset: NodeDataOffset) -> Self {
        use MastNode::*;

        match mast_node {
            Block(_block_node) => Self::Block { ops_offset },
            Join(join_node) => Self::Join {
                left_child_id: join_node.first().0,
                right_child_id: join_node.second().0,
            },
            Split(split_node) => Self::Split {
                if_branch_id: split_node.on_true().0,
                else_branch_id: split_node.on_false().0,
            },
            Loop(loop_node) => Self::Loop { body_id: loop_node.body().0 },
            Call(call_node) => {
                if call_node.is_syscall() {
                    Self::SysCall { callee_id: call_node.callee().0 }
                } else {
                    Self::Call { callee_id: call_node.callee().0 }
                }
            },
            Dyn(dyn_node) => {
                if dyn_node.is_dyncall() {
                    Self::Dyncall
                } else {
                    Self::Dyn
                }
            },
            External(_) => Self::External,
        }
    }
}

impl Serializable for MastNodeType {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let discriminant = self.discriminant();
        target.write_u8(discriminant);

        match *self {
            MastNodeType::Join {
                left_child_id: left,
                right_child_id: right,
            } => {
                target.write_usize(left as usize);
                target.write_usize(right as usize);
            },
            MastNodeType::Split {
                if_branch_id: if_branch,
                else_branch_id: else_branch,
            } => {
                target.write_usize(if_branch as usize);
                target.write_usize(else_branch as usize);
            },
            MastNodeType::Loop { body_id: body } => {
                target.write_usize(body as usize);
            },
            MastNodeType::Block { ops_offset } => {
                target.write_usize(ops_offset as usize);
            },
            MastNodeType::Call { callee_id } => {
                target.write_usize(callee_id as usize);
            },
            MastNodeType::SysCall { callee_id } => {
                target.write_usize(callee_id as usize);
            },
            MastNodeType::Dyn | MastNodeType::Dyncall | MastNodeType::External => {},
        }
    }
}

/// Serialization helpers
impl MastNodeType {
    fn discriminant(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a primitive representation with
        // #[repr(u8)], with the first field of the underlying union-of-structs the discriminant.
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *<*const _>::from(self).cast::<u8>() }
    }
}

impl Deserializable for MastNodeType {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let discriminant = source.read_u8()?;

        match discriminant {
            JOIN => {
                let left_child_id = read_u32_varint(source)?;
                let right_child_id = read_u32_varint(source)?;
                Ok(Self::Join { left_child_id, right_child_id })
            },
            SPLIT => {
                let if_branch_id = read_u32_varint(source)?;
                let else_branch_id = read_u32_varint(source)?;
                Ok(Self::Split { if_branch_id, else_branch_id })
            },
            LOOP => {
                let body_id = read_u32_varint(source)?;
                Ok(Self::Loop { body_id })
            },
            BLOCK => {
                let ops_offset = read_u32_varint(source)?;
                Ok(Self::Block { ops_offset })
            },
            CALL => {
                let callee_id = read_u32_varint(source)?;
                Ok(Self::Call { callee_id })
            },
            SYSCALL => {
                let callee_id = read_u32_varint(source)?;
                Ok(Self::SysCall { callee_id })
            },
            DYN => Ok(Self::Dyn),
            DYNCALL => Ok(Self::Dyncall),
            EXTERNAL => Ok(Self::External),
            _ => Err(DeserializationError::InvalidValue(format!(
                "Invalid tag for MAST node: {discriminant}"
            ))),
        }
    }

    /// Returns the minimum serialized size: 1 byte discriminant.
    fn min_serialized_size() -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn serialize_deserialize_payload_roundtrip() {
        let mast_node_type = MastNodeType::Join {
            left_child_id: u32::MAX,
            right_child_id: 0,
        };

        let serialized = mast_node_type.to_bytes();
        let deserialized = MastNodeType::read_from_bytes(&serialized).unwrap();

        assert_eq!(mast_node_type, deserialized);
    }

    #[test]
    fn deserialize_invalid_tag_fails() {
        let serialized = {
            let mut serialized_buffer: Vec<u8> = Vec::new();
            serialized_buffer.write_u8(0xff);
            serialized_buffer
        };

        let deserialized_result = MastNodeType::read_from_bytes(&serialized);

        assert_matches!(deserialized_result, Err(DeserializationError::InvalidValue(_)));
    }

    #[test]
    fn deserialize_large_payload_fails() {
        let serialized = {
            let mut serialized_buffer: Vec<u8> = Vec::new();
            serialized_buffer.write_u8(CALL);
            serialized_buffer.write_usize(u32::MAX as usize + 1);
            serialized_buffer
        };

        let deserialized_result = MastNodeType::read_from_bytes(&serialized);

        assert_matches!(deserialized_result, Err(DeserializationError::InvalidValue(_)));
    }
}
