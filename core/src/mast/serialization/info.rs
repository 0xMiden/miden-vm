use alloc::vec::Vec;

use super::{NodeDataOffset, basic_blocks::BasicBlockDataDecoder};
use crate::{
    mast::{
        MastForestContributor, MastNode, MastNodeId, Word,
        node::{MastNodeBuilder, MastNodeExt},
    },
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// MAST NODE INFO
// ================================================================================================

/// Fixed-width structural metadata for a serialized [`MastNode`].
///
/// This is the random-access portion of the node table. Digests are intentionally modeled
/// separately so the wire format can move them into dedicated sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MastNodeEntry {
    ty: MastNodeType,
}

impl MastNodeEntry {
    /// Constructs a new [`MastNodeEntry`] from a [`MastNode`], along with an `ops_offset`
    ///
    /// For non-basic block nodes, `ops_offset` is ignored, and should be set to 0.
    pub fn new(mast_node: &MastNode, ops_offset: NodeDataOffset) -> Self {
        if !matches!(mast_node, &MastNode::Block(_)) {
            debug_assert_eq!(ops_offset, 0);
        }

        let ty = MastNodeType::new(mast_node, ops_offset);
        Self { ty }
    }

    /// Attempts to convert this [`MastNodeEntry`] into a [`MastNodeBuilder`].
    ///
    /// The `node_count` is the total expected number of nodes in the
    /// [`crate::mast::MastForest`] **after deserialization**.
    pub fn try_into_mast_node_builder(
        self,
        node_count: usize,
        basic_block_data_decoder: &BasicBlockDataDecoder,
        digest: Word,
    ) -> Result<MastNodeBuilder, DeserializationError> {
        match self.ty {
            MastNodeType::Block { ops_offset } => {
                let op_batches = basic_block_data_decoder.decode_operations(ops_offset)?;
                let builder = crate::mast::node::BasicBlockNodeBuilder::from_op_batches(
                    op_batches,
                    Vec::new(), // decorators set later
                    digest,
                );
                Ok(MastNodeBuilder::BasicBlock(builder))
            },
            MastNodeType::Join { left_child_id, right_child_id } => {
                let left_child = MastNodeId::from_u32_with_node_count(left_child_id, node_count)?;
                let right_child = MastNodeId::from_u32_with_node_count(right_child_id, node_count)?;
                let builder = crate::mast::node::JoinNodeBuilder::new([left_child, right_child])
                    .with_digest(digest);
                Ok(MastNodeBuilder::Join(builder))
            },
            MastNodeType::Split { if_branch_id, else_branch_id } => {
                let if_branch = MastNodeId::from_u32_with_node_count(if_branch_id, node_count)?;
                let else_branch = MastNodeId::from_u32_with_node_count(else_branch_id, node_count)?;
                let builder = crate::mast::node::SplitNodeBuilder::new([if_branch, else_branch])
                    .with_digest(digest);
                Ok(MastNodeBuilder::Split(builder))
            },
            MastNodeType::Loop { body_id } => {
                let body_id = MastNodeId::from_u32_with_node_count(body_id, node_count)?;
                let builder = crate::mast::node::LoopNodeBuilder::new(body_id).with_digest(digest);
                Ok(MastNodeBuilder::Loop(builder))
            },
            MastNodeType::Call { callee_id } => {
                let callee_id = MastNodeId::from_u32_with_node_count(callee_id, node_count)?;
                let builder =
                    crate::mast::node::CallNodeBuilder::new(callee_id).with_digest(digest);
                Ok(MastNodeBuilder::Call(builder))
            },
            MastNodeType::SysCall { callee_id } => {
                let callee_id = MastNodeId::from_u32_with_node_count(callee_id, node_count)?;
                let builder =
                    crate::mast::node::CallNodeBuilder::new_syscall(callee_id).with_digest(digest);
                Ok(MastNodeBuilder::Call(builder))
            },
            MastNodeType::Dyn => Ok(MastNodeBuilder::Dyn(
                crate::mast::node::DynNodeBuilder::new_dyn().with_digest(digest),
            )),
            MastNodeType::Dyncall => Ok(MastNodeBuilder::Dyn(
                crate::mast::node::DynNodeBuilder::new_dyncall().with_digest(digest),
            )),
            MastNodeType::External => {
                Ok(MastNodeBuilder::External(crate::mast::node::ExternalNodeBuilder::new(digest)))
            },
        }
    }

    /// Returns the serialized node type metadata.
    pub fn node_type(&self) -> MastNodeType {
        self.ty
    }
}

impl Serializable for MastNodeEntry {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.ty.write_into(target);
    }
}

impl Deserializable for MastNodeEntry {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let ty = Deserializable::read_from(source)?;
        Ok(Self { ty })
    }

    fn min_serialized_size() -> usize {
        MastNodeType::min_serialized_size()
    }
}

/// Logical node metadata combining fixed-width structure and a digest value.
///
/// This is a convenience type for APIs that want both pieces together. The wire format does not
/// require `MastNodeInfo` to appear as one contiguous fixed-width section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MastNodeInfo {
    entry: MastNodeEntry,
    digest: Word,
}

impl MastNodeInfo {
    /// Constructs a new [`MastNodeInfo`] from a [`MastNode`], along with an `ops_offset`
    ///
    /// For non-basic block nodes, `ops_offset` is ignored, and should be set to 0.
    pub fn new(mast_node: &MastNode, ops_offset: NodeDataOffset) -> Self {
        Self {
            entry: MastNodeEntry::new(mast_node, ops_offset),
            digest: mast_node.digest(),
        }
    }

    /// Attempts to convert this [`MastNodeInfo`] into a [`MastNodeBuilder`].
    pub fn try_into_mast_node_builder(
        self,
        node_count: usize,
        basic_block_data_decoder: &BasicBlockDataDecoder,
    ) -> Result<MastNodeBuilder, DeserializationError> {
        self.entry
            .try_into_mast_node_builder(node_count, basic_block_data_decoder, self.digest)
    }

    /// Returns the fixed-width structural node entry.
    pub fn node_entry(&self) -> MastNodeEntry {
        self.entry
    }

    /// Returns the serialized node type metadata.
    pub fn node_type(&self) -> MastNodeType {
        self.entry.node_type()
    }

    /// Returns the stored node digest.
    pub fn digest(&self) -> Word {
        self.digest
    }

    /// Builds node metadata directly from serialized components.
    pub(crate) fn from_entry(entry: MastNodeEntry, digest: Word) -> Self {
        Self { entry, digest }
    }
}

impl Serializable for MastNodeInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.entry.write_into(target);
        self.digest.write_into(target);
    }
}

impl Deserializable for MastNodeInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let entry = MastNodeEntry::read_from(source)?;
        let digest = Word::read_from(source)?;
        Ok(Self { entry, digest })
    }

    /// Returns the minimum serialized size: 8 bytes for MastNodeType + 32 bytes for Word digest.
    fn min_serialized_size() -> usize {
        MastNodeEntry::min_serialized_size() + Word::min_serialized_size()
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

/// Represents the variant of a [`MastNode`], along with any inline structural payload.
///
/// Child indices for `Join`, `Split`, `Loop`, `Call`, and `SysCall` are stored inline so random
/// access does not need any extra pointer chasing.
///
/// The serialized representation is always 8 bytes, which keeps [`MastNodeEntry`] fixed-width on
/// the wire.
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
        let discriminant = self.discriminant() as u64;
        assert!(discriminant <= 0b1111);

        let payload = match *self {
            MastNodeType::Join {
                left_child_id: left,
                right_child_id: right,
            } => Self::encode_u32_pair(left, right),
            MastNodeType::Split {
                if_branch_id: if_branch,
                else_branch_id: else_branch,
            } => Self::encode_u32_pair(if_branch, else_branch),
            MastNodeType::Loop { body_id: body } => Self::encode_u32_payload(body),
            MastNodeType::Block { ops_offset } => Self::encode_u32_payload(ops_offset),
            MastNodeType::Call { callee_id } => Self::encode_u32_payload(callee_id),
            MastNodeType::SysCall { callee_id } => Self::encode_u32_payload(callee_id),
            MastNodeType::Dyn => 0,
            MastNodeType::Dyncall => 0,
            MastNodeType::External => 0,
        };

        let value = (discriminant << 60) | payload;
        target.write_u64(value);
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

    /// Encodes two u32 numbers in the first 60 bits of a `u64`.
    ///
    /// # Panics
    /// - Panics if either `left_value` or `right_value` doesn't fit in 30 bits.
    fn encode_u32_pair(left_value: u32, right_value: u32) -> u64 {
        assert!(
            left_value.leading_zeros() >= 2,
            "MastNodeType::encode_u32_pair: left value doesn't fit in 30 bits: {left_value}",
        );
        assert!(
            right_value.leading_zeros() >= 2,
            "MastNodeType::encode_u32_pair: right value doesn't fit in 30 bits: {right_value}",
        );

        ((left_value as u64) << 30) | (right_value as u64)
    }

    fn encode_u32_payload(payload: u32) -> u64 {
        payload as u64
    }
}

impl Deserializable for MastNodeType {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let (discriminant, payload) = {
            let value = source.read_u64()?;

            // 4 bits
            let discriminant = (value >> 60) as u8;
            // 60 bits
            let payload = value & 0x0f_ff_ff_ff_ff_ff_ff_ff;

            (discriminant, payload)
        };

        match discriminant {
            JOIN => {
                let (left_child_id, right_child_id) = Self::decode_u32_pair(payload);
                Ok(Self::Join { left_child_id, right_child_id })
            },
            SPLIT => {
                let (if_branch_id, else_branch_id) = Self::decode_u32_pair(payload);
                Ok(Self::Split { if_branch_id, else_branch_id })
            },
            LOOP => {
                let body_id = Self::decode_u32_payload(payload)?;
                Ok(Self::Loop { body_id })
            },
            BLOCK => {
                let ops_offset = Self::decode_u32_payload(payload)?;
                Ok(Self::Block { ops_offset })
            },
            CALL => {
                let callee_id = Self::decode_u32_payload(payload)?;
                Ok(Self::Call { callee_id })
            },
            SYSCALL => {
                let callee_id = Self::decode_u32_payload(payload)?;
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

    /// Returns the fixed serialized size: always 8 bytes (u64).
    fn min_serialized_size() -> usize {
        8
    }
}

/// Deserialization helpers
impl MastNodeType {
    /// Decodes two `u32` numbers from a 60-bit payload.
    fn decode_u32_pair(payload: u64) -> (u32, u32) {
        let left_value = (payload >> 30) as u32;
        let right_value = (payload & 0x3f_ff_ff_ff) as u32;

        (left_value, right_value)
    }

    /// Decodes one `u32` number from a 60-bit payload.
    ///
    /// Returns an error if the payload doesn't fit in a `u32`.
    pub fn decode_u32_payload(payload: u64) -> Result<u32, DeserializationError> {
        payload.try_into().map_err(|_| {
            DeserializationError::InvalidValue(format!(
                "Invalid payload: expected to fit in u32, but was {payload}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn serialize_deserialize_60_bit_payload() {
        // each child needs 30 bits
        let mast_node_type = MastNodeType::Join {
            left_child_id: 0x3f_ff_ff_ff,
            right_child_id: 0x3f_ff_ff_ff,
        };

        let serialized = mast_node_type.to_bytes();
        let deserialized = MastNodeType::read_from_bytes(&serialized).unwrap();

        assert_eq!(mast_node_type, deserialized);
    }

    #[test]
    #[should_panic]
    fn serialize_large_payloads_fails_1() {
        // left child needs 31 bits
        let mast_node_type = MastNodeType::Join {
            left_child_id: 0x4f_ff_ff_ff,
            right_child_id: 0x0,
        };

        // must panic
        let _serialized = mast_node_type.to_bytes();
    }

    #[test]
    #[should_panic]
    fn serialize_large_payloads_fails_2() {
        // right child needs 31 bits
        let mast_node_type = MastNodeType::Join {
            left_child_id: 0x0,
            right_child_id: 0x4f_ff_ff_ff,
        };

        // must panic
        let _serialized = mast_node_type.to_bytes();
    }

    #[test]
    fn deserialize_large_payloads_fails() {
        // Serialized `CALL` with a 33-bit payload
        let serialized = {
            let serialized_value = ((CALL as u64) << 60) | (u32::MAX as u64 + 1_u64);

            let mut serialized_buffer: Vec<u8> = Vec::new();
            serialized_value.write_into(&mut serialized_buffer);

            serialized_buffer
        };

        let deserialized_result = MastNodeType::read_from_bytes(&serialized);

        assert_matches!(deserialized_result, Err(DeserializationError::InvalidValue(_)));
    }
}
