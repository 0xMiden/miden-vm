use alloc::vec::Vec;

use super::NodeDataOffset;
use crate::{
    Operation,
    mast::BasicBlockNode,
    utils::{ByteReader, DeserializationError, Serializable, SliceReader},
};

// BASIC BLOCK DATA BUILDER
// ================================================================================================

/// Builds the node `data` section of a serialized [`crate::mast::MastForest`].
#[derive(Debug, Default)]
pub struct BasicBlockDataBuilder {
    node_data: Vec<u8>,
}

/// Constructors
impl BasicBlockDataBuilder {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Mutators
impl BasicBlockDataBuilder {
    /// Encodes a [`BasicBlockNode`]'s operations into the serialized [`crate::mast::MastForest`]
    /// data field. The decorators are not encoded because are stored separately
    pub fn encode_basic_block(&mut self, basic_block: &BasicBlockNode) -> NodeDataOffset {
        let ops_offset = self.node_data.len() as NodeDataOffset;

        let operations: Vec<Operation> = basic_block.raw_operations().copied().collect();
        operations.write_into(&mut self.node_data);

        ops_offset
    }

    /// Returns the serialized [`crate::mast::MastForest`] node data field.
    pub fn finalize(self) -> Vec<u8> {
        self.node_data
    }
}

// BASIC BLOCK DATA DECODER
// ================================================================================================

pub struct BasicBlockDataDecoder<'a> {
    node_data: &'a [u8],
}

/// Constructors
impl<'a> BasicBlockDataDecoder<'a> {
    pub fn new(node_data: &'a [u8]) -> Self {
        Self { node_data }
    }
}

/// Decoding methods
impl BasicBlockDataDecoder<'_> {
    pub fn decode_operations(
        &self,
        ops_offset: NodeDataOffset,
    ) -> Result<Vec<Operation>, DeserializationError> {
        // Read ops
        let mut ops_data_reader = SliceReader::new(&self.node_data[ops_offset as usize..]);
        let operations: Vec<Operation> = ops_data_reader.read()?;

        Ok(operations)
    }
}
