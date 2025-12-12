//! Basic block serialization format.
//!
//! ## Wire Format
//!
//! - Padded operations (variable size)
//! - Batch count (4 bytes)
//! - Indptr array per batch (9 bytes each)
//! - Padding flags per batch (1 byte each, bit-packed)
//!
//! **Total**: `ops_size + 4 + (10 * num_batches)` bytes

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
    /// data field. Decorators are stored separately.
    ///
    /// Operations are written in padded form with batch metadata for exact reconstruction.
    pub fn encode_basic_block(&mut self, basic_block: &BasicBlockNode) -> NodeDataOffset {
        let ops_offset = self.node_data.len() as NodeDataOffset;

        // Write padded operations
        let operations: Vec<Operation> = basic_block.operations().copied().collect();
        operations.write_into(&mut self.node_data);

        // Write batch metadata
        let op_batches = basic_block.op_batches();
        let num_batches = op_batches.len();

        // Write number of batches
        (num_batches as u32).write_into(&mut self.node_data);

        // Write indptr arrays for each batch (9 u8s per batch, since max index is 72)
        for batch in op_batches {
            let indptr = batch.indptr();
            for &idx in indptr {
                debug_assert!(idx <= 72, "batch index {} exceeds maximum of 72", idx);
                (idx as u8).write_into(&mut self.node_data);
            }
        }

        // Write padding metadata (1 byte per batch, bit-packed)
        for batch in op_batches {
            let padding = batch.padding();
            let mut packed: u8 = 0;
            for (i, &is_padded) in padding.iter().enumerate().take(8) {
                if is_padded {
                    packed |= 1 << i;
                }
            }
            packed.write_into(&mut self.node_data);
        }

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
    /// Reconstructs OpBatches from serialized data, preserving padding and batch structure.
    pub fn decode_operations(
        &self,
        ops_offset: NodeDataOffset,
    ) -> Result<Vec<crate::mast::OpBatch>, DeserializationError> {
        use crate::Felt;

        let offset = ops_offset as usize;

        // Bounds check before slicing to prevent panic
        if offset > self.node_data.len() {
            return Err(DeserializationError::InvalidValue(format!(
                "ops_offset {} exceeds basic_block_data length {}",
                offset,
                self.node_data.len()
            )));
        }

        let mut ops_data_reader = SliceReader::new(&self.node_data[offset..]);

        // Read padded operations
        let operations: Vec<Operation> = ops_data_reader.read()?;

        // Read batch count
        let num_batches: u32 = ops_data_reader.read()?;
        let num_batches = num_batches as usize;

        // Read indptr arrays (9 u8s per batch)
        let mut batch_indptrs: Vec<[usize; 9]> = Vec::with_capacity(num_batches);
        for _ in 0..num_batches {
            let mut indptr = [0usize; 9];
            for idx in indptr.iter_mut() {
                let val: u8 = ops_data_reader.read()?;
                *idx = val as usize;
            }
            batch_indptrs.push(indptr);
        }

        // Read padding metadata (1 byte per batch)
        let mut batch_padding: Vec<[bool; 8]> = Vec::with_capacity(num_batches);
        for _ in 0..num_batches {
            let packed: u8 = ops_data_reader.read()?;
            let mut padding = [false; 8];
            for (i, p) in padding.iter_mut().enumerate() {
                *p = (packed & (1 << i)) != 0;
            }
            batch_padding.push(padding);
        }

        // Reconstruct OpBatch structures
        let mut op_batches: Vec<crate::mast::OpBatch> = Vec::with_capacity(num_batches);
        let mut global_op_offset = 0;

        for (indptr, padding) in batch_indptrs.iter().zip(batch_padding) {
            // Find the highest operation group index
            let highest_op_group = (1..=8).rev().find(|&i| indptr[i] > indptr[i - 1]).unwrap_or(1);

            // Extract operations for this batch
            let batch_num_ops = indptr[highest_op_group];
            let batch_ops_end = global_op_offset + batch_num_ops;

            let batch_ops: Vec<Operation> = operations[global_op_offset..batch_ops_end].to_vec();

            // Reconstruct the groups array and calculate num_groups
            // num_groups is the next available slot after all operation groups and immediate values
            let mut groups = [Felt::new(0); 8];
            let mut next_group_idx = 0;

            for array_idx in 0..highest_op_group {
                let start = indptr[array_idx];
                let end = indptr[array_idx + 1];

                if start < end {
                    // This index contains an operation group - compute its hash
                    let mut group_value: u64 = 0;
                    for (local_op_idx, op) in batch_ops[start..end].iter().enumerate() {
                        let opcode = op.op_code() as u64;
                        group_value |= opcode << (Operation::OP_BITS * local_op_idx);
                    }
                    groups[array_idx] = Felt::new(group_value);
                    next_group_idx = array_idx + 1;

                    // Store immediate values from this operation group
                    for op in &batch_ops[start..end] {
                        if let Some(imm) = op.imm_value()
                            && next_group_idx < 8
                        {
                            groups[next_group_idx] = imm;
                            next_group_idx += 1;
                        }
                    }
                }
            }

            // num_groups is the next available index after all groups and immediates
            let num_groups = next_group_idx;

            op_batches.push(crate::mast::OpBatch::new_from_parts(
                batch_ops, *indptr, padding, groups, num_groups,
            ));

            global_op_offset = batch_ops_end;
        }

        Ok(op_batches)
    }
}
