//! Basic block serialization format.
//!
//! ## Wire Format
//!
//! - Padded operations (variable size)
//! - Batch count (4 bytes)
//! - Delta-encoded indptr per batch (4 bytes each: 8 deltas × 4 bits, packed)
//! - Padding flags per batch (1 byte each, bit-packed)
//!
//! **Total**: `ops_size + 4 + (5 * num_batches)` bytes

use alloc::vec::Vec;

use super::NodeDataOffset;
use crate::{
    Operation,
    mast::{BasicBlockNode, OP_GROUP_SIZE},
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

// INDPTR DELTA ENCODING
// ================================================================================================

/// Packs indptr array deltas into 4 bytes using 4-bit encoding.
///
/// The indptr array has 9 elements [0, a, b, c, d, e, f, g, h] where the first element
/// is always 0. We encode 8 deltas: [a-0, b-a, c-b, d-c, e-d, f-e, g-f, h-g].
/// Each delta is guaranteed to be in [0, 9] (fits in 4 bits).
///
/// # Format
///
/// Byte layout (4 bytes total):
/// ```text
/// Byte 0: [delta1_low_4bits | delta0_low_4bits]
/// Byte 1: [delta3_low_4bits | delta2_low_4bits]
/// Byte 2: [delta5_low_4bits | delta4_low_4bits]
/// Byte 3: [delta7_low_4bits | delta6_low_4bits]
/// ```
///
/// Returns 4 bytes with packed deltas in little-endian nibble order.
fn pack_indptr_deltas(indptr: &[usize; 9]) -> [u8; 4] {
    debug_assert_eq!(indptr[0], 0, "indptr must start at 0");

    let mut packed = [0u8; 4];
    for i in 0..8 {
        let delta = indptr[i + 1] - indptr[i];
        debug_assert!(delta <= 9, "delta {} exceeds maximum of 9", delta);

        let byte_idx = i / 2;
        let nibble_shift = (i % 2) * 4;
        packed[byte_idx] |= (delta as u8) << nibble_shift;
    }
    packed
}

/// Unpacks 4 bytes of delta-encoded indptr into a full indptr array.
///
/// Validates that each delta is in [0, GROUP_SIZE] and reconstructs the cumulative indptr array
/// starting from the implicit indptr[0] = 0.
///
/// # Errors
///
/// Returns `DeserializationError::InvalidValue` if any delta exceeds GROUP_SIZE.
fn unpack_indptr_deltas(packed: &[u8; 4]) -> Result<[usize; 9], DeserializationError> {
    let mut indptr = [0usize; 9];

    for i in 0..8 {
        let byte_idx = i / 2;
        let nibble_shift = (i % 2) * 4;
        let delta = ((packed[byte_idx] >> nibble_shift) & 0x0f) as usize;

        if delta > OP_GROUP_SIZE {
            return Err(DeserializationError::InvalidValue(format!(
                "indptr delta {} exceeds maximum of {} at position {} (operation groups comprise at most {} ops)",
                delta, OP_GROUP_SIZE, i, OP_GROUP_SIZE
            )));
        }

        indptr[i + 1] = indptr[i] + delta;
    }

    Ok(indptr)
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

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_pack_unpack_indptr_roundtrip() {
        // Test various valid indptr patterns
        let test_cases = vec![
            [0, 0, 0, 0, 0, 0, 0, 0, 0],        // All empty groups
            [0, 9, 18, 27, 36, 45, 54, 63, 72], // Max deltas (9 each)
            [0, 1, 2, 3, 4, 5, 6, 7, 8],        // Min non-zero deltas (1 each)
            [0, 3, 6, 9, 12, 15, 18, 21, 24],   // Mixed deltas (3 each)
            [0, 0, 5, 5, 10, 10, 15, 15, 20],   // Some zero deltas
        ];

        for indptr in test_cases {
            let packed = pack_indptr_deltas(&indptr);
            let unpacked = unpack_indptr_deltas(&packed).unwrap();
            assert_eq!(indptr, unpacked);
        }
    }

    #[test]
    fn test_unpack_invalid_delta() {
        // Delta of 10 at position 0 (exceeds GROUP_SIZE = 9)
        let packed = [0x0a, 0x00, 0x00, 0x00];
        let result = unpack_indptr_deltas(&packed);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("delta 10 exceeds maximum of 9"));
    }
}
