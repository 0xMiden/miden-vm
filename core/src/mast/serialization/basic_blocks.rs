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
    mast::{BasicBlockNode, OP_BATCH_SIZE, OP_GROUP_SIZE, collect_immediate_placements},
    operations::Operation,
    serde::{BudgetedReader, ByteReader, DeserializationError, Serializable, SliceReader},
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

/// Returns the serialized size of a basic block in the node data section.
pub(super) fn basic_block_data_len(basic_block: &BasicBlockNode) -> usize {
    let mut op_count = 0usize;
    let mut ops_size = 0usize;
    for op in basic_block.operations() {
        op_count += 1;
        ops_size += op.encoded_size();
    }

    let num_batches = basic_block.num_op_batches();
    let mut size = op_count.get_size_hint() + ops_size;
    size += core::mem::size_of::<u32>();
    size += 5 * num_batches;
    size
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

        // Write delta-encoded indptr arrays for each batch (4 bytes per batch)
        for batch in op_batches {
            let indptr = batch.indptr();
            let packed = pack_indptr_deltas(indptr);
            packed.write_into(&mut self.node_data);
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

/// Packs 8 indptr deltas into 4 bytes (4 bits each). Elides indptr[0] which is always 0.
///
/// Requires full array monotonicity. OpBatch only semantically uses the `[0..num_groups+1]`
/// prefix, but the tail must be filled (with final ops count) to avoid underflow when
/// computing deltas for serialization.
fn pack_indptr_deltas(indptr: &[usize; 9]) -> [u8; 4] {
    debug_assert_eq!(indptr[0], 0, "indptr must start at 0");

    let mut packed = [0u8; 4];
    for i in 0..8 {
        let delta = indptr[i + 1] - indptr[i];
        debug_assert!(delta <= 9, "delta {delta} exceeds maximum of 9");

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
fn unpack_indptr_deltas(packed: [u8; 4]) -> Result<[usize; 9], DeserializationError> {
    let mut indptr = [0usize; 9];

    for i in 0..8 {
        let byte_idx = i / 2;
        let nibble_shift = (i % 2) * 4;
        let delta = ((packed[byte_idx] >> nibble_shift) & 0x0f) as usize;

        if delta > OP_GROUP_SIZE {
            return Err(DeserializationError::InvalidValue(format!(
                "indptr delta {delta} exceeds maximum of {OP_GROUP_SIZE} at position {i} (operation groups comprise at most {OP_GROUP_SIZE} ops)"
            )));
        }

        indptr[i + 1] = indptr[i] + delta;
    }

    Ok(indptr)
}

// BASIC BLOCK DATA DECODER
// ================================================================================================

const INDPTR_BYTES_PER_BATCH: usize = 4;
const PADDING_BYTES_PER_BATCH: usize = 1;
const BATCH_METADATA_BYTES_PER_BATCH: usize = INDPTR_BYTES_PER_BATCH + PADDING_BYTES_PER_BATCH;

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

        let remaining_bytes = self.node_data.len() - offset;
        let mut ops_data_reader =
            BudgetedReader::new(SliceReader::new(&self.node_data[offset..]), remaining_bytes);

        // Read padded operations
        let operations: Vec<Operation> = ops_data_reader.read()?;

        // Read batch count
        let num_batches: u32 = ops_data_reader.read()?;
        let num_batches = num_batches as usize;
        let max_batches = ops_data_reader.max_alloc(BATCH_METADATA_BYTES_PER_BATCH);
        if num_batches > max_batches {
            return Err(DeserializationError::InvalidValue(format!(
                "batch count {num_batches} exceeds remaining data capacity {max_batches}"
            )));
        }

        // Read delta-encoded indptr arrays (4 bytes per batch)
        let mut batch_indptrs: Vec<[usize; 9]> = Vec::with_capacity(num_batches);
        for _ in 0..num_batches {
            let packed: [u8; 4] = ops_data_reader.read()?;
            let indptr = unpack_indptr_deltas(packed)?;
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

        for (batch_idx, (indptr, padding)) in batch_indptrs.iter().zip(batch_padding).enumerate() {
            // Find the highest operation group index
            let highest_op_group = (1..=8).rev().find(|&i| indptr[i] > indptr[i - 1]).unwrap_or(1);

            // Extract operations for this batch
            let batch_num_ops = indptr[highest_op_group];
            let batch_ops_end = global_op_offset + batch_num_ops;

            // Validate that the batch doesn't exceed the operations array
            if batch_ops_end > operations.len() {
                return Err(DeserializationError::InvalidValue(format!(
                    "batch_op_end {} exceeds operations length {}",
                    batch_ops_end,
                    operations.len()
                )));
            }

            let batch_ops: Vec<Operation> = operations[global_op_offset..batch_ops_end].to_vec();

            // Reconstruct the groups array and calculate num_groups
            // num_groups is the next available slot after all operation groups and immediate values
            let mut groups = [Felt::new_unchecked(0); 8];
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
                    groups[array_idx] = Felt::new_unchecked(group_value);

                    let (placements, next_group_idx_after) = collect_immediate_placements(
                        &batch_ops,
                        indptr,
                        array_idx,
                        OP_BATCH_SIZE,
                        None,
                    )
                    .map_err(DeserializationError::InvalidValue)?;

                    for (imm_group_idx, imm_value) in placements {
                        groups[imm_group_idx] = imm_value;
                    }

                    next_group_idx = next_group_idx_after;
                }
            }

            // num_groups is the next available index after all groups and immediates
            let num_groups = next_group_idx;

            let op_batch = crate::mast::OpBatch::new_from_parts(
                batch_ops, *indptr, padding, groups, num_groups,
            );
            op_batch.validate_padding_semantics().map_err(|err| {
                DeserializationError::InvalidValue(format!("batch {batch_idx}: {err}"))
            })?;

            op_batches.push(op_batch);

            global_op_offset = batch_ops_end;
        }

        Ok(op_batches)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use rstest::rstest;

    use super::*;
    use crate::{
        Felt,
        serde::{ByteWriter, DeserializationError, Serializable},
    };

    #[rstest]
    #[case::all_empty([0, 0, 0, 0, 0, 0, 0, 0, 0])]
    #[case::max_deltas([0, 9, 18, 27, 36, 45, 54, 63, 72])]
    #[case::min_non_zero_deltas([0, 1, 2, 3, 4, 5, 6, 7, 8])]
    #[case::mixed_deltas([0, 3, 6, 9, 12, 15, 18, 21, 24])]
    #[case::some_zero_deltas([0, 0, 5, 5, 10, 10, 15, 15, 20])]
    fn test_pack_unpack_indptr_roundtrip(#[case] indptr: [usize; 9]) {
        let packed = pack_indptr_deltas(&indptr);
        let unpacked = unpack_indptr_deltas(packed).unwrap();
        assert_eq!(indptr, unpacked);
    }

    #[rstest]
    #[case::delta_10_position_0([0x0a, 0x00, 0x00, 0x00], "delta 10 exceeds maximum of 9")]
    #[case::delta_15_position_0([0x0f, 0x00, 0x00, 0x00], "delta 15 exceeds maximum of 9")]
    #[case::delta_10_position_1([0x0a, 0x00, 0x00, 0x00], "delta 10 exceeds maximum of 9")]
    #[case::delta_11_position_3([0x00, 0xb0, 0x00, 0x00], "delta 11 exceeds maximum of 9")]
    #[case::delta_14_position_7([0x00, 0x00, 0x00, 0x0e], "delta 14 exceeds maximum of 9")]
    fn test_unpack_invalid_delta(#[case] packed: [u8; 4], #[case] expected_msg: &str) {
        let result = unpack_indptr_deltas(packed);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains(expected_msg));
    }

    #[test]
    fn decode_operations_rejects_over_budget_batch_count() {
        let mut bytes = Vec::new();
        let operations: Vec<Operation> = Vec::new();
        operations.write_into(&mut bytes);
        bytes.write_u32(u32::MAX);

        let decoder = BasicBlockDataDecoder::new(&bytes);
        let err = decoder.decode_operations(0).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("batch count"));
    }

    #[test]
    fn decode_operations_allows_exact_batch_budget() {
        let mut bytes = Vec::new();
        let operations: Vec<Operation> = Vec::new();
        operations.write_into(&mut bytes);

        bytes.write_u32(2);
        for _ in 0..2 {
            bytes.write_bytes(&[0u8; INDPTR_BYTES_PER_BATCH]);
        }
        for _ in 0..2 {
            bytes.write_u8(0);
        }

        let decoder = BasicBlockDataDecoder::new(&bytes);
        let op_batches = decoder.decode_operations(0).unwrap();
        assert_eq!(op_batches.len(), 2);
    }

    #[test]
    fn decode_operations_rejects_over_budget_with_ops_consumed() {
        let mut bytes = Vec::new();
        let operations: Vec<Operation> = vec![Operation::Noop];
        operations.write_into(&mut bytes);

        bytes.write_u32(2);
        bytes.write_bytes(&[0u8; INDPTR_BYTES_PER_BATCH]);
        bytes.write_u8(0);

        let decoder = BasicBlockDataDecoder::new(&bytes);
        let err = decoder.decode_operations(0).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("batch count"));
    }

    #[test]
    fn test_decode_operations_rejects_push_immediate_group_overflow() {
        let operations = vec![Operation::Push(Felt::new_unchecked(1))];

        let mut bytes = Vec::new();
        operations.write_into(&mut bytes);
        1u32.write_into(&mut bytes);

        let indptr = [0usize, 0, 0, 0, 0, 0, 0, 0, 1];
        let packed = pack_indptr_deltas(&indptr);
        packed.write_into(&mut bytes);
        0u8.write_into(&mut bytes);

        let decoder = BasicBlockDataDecoder::new(&bytes);
        let err = decoder.decode_operations(0).unwrap_err();
        assert!(
            matches!(
                err,
                DeserializationError::InvalidValue(ref msg) if msg.contains("exceeds group slots")
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn decode_operations_rejects_empty_padded_group() {
        let mut bytes = Vec::new();

        vec![Operation::Noop].write_into(&mut bytes);

        bytes.write_u32(1);
        bytes.write_bytes(&[0x10, 0x00, 0x00, 0x00]);
        bytes.write_u8(0x01);

        let decoder = BasicBlockDataDecoder::new(&bytes);
        let err = decoder.decode_operations(0).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("empty group cannot be marked as padded"));
    }

    #[test]
    fn decode_operations_rejects_padded_group_without_noop() {
        let mut bytes = Vec::new();

        vec![Operation::Add].write_into(&mut bytes);

        bytes.write_u32(1);
        bytes.write_bytes(&[0x01, 0x00, 0x00, 0x00]);
        bytes.write_u8(0x01);

        let decoder = BasicBlockDataDecoder::new(&bytes);
        let err = decoder.decode_operations(0).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("padded group must end with NOOP"));
    }

    #[test]
    fn decode_operations_accepts_padded_group_with_noop() {
        let mut bytes = Vec::new();

        vec![Operation::Add, Operation::Noop].write_into(&mut bytes);

        bytes.write_u32(1);
        bytes.write_bytes(&[0x02, 0x00, 0x00, 0x00]);
        bytes.write_u8(0x01);

        let decoder = BasicBlockDataDecoder::new(&bytes);
        let batches = decoder.decode_operations(0).unwrap();

        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(batch.num_groups(), 1);
        assert_eq!(batch.ops(), &[Operation::Add, Operation::Noop]);
        assert!(batch.padding()[0]);
    }
}
