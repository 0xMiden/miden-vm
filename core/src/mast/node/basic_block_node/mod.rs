use alloc::{boxed::Box, string::String, vec::Vec};
use core::{fmt, iter::repeat_n};

#[cfg(any(test, feature = "arbitrary"))]
use crate::mast::MastNode;
use crate::{
    Felt, Word, ZERO,
    chiplets::hasher,
    mast::{MastForest, MastForestError, MastNodeId},
    operations::Operation,
    prettier::PrettyPrint,
    serde::Serializable,
    utils::{LookupByIdx, bytes_to_packed_u32_elements},
};

mod op_batch;
pub use op_batch::OpBatch;
use op_batch::OpBatchAccumulator;
pub(crate) use op_batch::collect_immediate_placements;

use super::{MastForestContributor, MastNodeContext, MastNodeExt};

#[cfg(any(test, feature = "arbitrary"))]
pub mod arbitrary;

#[cfg(test)]
mod tests;

// CONSTANTS
// ================================================================================================

/// Maximum number of operations per group.
pub const GROUP_SIZE: usize = 9;

/// Maximum number of groups per batch.
pub const BATCH_SIZE: usize = 8;
const _: [(); 1] = [(); ((BATCH_SIZE & (BATCH_SIZE - 1)) == 0) as usize];

const ERROR_CODE_FINGERPRINT_DOMAIN: Felt = Felt::new_unchecked(0x2473_0001);

// BASIC BLOCK NODE
// ================================================================================================

/// Block for a linear sequence of operations (i.e., no branching or loops).
///
/// Executes its operations in order. Fails if any of the operations fails.
///
/// A basic block is composed of operation batches, operation batches are composed of operation
/// groups, operation groups encode the VM's operations and immediate values. These values are
/// created according to these rules:
///
/// - A basic block contains one or more batches.
/// - A batch contains up to 8 groups, and the number of groups must be a power of 2.
/// - A group contains up to 9 operations or 1 immediate value.
/// - Last operation in a group cannot be an operation that requires an immediate value.
/// - NOOPs are used to fill a group or batch when necessary.
/// - An immediate value follows the operation that requires it, using the next available group in
///   the batch. If there are no groups available in the batch, then both the operation and its
///   immediate value are moved to the next batch.
///
/// Example: 8 pushes result in two operation batches:
///
/// - First batch: First group with 7 push opcodes and 2 zero-paddings packed together, followed by
///   7 groups with their respective immediate values.
/// - Second batch: First group with the last push opcode and 8 zero-paddings packed together,
///   followed by one immediate and 6 padding groups.
///
/// The hash of a basic block is:
///
/// > hash(batches, domain=BASIC_BLOCK_DOMAIN)
///
/// Where `batches` is the concatenation of each `batch` in the basic block, and each batch is 8
/// field elements (512 bits).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlockNode {
    /// The primitive operations contained in this basic block.
    ///
    /// The operations are broken up into batches of 8 groups, with each group containing up to 9
    /// operations, or a single immediates. Thus the maximum size of each batch is 72 operations.
    /// Multiple batches are used for blocks consisting of more than 72 operations.
    op_batches: Vec<OpBatch>,
    digest: Word,
}

// ------------------------------------------------------------------------------------------------
// SERIALIZATION
// ================================================================================================

// ------------------------------------------------------------------------------------------------
/// Constants
impl BasicBlockNode {
    /// The domain of the basic block node (used for control block hashing).
    pub const DOMAIN: Felt = ZERO;
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl BasicBlockNode {
    /// Returns a new [`BasicBlockNode`] instantiated with the specified operations.
    #[cfg(any(test, feature = "arbitrary"))]
    pub(crate) fn new(operations: Vec<Operation>) -> Result<Self, MastForestError> {
        if operations.is_empty() {
            return Err(MastForestError::EmptyBasicBlock);
        }

        let (op_batches, digest) = batch_and_hash_ops(&operations);
        Ok(Self { op_batches, digest })
    }

    /// Adjusts raw operation indices to padded indices for AssemblyOp mappings.
    ///
    /// Adjusts AssemblyOp mappings `(raw_idx, id)` to account for padding NOOPs inserted into
    /// op_batches.
    pub fn adjust_asm_op_indices<T: Copy>(
        asm_ops: Vec<(usize, T)>,
        op_batches: &[OpBatch],
    ) -> Vec<(usize, T)> {
        let raw2pad = RawToPaddedPrefix::new(op_batches);
        asm_ops
            .into_iter()
            .map(|(raw_idx, id)| {
                let padded = raw_idx + raw2pad[raw_idx];
                (padded, id)
            })
            .collect()
    }

    /// Adjusts padded operation indices back to raw indices for AssemblyOp mappings.
    pub fn unadjust_asm_op_indices<T: Copy>(
        asm_ops: Vec<(usize, T)>,
        op_batches: &[OpBatch],
    ) -> Vec<(usize, T)> {
        let pad2raw = PaddedToRawPrefix::new(op_batches);
        asm_ops
            .into_iter()
            .map(|(padded_idx, id)| {
                let raw = padded_idx - pad2raw[padded_idx];
                (raw, id)
            })
            .collect()
    }
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl BasicBlockNode {
    /// Returns a reference to the operation batches in this basic block.
    pub fn op_batches(&self) -> &[OpBatch] {
        &self.op_batches
    }

    /// Returns the number of operation batches in this basic block.
    pub fn num_op_batches(&self) -> usize {
        self.op_batches.len()
    }

    /// Returns the total number of operation groups in this basic block.
    ///
    /// Then number of operation groups is computed as follows:
    /// - For all batches but the last one we set the number of groups to 8, regardless of the
    ///   actual number of groups in the batch. The reason for this is that when operation batches
    ///   are concatenated together each batch contributes 8 elements to the hash.
    /// - For the last batch, we take the number of actual groups and round it up to the next power
    ///   of two. The reason for rounding is that the VM always executes a number of operation
    ///   groups which is a power of two.
    pub fn num_op_groups(&self) -> usize {
        let last_batch_num_groups = self.op_batches.last().expect("no last group").num_groups();
        (self.op_batches.len() - 1) * BATCH_SIZE + last_batch_num_groups.next_power_of_two()
    }

    /// Returns the number of operations in this basic block.
    pub fn num_operations(&self) -> u32 {
        let num_ops: usize = self.op_batches.iter().map(|batch| batch.ops().len()).sum();
        num_ops.try_into().expect("basic block contains more than 2^32 operations")
    }

    /// Returns an iterator over the operations in the order in which they appear in the program.
    pub fn operations(&self) -> impl Iterator<Item = &Operation> {
        self.op_batches.iter().flat_map(OpBatch::ops)
    }

    /// Returns an iterator over the un-padded operations in the order in which they
    /// appear in the program.
    pub fn raw_operations(&self) -> impl Iterator<Item = &Operation> {
        self.op_batches.iter().flat_map(OpBatch::raw_ops)
    }
}

// BATCH VALIDATION
// ================================================================================================

impl BasicBlockNode {
    /// Validates that this BasicBlockNode satisfies the core invariants:
    /// 1. Non-final batches must be full (BATCH_SIZE groups), final batch must be power-of-two
    /// 2. No operation group ends with an operation requiring an immediate value
    /// 3. The last operation group in a batch cannot contain operations requiring immediate values
    /// 4. OpBatch structural consistency (num_groups <= BATCH_SIZE, group size <= GROUP_SIZE)
    /// 5. Immediate values are committed to empty groups and match group contents
    /// 6. OpBatch padding semantics (no padding on empty groups; padded groups end with NOOP)
    ///
    /// Returns an error string describing which invariant was violated if validation fails.
    pub fn validate_batch_invariants(&self) -> Result<(), String> {
        // Check invariant 1: Power-of-two groups in each batch
        self.validate_power_of_two_groups()?;

        // Check invariant 4: OpBatch structural consistency
        // This needs to be done early on as it will validate indptr indexes used in later checks.
        self.validate_batch_structure()?;

        // Control-flow opcodes are expected to be filtered upstream and enforced centrally via
        // MastForest::validate.

        // Check invariants 2 and 3: immediate-ending constraints
        self.validate_no_immediate_endings()?;

        // Check invariant 5: Immediate values must be committed to empty groups
        self.validate_immediate_commitment()?;

        // Check invariant 6: OpBatch padding semantics
        self.validate_padding_semantics()?;

        Ok(())
    }

    /// Validates that non-final batches are full and the final batch is power-of-two.
    ///
    /// This invariant is required by trace generation (see `num_op_groups`) and is expected to
    /// hold for all serialized forests produced by the assembler; violations indicate corrupted
    /// or malformed input.
    fn validate_power_of_two_groups(&self) -> Result<(), String> {
        for (batch_idx, batch) in self.op_batches.iter().enumerate() {
            let num_groups = batch.num_groups();
            if batch_idx + 1 < self.op_batches.len() {
                if num_groups != BATCH_SIZE {
                    return Err(format!(
                        "Batch {batch_idx}: {num_groups} groups is not full batch size {BATCH_SIZE}"
                    ));
                }
            } else if !num_groups.is_power_of_two() {
                return Err(format!("Batch {batch_idx}: {num_groups} groups is not power of two"));
            }
        }
        Ok(())
    }

    /// Validates that no operation group ends with an operation that has an immediate value.
    /// Also validates that the last operation group in a batch cannot contain operations
    /// requiring immediate values.
    fn validate_no_immediate_endings(&self) -> Result<(), String> {
        for (batch_idx, batch) in self.op_batches.iter().enumerate() {
            let num_groups = batch.num_groups();
            let indptr = batch.indptr();
            let ops = batch.ops();

            // Check each group in the batch
            for group_idx in 0..num_groups {
                let group_start = indptr[group_idx];
                let group_end = indptr[group_idx + 1];

                // Skip empty groups (they contain immediate values, not operations)
                if group_start == group_end {
                    continue;
                }

                let group_ops = &ops[group_start..group_end];

                // Check if this is the last group in the batch
                let is_last_group = group_idx == num_groups - 1;

                if is_last_group {
                    // Last group in a batch cannot contain ANY operations requiring immediate
                    // values
                    for (op_idx, op) in group_ops.iter().enumerate() {
                        if op.imm_value().is_some() {
                            return Err(format!(
                                "Batch {batch_idx}, group {group_idx}: operation at index {op_idx} requires immediate value, but this is the last group in batch"
                            ));
                        }
                    }
                } else {
                    // Non-last groups: check that the last operation doesn't require an immediate
                    if let Some(last_op) = group_ops.last()
                        && last_op.imm_value().is_some()
                    {
                        return Err(format!(
                            "Batch {batch_idx}, group {group_idx}: ends with operation requiring immediate value"
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Validates that OpBatch structure is consistent and won't cause panics during access.
    /// Checks:
    /// - num_groups <= BATCH_SIZE
    /// - indptr array is monotonic non-decreasing
    /// - indptr values are within ops bounds
    /// - each group has at most GROUP_SIZE operations
    fn validate_batch_structure(&self) -> Result<(), String> {
        for (batch_idx, batch) in self.op_batches.iter().enumerate() {
            // Check num_groups is within bounds
            if batch.num_groups() > BATCH_SIZE {
                return Err(format!(
                    "Batch {}: num_groups {} exceeds maximum {}",
                    batch_idx,
                    batch.num_groups(),
                    BATCH_SIZE
                ));
            }

            // Check indptr array consistency
            let indptr = batch.indptr();
            let ops = batch.ops();

            // Full array must be monotonic for serialization (delta encoding)
            for i in 0..indptr.len() - 1 {
                if indptr[i] > indptr[i + 1] {
                    return Err(format!(
                        "Batch {}: indptr[{}] {} > indptr[{}] {} - full array not monotonic (required for serialization)",
                        batch_idx,
                        i,
                        indptr[i],
                        i + 1,
                        indptr[i + 1]
                    ));
                }
            }

            let ops_len = ops.len();
            if indptr[indptr.len() - 1] != ops_len {
                return Err(format!(
                    "Batch {}: final indptr value {} doesn't match ops.len() {}",
                    batch_idx,
                    indptr[indptr.len() - 1],
                    ops_len
                ));
            }

            // Check that each group has at most GROUP_SIZE operations
            for group_idx in 0..batch.num_groups() {
                let group_start = indptr[group_idx];
                let group_end = indptr[group_idx + 1];
                let group_size = group_end - group_start;

                if group_size > GROUP_SIZE {
                    return Err(format!(
                        "Batch {batch_idx}, group {group_idx}: contains {group_size} operations, exceeds maximum {GROUP_SIZE}"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validates that immediate values are committed to empty groups and match group contents.
    /// Checks:
    /// - operation group encodings match committed group values
    /// - each immediate maps to an empty group slot
    /// - immediate group values equal the push immediate
    /// - immediate placement does not exceed num_groups or batch size
    fn validate_immediate_commitment(&self) -> Result<(), String> {
        for (batch_idx, batch) in self.op_batches.iter().enumerate() {
            let num_groups = batch.num_groups();
            let indptr = batch.indptr();
            let ops = batch.ops();
            let groups = batch.groups();

            let mut immediate_slots = [false; BATCH_SIZE];

            for group_idx in 0..num_groups {
                let group_start = indptr[group_idx];
                let group_end = indptr[group_idx + 1];

                if group_start == group_end {
                    continue;
                }

                let mut group_value: u64 = 0;
                for (local_op_idx, op) in ops[group_start..group_end].iter().enumerate() {
                    let opcode = op.op_code() as u64;
                    group_value |= opcode << (Operation::OP_BITS * local_op_idx);
                }
                if groups[group_idx] != Felt::new_unchecked(group_value) {
                    return Err(format!(
                        "Batch {batch_idx}, group {group_idx}: committed opcode group does not match operations"
                    ));
                }

                let (placements, _next_group_idx) = collect_immediate_placements(
                    ops,
                    indptr,
                    group_idx,
                    BATCH_SIZE,
                    Some(num_groups),
                )
                .map_err(|err| format!("Batch {batch_idx}: {err}"))?;

                for (imm_group_idx, imm_value) in placements {
                    if groups[imm_group_idx] != imm_value {
                        return Err(format!(
                            "Batch {batch_idx}: push immediate value mismatch at index {imm_group_idx}"
                        ));
                    }
                    immediate_slots[imm_group_idx] = true;
                }
            }

            for group_idx in 0..num_groups {
                if indptr[group_idx] == indptr[group_idx + 1]
                    && !immediate_slots[group_idx]
                    && groups[group_idx] != ZERO
                {
                    return Err(format!(
                        "Batch {batch_idx}, group {group_idx}: empty group must be zero"
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validates that padding metadata matches batch contents.
    /// - Empty groups cannot be marked as padded.
    /// - Padded groups must end with a NOOP operation.
    fn validate_padding_semantics(&self) -> Result<(), String> {
        for (batch_idx, batch) in self.op_batches.iter().enumerate() {
            batch
                .validate_padding_semantics()
                .map_err(|err| format!("Batch {batch_idx}: {err}"))?;
        }

        Ok(())
    }
}

// PRETTY PRINTING
// ================================================================================================

impl BasicBlockNode {
    pub(super) fn to_display<'a>(&'a self, _mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        self.clone()
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        _mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        self.clone()
    }
}

// MAST NODE TRAIT IMPLEMENTATION
// ================================================================================================

impl MastNodeExt for BasicBlockNode {
    /// Returns a commitment to this basic block.
    fn digest(&self) -> Word {
        self.digest
    }

    fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn fmt::Display + 'a> {
        Box::new(BasicBlockNode::to_display(self, mast_forest))
    }

    fn to_pretty_print<'a>(&'a self, mast_forest: &'a MastForest) -> Box<dyn PrettyPrint + 'a> {
        Box::new(BasicBlockNode::to_pretty_print(self, mast_forest))
    }

    fn has_children(&self) -> bool {
        false
    }

    fn append_children_to(&self, _target: &mut Vec<MastNodeId>) {
        // No children for basic blocks
    }

    fn for_each_child<F>(&self, _f: F)
    where
        F: FnMut(MastNodeId),
    {
        // BasicBlockNode has no children
    }

    fn domain(&self) -> Felt {
        Self::DOMAIN
    }

    type Builder = BasicBlockNodeBuilder;

    fn to_builder(self, _forest: &MastForest) -> Self::Builder {
        // Use from_op_batches to avoid re-batching existing operation batches.
        BasicBlockNodeBuilder::from_op_batches(self.op_batches, self.digest)
    }
}

impl PrettyPrint for BasicBlockNode {
    #[rustfmt::skip]
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        // e.g. `basic_block a b c end`
        let single_line = const_text("basic_block")
            + const_text(" ")
            + self
                .operations()
                .map(PrettyPrint::render)
                .reduce(|acc, doc| acc + const_text(" ") + doc)
                .unwrap_or_default()
            + const_text(" ")
            + const_text("end");

        // e.g. `
        // basic_block
        //     a
        //     b
        //     c
        // end
        // `

        let multi_line = indent(
            4,
            const_text("basic_block")
                + nl()
                + self
                    .operations()
                    .map(PrettyPrint::render)
                    .reduce(|acc, doc| acc + nl() + doc)
                    .unwrap_or_default(),
        ) + nl()
            + const_text("end");

        single_line | multi_line
    }
}

impl fmt::Display for BasicBlockNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.pretty_print(f)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Raw-indexed prefix: how many paddings strictly before raw index r
///
/// This struct provides O(1) lookup for converting raw operation indices to padded indices.
/// For any raw index r, `raw_to_padded[r] = count of padding ops strictly before raw index r`.
///
/// Length: `raw_ops + 1` (includes sentinel entry at `r == raw_ops`)
/// Usage: `padded_idx = r + raw_to_padded[r]` (addition)
#[derive(Debug, Clone)]
pub struct RawToPaddedPrefix(Vec<usize>);

impl RawToPaddedPrefix {
    /// Build a raw-indexed prefix array from op batches.
    ///
    /// For each raw index r, records how many padding operations have been inserted before r.
    /// Includes a sentinel entry at `r == raw_ops`.
    pub fn new(op_batches: &[OpBatch]) -> Self {
        let mut v = Vec::new();
        let mut pads_so_far = 0usize;

        for b in op_batches {
            let n = b.num_groups();
            let indptr = b.indptr();
            let padding = b.padding();

            for g in 0..n {
                let group_len = indptr[g + 1] - indptr[g];
                let has_pad = padding[g] as usize;
                let raw_in_g = group_len - has_pad;

                // For each raw op, record how many paddings were before it.
                v.extend(repeat_n(pads_so_far, raw_in_g));

                // After the group's raw ops, account for the (optional) padding op.
                pads_so_far += has_pad; // adds 1 if there is a padding, else 0
            }
        }

        // Extra prefix slot for r == raw_ops
        v.push(pads_so_far);
        RawToPaddedPrefix(v)
    }
}

/// Get the number of padding operations before raw index r.
///
/// ## Sentinel Access
///
/// The extra prefix slot supports internal raw end-of-block mappings.
impl core::ops::Index<usize> for RawToPaddedPrefix {
    type Output = usize;
    #[inline]
    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

/// Padded-indexed prefix: how many paddings strictly before padded index p
///
/// This struct provides O(1) lookup for converting padded operation indices to raw indices.
/// For any padded index p, `padded_to_raw[p] = count of padding ops strictly before padded index
/// p`.
///
/// Length: `padded_ops + 1` (includes extra entry at `p == padded_ops`)
/// Usage: `raw_idx = p - padded_to_raw[p]` (subtraction)
#[derive(Debug, Clone)]
pub struct PaddedToRawPrefix(Vec<usize>);

impl PaddedToRawPrefix {
    /// Build a padded-indexed prefix array from op batches.
    ///
    /// Simulates emission of the padded sequence, recording padding count before each position.
    /// Includes an extra entry at `p == padded_ops` for internal end-of-block mappings.
    pub fn new(op_batches: &[OpBatch]) -> Self {
        // Exact capacity to avoid reallocations: sum of per-group lengths across all batches.
        let padded_ops = op_batches
            .iter()
            .map(|b| {
                let n = b.num_groups();
                let indptr = b.indptr();
                indptr[1..=n]
                    .iter()
                    .zip(&indptr[..n])
                    .map(|(end, start)| end - start)
                    .sum::<usize>()
            })
            .sum::<usize>();

        let mut v = Vec::with_capacity(padded_ops + 1);
        let mut pads_so_far = 0usize;

        for b in op_batches {
            let n = b.num_groups();
            let indptr = b.indptr();
            let padding = b.padding();

            for g in 0..n {
                let group_len = indptr[g + 1] - indptr[g];
                let has_pad = padding[g] as usize;
                let raw_in_g = group_len - has_pad;

                // Emit raw ops of the group.
                v.extend(repeat_n(pads_so_far, raw_in_g));

                // Emit the optional padding op.
                if has_pad == 1 {
                    v.push(pads_so_far);
                    pads_so_far += 1; // subsequent positions see one more padding before them
                }
            }
        }

        // Extra prefix slot at p == padded_ops
        v.push(pads_so_far);

        PaddedToRawPrefix(v)
    }
}

/// Get the number of padding operations before padded index p.
///
/// ## Sentinel Access
///
/// The extra prefix slot supports internal padded end-of-block mappings.
impl core::ops::Index<usize> for PaddedToRawPrefix {
    type Output = usize;
    #[inline]
    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

/// Groups the provided operations into batches and computes the hash of the block.
fn batch_and_hash_ops(ops: &[Operation]) -> (Vec<OpBatch>, Word) {
    // Group the operations into batches.
    let batches = batch_ops(ops);

    // Compute the hash of all operation groups.
    let op_groups: Vec<Felt> = batches.iter().flat_map(|batch| batch.groups).collect();
    let hash = hasher::hash_elements(&op_groups);

    (batches, hash)
}

fn fingerprint_basic_block_error_codes(block_digest: Word, op_batches: &[OpBatch]) -> Word {
    let error_code_data = serialize_basic_block_error_codes(op_batches);
    if error_code_data.is_empty() {
        return block_digest;
    }

    let data_len = error_code_data.len() as u64;
    let mut elements = Vec::with_capacity(7 + error_code_data.len().div_ceil(4));
    elements.push(ERROR_CODE_FINGERPRINT_DOMAIN);
    elements.extend_from_slice(block_digest.as_elements());
    elements.push(Felt::from_u32(data_len as u32));
    elements.push(Felt::from_u32((data_len >> 32) as u32));
    elements.extend(bytes_to_packed_u32_elements(&error_code_data));
    hasher::hash_elements(&elements)
}

fn serialize_basic_block_error_codes(op_batches: &[OpBatch]) -> Vec<u8> {
    let mut data = Vec::new();

    for (raw_op_idx, op) in op_batches.iter().flat_map(OpBatch::raw_ops).enumerate() {
        if matches!(op, Operation::Assert(_) | Operation::U32assert2(_) | Operation::MpVerify(_)) {
            data.extend_from_slice(&(raw_op_idx as u64).to_le_bytes());
            op.write_into(&mut data);
        }
    }

    data
}

/// Groups the provided operations into batches as described in the docs for this module (i.e., up
/// to 9 operations per group, and 8 groups per batch).
fn batch_ops(ops: &[Operation]) -> Vec<OpBatch> {
    let mut batches = Vec::<OpBatch>::new();
    let mut batch_acc = OpBatchAccumulator::new();

    for op in ops.iter().copied() {
        // If the operation cannot be accepted into the current accumulator, add the contents of
        // the accumulator to the list of batches and start a new accumulator.
        if !batch_acc.can_accept_op(op) {
            let batch = batch_acc.into_batch();
            batch_acc = OpBatchAccumulator::new();

            batches.push(batch);
        }

        // Add the operation to the accumulator.
        batch_acc.add_op(op);
    }

    // Make sure we finished processing the last batch.
    if !batch_acc.is_empty() {
        let batch = batch_acc.into_batch();
        batches.push(batch);
    }

    batches
}

// ------------------------------------------------------------------------------------------------
/// Represents the operation data for a [`BasicBlockNodeBuilder`].
#[derive(Debug)]
enum OperationData {
    /// Raw operations.
    Raw { operations: Vec<Operation> },
    /// Pre-batched operations.
    Batched { op_batches: Vec<OpBatch> },
}

/// Builder for creating [`BasicBlockNode`] instances.
#[derive(Debug)]
pub struct BasicBlockNodeBuilder {
    operation_data: OperationData,
    digest: Option<Word>,
}

impl BasicBlockNodeBuilder {
    /// Creates a new builder for a BasicBlockNode with the specified operations.
    pub fn new(operations: Vec<Operation>) -> Self {
        Self {
            operation_data: OperationData::Raw { operations },
            digest: None,
        }
    }

    /// Creates a builder from pre-existing OpBatches and a trusted digest.
    ///
    /// This constructor is used when operations are already batched, such as during
    /// deserialization. The provided digest is preserved as-is; it is not recomputed or checked
    /// against the batches by the builder. Callers that accept untrusted input must validate the
    /// resulting forest before use.
    pub(crate) fn from_op_batches(op_batches: Vec<OpBatch>, digest: Word) -> Self {
        Self {
            operation_data: OperationData::Batched { op_batches },
            digest: Some(digest),
        }
    }

    /// Creates a builder from already-batched operations and preserves the provided digest.
    ///
    /// This is used by the assembly builder when it has already formed operation batches while
    /// pending nodes were still builder-local references. The digest is treated as trusted node
    /// identity and is not recomputed by this builder.
    #[doc(hidden)]
    pub fn from_op_batches_preserving_digest(op_batches: Vec<OpBatch>, digest: Word) -> Self {
        Self::from_op_batches(op_batches, digest)
    }

    /// Builds the BasicBlockNode.
    pub fn build(self) -> Result<BasicBlockNode, MastForestError> {
        let (op_batches, digest) = match self.operation_data {
            OperationData::Raw { operations } => {
                if operations.is_empty() {
                    return Err(MastForestError::EmptyBasicBlock);
                }

                let (op_batches, computed_digest) = batch_and_hash_ops(&operations);

                // Use the forced digest if provided, otherwise use the computed digest
                let digest = self.digest.unwrap_or(computed_digest);

                (op_batches, digest)
            },
            OperationData::Batched { op_batches } => {
                if op_batches.is_empty() {
                    return Err(MastForestError::EmptyBasicBlock);
                }

                let digest = self.digest.expect("digest must be set for batched operations");

                (op_batches, digest)
            },
        };

        Ok(BasicBlockNode { op_batches, digest })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl BasicBlockNodeBuilder {
    pub fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let node = self.build()?;
        forest
            .nodes
            .push(MastNode::Block(node))
            .map_err(|_| MastForestError::TooManyNodes)
    }
}

impl MastForestContributor for BasicBlockNodeBuilder {
    fn fingerprint_for_node(
        &self,
        _context: &impl MastNodeContext,
        _hash_by_node_id: &impl LookupByIdx<MastNodeId, Word>,
    ) -> Result<Word, MastForestError> {
        let (op_batches, digest) = match &self.operation_data {
            OperationData::Raw { operations } => {
                // Compute digest - use forced digest if available, otherwise compute normally
                let (op_batches, computed_digest) = batch_and_hash_ops(operations);
                (op_batches, self.digest.unwrap_or(computed_digest))
            },
            OperationData::Batched { op_batches } => {
                let digest = self.digest.expect("digest must be set for batched operations");
                (op_batches.clone(), digest)
            },
        };

        Ok(fingerprint_basic_block_error_codes(digest, &op_batches))
    }

    fn remap_children(self, _remapping: &impl LookupByIdx<MastNodeId, MastNodeId>) -> Self {
        // BasicBlockNode has no children to remap
        self
    }

    fn with_digest(mut self, digest: Word) -> Self {
        self.digest = Some(digest);
        self
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for BasicBlockNodeBuilder {
    type Parameters = arbitrary::BasicBlockNodeParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        use super::arbitrary::op_non_control_sequence_strategy;

        op_non_control_sequence_strategy(params.max_ops_len).prop_map(Self::new).boxed()
    }
}
