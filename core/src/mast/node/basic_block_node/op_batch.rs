use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{BATCH_SIZE, Felt, GROUP_SIZE, Operation, ZERO};

// OPERATION BATCH
// ================================================================================================

/// A batch of operations in a span block.
///
/// An operation batch consists of up to 8 operation groups, with each group containing up to 9
/// operations or a single immediate value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OpBatch {
    /// A list of operations in this batch, including padding noops.
    pub(super) ops: Vec<Operation>,
    /// Indexes marking the start and end of each group in the ops array.
    ///
    /// Group i is at `self.ops[self.indptr[i]..self.indptr[i+1]]`. Groups with immediate values
    /// have zero-length slices.
    ///
    /// Only `[0..num_groups+1]` is valid data. The tail is undefined but must be monotonic
    /// (filled with final ops count) for delta encoding during serialization.
    pub(super) indptr: [usize; Self::BATCH_SIZE_PLUS_ONE],
    /// Whether each group had padding added. Only `[0..num_groups]` is valid.
    pub(super) padding: [bool; BATCH_SIZE],
    /// Group hashes and immediate values. Only `[0..num_groups]` is valid.
    pub(super) groups: [Felt; BATCH_SIZE],
    /// Number of groups. Determines valid prefix sizes: indptr `[0..num_groups+1]`, padding and
    /// groups `[0..num_groups]`.
    pub(super) num_groups: usize,
}

impl OpBatch {
    /// The size of the indptr array, made to maintain its invariant:
    ///
    /// The OpBatch's indptr array maintains the invariant that the i-th group (i <= BATCH_SIZE-1)
    /// is at `self.ops[self.indptr[i]..self.indptr[i+1]]`.
    const BATCH_SIZE_PLUS_ONE: usize = BATCH_SIZE + 1;

    /// Returns a list of operations contained in this batch. This will include padding noops,
    /// if any.
    pub fn ops(&self) -> &[Operation] {
        &self.ops
    }

    /// Returns a list of operations contained in this batch, without any padding noops.
    ///
    /// Note: the processor will insert NOOP operations to fill out the groups, so the true number
    /// of operations in the batch may be larger than the number of operations reported by this
    /// method.
    pub fn raw_ops(&self) -> impl Iterator<Item = &Operation> {
        debug_assert!(self.num_groups == 0 || self.indptr[self.num_groups] != 0, "{:?}", self);
        (0..self.num_groups).flat_map(|group_idx| {
            let padded = self.padding[group_idx];
            let start_idx = self.indptr[group_idx];
            // in a group, operations are padded at the end of the group or not at all
            // here, we're iterating without padding noops
            let end_idx = self.indptr[group_idx + 1] - usize::from(padded);
            self.ops[start_idx..end_idx].iter()
        })
    }

    /// Returns a list of operation groups contained in this batch.
    ///
    /// Each group is represented by a single field element.
    pub fn groups(&self) -> &[Felt; BATCH_SIZE] {
        &self.groups
    }

    /// Returns a list of indexes in the ops array, marking the beginning and end of each group.
    ///
    /// The array maintains the invariant that the i-th group (i <= BATCH_SIZE-1) is at
    /// `self.ops[self.indptr[i]..self.indptr[i+1]]`.
    pub fn indptr(&self) -> &[usize; Self::BATCH_SIZE_PLUS_ONE] {
        &self.indptr
    }

    /// Returns a list of flags marking whether each group of the batch contains a final padding
    /// Noop
    pub fn padding(&self) -> &[bool; BATCH_SIZE] {
        &self.padding
    }

    /// Returns sequences of operations for each group in this batch
    ///
    /// By convention, groups carrying immediate values are empty in this representation
    #[cfg(test)]
    #[doc(hidden)]
    pub(super) fn group_chunks(&self) -> impl Iterator<Item = &[Operation]> {
        self.indptr[..=self.num_groups].windows(2).map(|slice| match slice {
            [start, end] => &self.ops[*start..*end],
            _ => unreachable!("windows invariant violated"),
        })
    }

    /// Returns the end indexes of each group.
    pub fn end_indices(&self) -> &[usize; BATCH_SIZE] {
        debug_assert!(self.indptr.len() == BATCH_SIZE + 1);
        // SAFETY:
        // - indptr is an array of length BATCH_SIZE+1, so elements 1..=BATCH_SIZE form exactly
        //   BATCH_SIZE contiguous `usize`s.
        // - `as_ptr().add(1)` is in-bounds and properly aligned, since `[T; N]` has the same
        //   alignment requirements as `T` (see [layout.array] in the reference)
        // - We immediately reborrow as an immutable reference tied to `&self`.
        unsafe { &*(self.indptr.as_ptr().add(1) as *const [usize; BATCH_SIZE]) }
    }

    /// Returns the number of groups in this batch.
    pub fn num_groups(&self) -> usize {
        self.num_groups
    }

    /// Creates a new OpBatch from its constituent parts.
    ///
    /// This constructor is used during deserialization to reconstruct OpBatches with the exact
    /// structure they had when serialized.
    ///
    /// # Arguments
    /// * `ops` - The operations in this batch (including padding NOOPs)
    /// * `indptr` - Array of group boundary indices
    /// * `padding` - Array of padding flags for each group
    /// * `groups` - Array of group hashes and immediate values
    /// * `num_groups` - Number of groups in this batch
    pub(crate) fn new_from_parts(
        ops: Vec<Operation>,
        indptr: [usize; Self::BATCH_SIZE_PLUS_ONE],
        padding: [bool; BATCH_SIZE],
        groups: [Felt; BATCH_SIZE],
        num_groups: usize,
    ) -> Self {
        let batch = Self { ops, indptr, padding, groups, num_groups };
        #[cfg(debug_assertions)]
        batch.validate_invariants();
        batch
    }

    /// Validates invariants in debug builds: num_groups in range, indptr monotonic (full array),
    /// final indptr equals ops.len().
    #[cfg(debug_assertions)]
    fn validate_invariants(&self) {
        // Validate num_groups is in valid range
        assert!(
            self.num_groups <= BATCH_SIZE,
            "num_groups {} exceeds BATCH_SIZE {}",
            self.num_groups,
            BATCH_SIZE
        );

        // Validate indptr starts at 0
        assert_eq!(self.indptr[0], 0, "indptr must start at 0, got {}", self.indptr[0]);

        // Validate monotonicity in the semantically valid prefix [0..num_groups+1]
        for i in 0..self.num_groups {
            assert!(
                self.indptr[i] <= self.indptr[i + 1],
                "indptr not monotonic in valid prefix: indptr[{}]={} > indptr[{}]={}",
                i,
                self.indptr[i],
                i + 1,
                self.indptr[i + 1]
            );
        }

        // Validate monotonicity across ENTIRE array (required for serialization)
        for i in 0..Self::BATCH_SIZE_PLUS_ONE - 1 {
            assert!(
                self.indptr[i] <= self.indptr[i + 1],
                "indptr not monotonic at index {}: indptr[{}]={} > indptr[{}]={} \
                 (full array monotonicity required for delta encoding)",
                i,
                i,
                self.indptr[i],
                i + 1,
                self.indptr[i + 1]
            );
        }

        // Validate final indptr value matches ops length
        let final_indptr = self.indptr[Self::BATCH_SIZE_PLUS_ONE - 1];
        assert_eq!(
            final_indptr,
            self.ops.len(),
            "final indptr value {} doesn't match ops.len() {}",
            final_indptr,
            self.ops.len()
        );
    }

    /// Returns the (op_group_idx, op_idx_in_group) given an operation index in the batch. Returns
    /// `None` if the index is out of bounds.
    ///
    /// This uses binary search (`partition_point`) on the group end indices to find the
    /// containing group. For batches with many operations, this can be expensive when
    /// called repeatedly.
    ///
    /// # Performance Consideration
    /// For iterating over all operations in a batch, prefer using `iter_with_groups()`
    /// which tracks group boundaries incrementally in O(1) per operation rather than
    /// O(log m) per operation, where m is the number of groups.
    #[must_use]
    pub fn op_idx_in_batch_to_group(&self, op_idx_in_batch: usize) -> Option<(usize, usize)> {
        if op_idx_in_batch >= self.ops.len() {
            return None;
        }

        let group_idx = {
            let n = self.num_groups();
            // Ends of groups (length n), monotonic non-decreasing (zero-length groups allowed).
            let ends = &self.indptr[1..=n];

            // first index where end > op_idx_in_batch
            let group_idx = ends.partition_point(|&end| end <= op_idx_in_batch);
            debug_assert!(group_idx < n);

            group_idx
        };

        Some((group_idx, op_idx_in_batch - self.indptr[group_idx]))
    }

    /// Returns an iterator over operations in the batch with their group information.
    ///
    /// This iterator yields tuples of (group_idx, op_idx_in_group, operation) for each operation
    /// in the batch, tracking group boundaries incrementally without binary search.
    ///
    /// # Returns
    /// An iterator that produces tuples containing:
    /// - `group_idx`: Index of the operation group within the batch (0-7)
    /// - `op_idx_in_group`: Index of the operation within its group (0-8)
    /// - `operation`: Reference to the operation itself
    ///
    /// This is significantly more efficient than calling `op_idx_in_batch_to_group()` for each
    /// operation because it tracks group boundaries incrementally instead of using binary search
    /// for each operation (which would be O(n * log m) total, where m is the number of groups,
    /// and n is the number of operations).
    pub fn iter_with_groups(&self) -> OpBatchIterator<'_> {
        OpBatchIterator::new(self)
    }

    /// Returns the index of the first group that contains operations that comes after
    /// `after_this_group_index`, if any.
    ///
    /// Since groups either contain immediate values or operations, this is equivalent to skipping
    /// all groups that contain immediate values after `after_this_group_index` and returns the
    /// index of the first group that contains operations.
    pub fn next_op_group_index(&self, after_this_group_index: usize) -> Option<usize> {
        // when indptr[i] == indptr[i+1], the group has no operations - and therefore carries an
        // immediate value
        let is_op_group = |group_idx: usize| self.indptr[group_idx] != self.indptr[group_idx + 1];

        ((after_this_group_index + 1)..self.num_groups())
            .find(|&candidate_group_index| is_op_group(candidate_group_index))
    }
}

// OPERATION BATCH ACCUMULATOR
// ================================================================================================

/// An accumulator used in construction of operation batches.
pub(super) struct OpBatchAccumulator {
    /// A list of operations in this batch, including noops.
    ops: Vec<Operation>,
    /// An array of indexes in the ops array, marking the beginning and end of each group.
    /// The array maintains the invariant that the i-th group (i <= BATCH_SIZE-1) is at
    /// `self.ops[self.indptr[i]..self.indptr[i+1]]`.
    indptr: [usize; OpBatch::BATCH_SIZE_PLUS_ONE],
    /// An array of bits representing whether a group had undergone padding with a
    /// noop at the end of the group.
    padding: [bool; BATCH_SIZE],
    /// Value of groups in the batch, which includes operations and immediate values.
    groups: [Felt; BATCH_SIZE],
    /// Value of the currently active op group.
    group: u64,
    /// Index of the next opcode in the current group.
    op_idx: usize,
    /// index of the current group in the batch.
    group_idx: usize,
    // Index of the next free group in the batch.
    next_group_idx: usize,
}

impl OpBatchAccumulator {
    // an impossible index into the ops vec (which max size if BATCH_SIZE * GROUP_SIZE)
    #[doc(hidden)]
    const INVALID_IDX: usize = BATCH_SIZE * GROUP_SIZE + 1;

    /// Returns a blank [OpBatchAccumulator].
    pub fn new() -> Self {
        Self {
            ops: Vec::new(),
            indptr: [0; OpBatch::BATCH_SIZE_PLUS_ONE],
            padding: [false; BATCH_SIZE],
            groups: [ZERO; BATCH_SIZE],
            group: 0,
            op_idx: 0,
            group_idx: 0,
            next_group_idx: 1,
        }
    }

    /// Returns true if this accumulator does not contain any operations.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Returns true if this accumulator can accept the specified operation.
    ///
    /// An accumulator may not be able accept an operation for the following reasons:
    /// - There is no more space in the underlying batch (e.g., the 8th group of the batch already
    ///   contains 9 operations).
    /// - There is no space for the immediate value carried by the operation (e.g., the 8th group is
    ///   only partially full, but we are trying to add a PUSH operation).
    /// - The alignment rules require that the operation overflows into the next group, and if this
    ///   happens, there will be no space for the operation or its immediate value.
    pub fn can_accept_op(&self, op: Operation) -> bool {
        if op.imm_value().is_some() {
            // an operation carrying an immediate value cannot be the last one in a group; so, we
            // check if we need to move the operation to the next group. in either case, we need
            // to make sure there is enough space for the immediate value as well.
            if self.op_idx < GROUP_SIZE - 1 {
                self.next_group_idx < BATCH_SIZE
            } else {
                self.next_group_idx + 1 < BATCH_SIZE
            }
        } else {
            // check if there is space for the operation in the current group, or if there isn't,
            // whether we can add another group
            self.op_idx < GROUP_SIZE || self.next_group_idx < BATCH_SIZE
        }
    }

    /// Adds the specified operation to this accumulator. It is expected that the specified
    /// operation is not a decorator and that (can_accept_op())[OpBatchAccumulator::can_accept_op]
    /// is called before this function to make sure that the specified operation can be added to
    /// the accumulator.
    pub fn add_op(&mut self, op: Operation) {
        // if the group is full, finalize it and start a new group
        if self.op_idx == GROUP_SIZE {
            self.finalize_op_group();
        }

        // for operations with immediate values, we need to do a few more things
        if let Some(imm) = op.imm_value() {
            // since an operation with an immediate value cannot be the last one in a group, if
            // the operation would be the last one in the group, we need to start a new group
            if self.op_idx == GROUP_SIZE - 1 {
                self.finalize_op_group();
            }

            // save the immediate value at the next group index and advance the next group pointer
            self.groups[self.next_group_idx] = imm;
            // we're adding an immediate value without advancing the group, it will need further
            // correction once we know where this group finishes
            self.indptr[self.next_group_idx] = Self::INVALID_IDX;
            self.next_group_idx += 1;
        }

        // add the opcode to the group and increment the op index pointer
        self.push_op(op);
    }

    /// Convert the accumulator into an [OpBatch].
    pub fn into_batch(mut self) -> OpBatch {
        // Pad to a power of two
        let num_groups = self.next_group_idx;
        let target_num_groups = num_groups.next_power_of_two();
        for _ in num_groups..target_num_groups {
            self.finalize_op_group();
        }

        // make sure the last group gets added to the group array; we also check the op_idx to
        // handle the case when a group contains a single NOOP operation.
        if self.group != 0 || self.op_idx != 0 {
            self.groups[self.group_idx] = Felt::new(self.group);
        }
        self.pad_if_needed();
        self.finalize_indptr();

        // Fill the unused tail of indptr array with the final value to maintain monotonicity
        // This is required for delta encoding which expects indptr to be monotonically
        // non-decreasing
        let final_ops_count = self.ops.len();
        for i in self.next_group_idx..OpBatch::BATCH_SIZE_PLUS_ONE {
            self.indptr[i] = final_ops_count;
        }

        let batch = OpBatch {
            ops: self.ops,
            indptr: self.indptr,
            padding: self.padding,
            groups: self.groups,
            num_groups: self.next_group_idx,
        };

        #[cfg(debug_assertions)]
        batch.validate_invariants();

        batch
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Saves the current group into the group array, advances current and next group pointers,
    /// and resets group content.
    pub(super) fn finalize_op_group(&mut self) {
        // we pad if we are looking at an empty group, or one finishing in an op carrying an
        // immediate
        self.pad_if_needed();
        self.groups[self.group_idx] = Felt::new(self.group);
        self.finalize_indptr();

        self.group_idx = self.next_group_idx;
        self.next_group_idx = self.group_idx + 1;

        self.op_idx = 0;
        self.group = 0;
    }

    /// Saves the start index of the upcoming group (at self.next_group_idx), corrects any groups
    /// created through immediate values.
    #[inline]
    fn finalize_indptr(&mut self) {
        // we are finalizing a group, we now know the start of the upcoming group
        self.indptr[self.next_group_idx] = self.ops.len();
        // we also need to correct the start indexes of groups carrying immediate values, if any,
        let mut uninit_group_idx = self.next_group_idx - 1;
        while uninit_group_idx >= self.group_idx
            && self.indptr[uninit_group_idx] == Self::INVALID_IDX
        {
            // This guarantees the range (within ops) spanned by an immediate value is 0
            self.indptr[uninit_group_idx] = self.ops.len();
            uninit_group_idx -= 1;
        }
    }

    /// Add the opcode to the group and increment the op index pointer
    #[inline]
    fn push_op(&mut self, op: Operation) {
        let opcode = op.op_code() as u64;
        self.group |= opcode << (Operation::OP_BITS * self.op_idx);
        self.ops.push(op);
        self.op_idx += 1;
    }

    /// Check if any padding is needed
    #[inline]
    fn pad_if_needed(&mut self) {
        if self.op_idx == 0 || self.ops.last().is_some_and(|op| op.imm_value().is_some()) {
            debug_assert!(
                self.op_idx < GROUP_SIZE,
                "invariant violated: an immediate can't end a group"
            );
            self.push_op(Operation::Noop);
            self.padding[self.group_idx] = true;
        }
    }
}

/// Iterator over operations in an OpBatch with their group information.
///
/// This iterator yields tuples of (group_idx, op_idx_in_group, operation) for each operation
/// in the batch, tracking group boundaries incrementally without binary search.
///
/// # Fields
/// - `batch`: Reference to the batch being iterated
/// - `current_op_idx`: Current operation index within the batch
/// - `grp_idx`: Current group index tracked incrementally
///
///
/// This is more efficient than calling `op_idx_in_batch_to_group()` for each
/// operation (O(log m) per operation, for m groups) because it tracks group boundaries
/// incrementally using a simple counter check.
pub struct OpBatchIterator<'a> {
    batch: &'a OpBatch,
    current_op_idx: usize,
    grp_idx: usize,
}

impl<'a> OpBatchIterator<'a> {
    /// Creates a new iterator over the operations in the batch.
    pub fn new(batch: &'a OpBatch) -> Self {
        Self { batch, current_op_idx: 0, grp_idx: 0 }
    }
}

impl<'a> Iterator for OpBatchIterator<'a> {
    type Item = (usize, usize, &'a Operation);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_op_idx >= self.batch.ops().len() {
            return None;
        }

        let op = &self.batch.ops()[self.current_op_idx];
        let indptr = self.batch.indptr();

        // Increment grp_idx if we've crossed into the next group
        // Check if current_op_idx >= indptr[self.grp_idx + 1] (start of next group)
        // The while loop skips the groups dedicated to immediates, which are devoid
        // of operations.
        while self.grp_idx + 1 < self.batch.num_groups()
            && self.current_op_idx >= indptr[self.grp_idx + 1]
        {
            self.grp_idx += 1;
        }

        let op_idx_in_group = self.current_op_idx - indptr[self.grp_idx];
        let result = (self.grp_idx, op_idx_in_group, op);

        self.current_op_idx += 1;
        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.batch.ops().len() - self.current_op_idx;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for OpBatchIterator<'a> {}

#[cfg(test)]
mod op_batch_tests {
    use proptest::prelude::*;

    use super::*;
    use crate::mast::{BasicBlockNode, arbitrary::BasicBlockNodeParams};

    #[test]
    fn test_op_idx_in_batch_to_group() {
        // batch:
        // 0: [push, push, push, swap, swap, swap, swap, swap, swap] [2] [3] [4]
        // 4: [swap, swap, swap, swap, swap, swap, swap, swap]
        // 5: [push, swap, swap, swap, swap, swap, swap, swap, swap] [5]
        // 7: [noop]
        let batch = {
            let mut acc = OpBatchAccumulator::new();
            // group 0
            acc.add_op(Operation::Push(Felt::new(2)));
            acc.add_op(Operation::Push(Felt::new(3)));
            acc.add_op(Operation::Push(Felt::new(4)));
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);

            // group 4
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);

            // group 5
            acc.add_op(Operation::Push(Felt::new(5)));
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);

            // group 7: [noop]

            acc.into_batch()
        };
        assert_eq!(batch.num_groups(), 8);

        assert_eq!(batch.op_idx_in_batch_to_group(0), Some((0, 0)));
        assert_eq!(batch.op_idx_in_batch_to_group(5), Some((0, 5)));
        assert_eq!(batch.op_idx_in_batch_to_group(9), Some((4, 0)));
        assert_eq!(batch.op_idx_in_batch_to_group(10), Some((4, 1)));
        assert_eq!(batch.op_idx_in_batch_to_group(16), Some((4, 7)));
        assert_eq!(batch.op_idx_in_batch_to_group(17), Some((5, 0)));
        assert_eq!(batch.op_idx_in_batch_to_group(25), Some((5, 8)));
        assert_eq!(batch.op_idx_in_batch_to_group(26), Some((7, 0)));
        assert_eq!(batch.op_idx_in_batch_to_group(27), None);
    }

    #[test]
    fn test_next_op_group_index() {
        // batch:
        // 0: [push, push, push, swap, swap, swap, swap, swap, swap] [2] [3] [4]
        // 4: [swap, swap, swap, swap, swap, swap, swap, swap]
        // 5: [push, swap, swap, swap, swap, swap, swap, swap, swap] [5]
        // 7: [noop]
        let batch = {
            let mut acc = OpBatchAccumulator::new();
            // group 0
            acc.add_op(Operation::Push(Felt::new(2)));
            acc.add_op(Operation::Push(Felt::new(3)));
            acc.add_op(Operation::Push(Felt::new(4)));
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);

            // group 4
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);

            // group 5
            acc.add_op(Operation::Push(Felt::new(5)));
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);
            acc.add_op(Operation::Swap);

            // group 7: [noop]

            acc.into_batch()
        };
        assert_eq!(batch.num_groups(), 8);

        assert_eq!(batch.next_op_group_index(0), Some(4));
        assert_eq!(batch.next_op_group_index(1), Some(4));
        assert_eq!(batch.next_op_group_index(2), Some(4));
        assert_eq!(batch.next_op_group_index(3), Some(4));
        assert_eq!(batch.next_op_group_index(4), Some(5));
        assert_eq!(batch.next_op_group_index(5), Some(7));
        assert_eq!(batch.next_op_group_index(6), Some(7));
        assert_eq!(batch.next_op_group_index(7), None);
    }

    #[test]
    fn test_op_batch_iterator_edge_cases() {
        // Test with empty batch - it gets padded with a NOOP, so has 1 operation
        let empty_batch = OpBatchAccumulator::new().into_batch();
        assert_eq!(empty_batch.iter_with_groups().count(), 1);

        // Test with single operation
        let mut acc = OpBatchAccumulator::new();
        acc.add_op(Operation::Noop);
        let single_op_batch = acc.into_batch();

        let results: Vec<_> = single_op_batch.iter_with_groups().collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], (0, 0, &Operation::Noop));
    }

    proptest! {
        #[test]
        fn test_op_batch_iterator_arbitrary_large_block(
            // Generate BasicBlockNodes with 73-200 operations to ensure multiple batches
            basic_block in any_with::<BasicBlockNode>(BasicBlockNodeParams {
                max_ops_len: 200,        // Generate blocks with up to 200 operations
                max_pairs: 30,           // Allow more decorators
                max_decorator_id_u32: 100,
            })
        ) {
            // Verify that we actually have a multi-batch block
            prop_assume!(basic_block.num_operations() > 72, "Need multiple batches for meaningful testing");

            // Test all batches in the basic block
            for batch in basic_block.op_batches() {
                // Verify iterator results match op_idx_in_batch_to_group for every operation
                for (op_idx_in_batch, (group_idx, op_idx_in_group, _op)) in
                    batch.iter_with_groups().enumerate()
                {
                    let expected = batch.op_idx_in_batch_to_group(op_idx_in_batch);
                    prop_assert_eq!(
                        expected,
                        Some((group_idx, op_idx_in_group)),
                        "Mismatch for op_idx_in_batch {}: expected {:?}, got ({}, {})",
                        op_idx_in_batch,
                        expected,
                        group_idx,
                        op_idx_in_group
                    );
                }

                // Verify that the iterator produces the correct number of results
                let iterator_count = batch.iter_with_groups().count();
                let expected_count = batch.ops().len();
                prop_assert_eq!(
                    iterator_count, expected_count,
                    "Iterator should produce {} results, got {}",
                    expected_count, iterator_count
                );
            }
        }
    }
}

#[cfg(test)]
mod accumulator_tests {
    use proptest::prelude::*;

    use super::*;
    use crate::mast::node::basic_block_node::arbitrary::op_non_control_sequence_strategy;

    proptest! {
        #[test]
        fn test_can_accept_ops(ops in op_non_control_sequence_strategy(50)){
            let acc = OpBatchAccumulator::new();
            for op in ops {
                let has_imm = op.imm_value().is_some();
                let need_extra_group = has_imm && acc.op_idx >= GROUP_SIZE - 1;

                let can_accept = (!has_imm && acc.op_idx < GROUP_SIZE)
                    || acc.next_group_idx + usize::from(need_extra_group) < BATCH_SIZE;

                assert_eq!(acc.can_accept_op(op), can_accept);
            }
        }

        #[test]
        fn test_add_op(ops in op_non_control_sequence_strategy(50)){
            let mut acc = OpBatchAccumulator::new();
            for op in ops {
                let init_len = acc.ops.len();
                let init_op_idx = acc.op_idx;
                let init_group_idx = acc.group_idx;
                let init_next_group_idx = acc.next_group_idx;
                let init_indptr = acc.indptr;
                let init_ops = acc.ops.clone();
                let init_groups = acc.groups;
                let init_group = acc.group;
                if acc.can_accept_op(op){
                    acc.add_op(op);
                    // the op was stored, perhaps with padding
                    assert!(acc.ops.len() > init_len);
                    // we pad by almost one per batch
                    assert!(acc.ops.len() <= init_len + 2);
                    // .. at the end of ops
                    assert_eq!(*acc.ops.last().unwrap(), op);
                    // we never edit older ops, older op counts, or older groups
                    assert_eq!(acc.ops[..init_len], init_ops);
                    assert_eq!(init_groups[..init_group_idx], acc.groups[..init_group_idx]);
                    assert_eq!(init_indptr[..init_group_idx+1], acc.indptr[..init_group_idx+1]);
                    // the group value has changed in all cases
                    assert_ne!(acc.group, init_group);
                    // we bump the group iff it's full, or we're adding an immediate at the penultimate position
                    if acc.group_idx == init_group_idx {
                        assert!(init_op_idx < GROUP_SIZE);
                        // we only change the groups array for an immediate in case the group isn't full
                        if op.imm_value().is_none() {
                            assert_eq!(init_groups, acc.groups);
                            assert_eq!(init_indptr, acc.indptr);
                        }
                    } else {
                        assert_eq!(acc.group_idx, init_next_group_idx);
                        assert!(init_op_idx == GROUP_SIZE || op.imm_value().is_some() && init_op_idx + 1 == GROUP_SIZE);
                        // we update the groups array at finalization at least (and possibly for an imemdiate)
                        assert_ne!(init_groups, acc.groups);
                        assert_ne!(init_indptr, acc.indptr);
                        // we are now in a group which starts at the just-inserted op
                        assert_eq!(acc.indptr[acc.group_idx], acc.ops.len() - 1);
                    }
                    // we bump the next group iff the op has an immediate or the group is full
                    if acc.next_group_idx == init_next_group_idx {
                        assert!(init_op_idx < GROUP_SIZE && op.imm_value().is_none());
                    } else {
                        // when we add an immediate to a full or next-to-full group,
                        // we overflow it (finalization) and store its immediate value
                        // which bumps the next_group_idx by 2
                        if acc.next_group_idx > init_next_group_idx + 1 {
                            assert!(op.imm_value().is_some());
                            assert!(init_op_idx >=  GROUP_SIZE - 1);
                        }
                    }

                }
            }
        }
    }
}
