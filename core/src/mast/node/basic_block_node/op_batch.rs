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
    /// An array of indexes in the ops array, marking the beginning and end of each group.
    ///
    /// The array maintains the invariant that the i-th group (i <= BATCH_SIZE-1) is at
    /// `self.ops[self.indptr[i]..self.indptr[i+1]]`.
    ///
    /// By convention, the groups containing immediate values have a zero-length slice of the ops
    /// array.
    pub(super) indptr: [usize; Self::BATCH_SIZE_PLUS_ONE],
    /// An array of bits representing whether a group had undergone padding
    pub(super) padding: [bool; BATCH_SIZE],
    /// Value of groups in the batch, which includes operations and immediate values.
    pub(super) groups: [Felt; BATCH_SIZE],
    /// Number of groups in this batch.
    ///
    /// The arrays above are meaningful in their [0..self.num_groups] prefix
    /// (or [0..self.num_groups + 1] in the case of the indptr array).
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

    /// Returns the (op_group_idx, op_idx_in_group) given an operation index in the batch. Returns
    /// `None` if the index is out of bounds.
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

        OpBatch {
            ops: self.ops,
            indptr: self.indptr,
            padding: self.padding,
            groups: self.groups,
            num_groups: self.next_group_idx,
        }
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

#[cfg(test)]
mod op_batch_tests {
    use super::*;

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
