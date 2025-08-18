use alloc::vec::Vec;

use super::{BATCH_SIZE, Felt, GROUP_SIZE, Operation, ZERO};

// OPERATION BATCH
// ================================================================================================

/// A batch of operations in a span block.
///
/// An operation batch consists of up to 8 operation groups, with each group containing up to 9
/// operations or a single immediate value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpBatch {
    pub(super) ops: Vec<Operation>,
    pub(super) groups: [Felt; BATCH_SIZE],
    pub(super) op_counts: [usize; BATCH_SIZE],
    pub(super) num_groups: usize,
}

impl OpBatch {
    /// Returns a list of operations contained in this batch.
    ///
    /// Note: the processor will insert NOOP operations to fill out the groups, so the true number
    /// of operations in the batch may be larger than the number of operations reported by this
    /// method.
    pub fn ops(&self) -> &[Operation] {
        &self.ops
    }

    /// Returns a list of operation groups contained in this batch.
    ///
    /// Each group is represented by a single field element.
    pub fn groups(&self) -> &[Felt; BATCH_SIZE] {
        &self.groups
    }

    /// Returns the number of non-decorator operations for each operation group.
    ///
    /// Number of operations for groups containing immediate values is set to 0.
    pub fn op_counts(&self) -> &[usize; BATCH_SIZE] {
        &self.op_counts
    }

    /// Returns the number of groups in this batch.
    pub fn num_groups(&self) -> usize {
        self.num_groups
    }
}

// OPERATION BATCH ACCUMULATOR
// ================================================================================================

/// An accumulator used in construction of operation batches.
pub(super) struct OpBatchAccumulator {
    /// A list of operations in this batch, including decorators.
    ops: Vec<Operation>,
    /// Values of operation groups, including immediate values.
    groups: [Felt; BATCH_SIZE],
    /// Number of non-decorator operations in each operation group. Operation count for groups
    /// with immediate values is set to 0.
    op_counts: [usize; BATCH_SIZE],
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
    /// Returns a blank [OpBatchAccumulator].
    pub fn new() -> Self {
        Self {
            ops: Vec::new(),
            groups: [ZERO; BATCH_SIZE],
            op_counts: [0; BATCH_SIZE],
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
            self.next_group_idx += 1;
        }

        // add the opcode to the group and increment the op index pointer
        let opcode = op.op_code() as u64;
        self.group |= opcode << (Operation::OP_BITS * self.op_idx);
        self.ops.push(op);
        self.op_idx += 1;
    }

    /// Convert the accumulator into an [OpBatch].
    pub fn into_batch(mut self) -> OpBatch {
        // make sure the last group gets added to the group array; we also check the op_idx to
        // handle the case when a group contains a single NOOP operation.
        if self.group != 0 || self.op_idx != 0 {
            self.groups[self.group_idx] = Felt::new(self.group);
            self.op_counts[self.group_idx] = self.op_idx;
        }

        OpBatch {
            ops: self.ops,
            groups: self.groups,
            op_counts: self.op_counts,
            num_groups: self.next_group_idx,
        }
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Saves the current group into the group array, advances current and next group pointers,
    /// and resets group content.
    pub(super) fn finalize_op_group(&mut self) {
        self.groups[self.group_idx] = Felt::new(self.group);
        self.op_counts[self.group_idx] = self.op_idx;

        self.group_idx = self.next_group_idx;
        self.next_group_idx = self.group_idx + 1;

        self.op_idx = 0;
        self.group = 0;
    }
}

#[cfg(test)]
mod accumulator_tests {
    use proptest::prelude::*;
    use crate::mast::node::basic_block_node::tests::op_non_control_sequence_strategy;
    use super::*;

    proptest!{
    #[test]
    fn test_can_accept_ops(ops in op_non_control_sequence_strategy(25)){
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
    fn test_add_op(ops in op_non_control_sequence_strategy(30)){
        let mut acc = OpBatchAccumulator::new();
        for op in ops {
            let init_len = acc.ops.len();
            let init_op_idx = acc.op_idx;
            let init_group_idx = acc.group_idx;
            let init_next_group_idx = acc.next_group_idx;
            let init_ops = acc.ops.clone();
            let init_op_counts = acc.op_counts.clone();
            let init_groups = acc.groups.clone();
            let init_group = acc.group.clone();
            if acc.can_accept_op(op){
                acc.add_op(op);
                // the op was stored
                assert_eq!(acc.ops.len(), init_len + 1);
                // .. at the end of ops
                assert_eq!(*acc.ops.last().unwrap(), op);
                // we never edit older ops, older op counts, or older groups
                assert_eq!(acc.ops[..init_len], init_ops);
                assert_eq!(init_op_counts[..init_group_idx], acc.op_counts[..init_group_idx]);
                assert_eq!(init_groups[..init_group_idx], acc.groups[..init_group_idx]);
                // the group value has changed in all cases
                assert_ne!(acc.group, init_group);
                // we bump the group iff it's full, or we're adding an immediate at the penultimate position
                if acc.group_idx == init_group_idx {
                    assert!(init_op_idx < GROUP_SIZE);
                    // we only change the groups array for an immediate in case the group isn't full
                    if op.imm_value().is_none() {
                        assert_eq!(init_groups, acc.groups);
                    }
                    // no change in group -> no change in op counts
                    assert_eq!(acc.op_counts, init_op_counts);
                } else {
                    assert_eq!(acc.group_idx, init_next_group_idx);
                    assert!(init_op_idx == GROUP_SIZE || op.imm_value().is_some() && init_op_idx + 1 == GROUP_SIZE);
                    // we update the groups array at finalization at least (and possibly for an imemdiate)
                    assert_ne!(init_groups, acc.groups);
                    assert_eq!(acc.op_counts[init_group_idx], init_op_idx);
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