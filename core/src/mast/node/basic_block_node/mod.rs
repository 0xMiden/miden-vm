use alloc::{boxed::Box, vec::Vec};
use core::{
    fmt,
    iter::{Peekable, repeat_n},
    slice::Iter,
};

use miden_crypto::{
    Felt, Word, ZERO,
    hash::{Digest, blake::Blake3_256},
};
use miden_formatting::prettier::PrettyPrint;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    DecoratorList, Operation,
    chiplets::hasher,
    mast::{
        DecoratedOpLink, DecoratorId, MastForest, MastForestError, MastNodeFingerprint, MastNodeId,
    },
};

mod op_batch;
pub use op_batch::OpBatch;
use op_batch::OpBatchAccumulator;

use super::{MastForestContributor, MastNodeErrorContext, MastNodeExt};

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
/// - A batch contains exactly 8 groups.
/// - A group contains exactly 9 operations or 1 immediate value.
/// - NOOPs are used to fill a group or batch when necessary.
/// - An immediate value follows the operation that requires it, using the next available group in
///   the batch. If there are no batches available in the group, then both the operation and its
///   immediate are moved to the next batch.
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct BasicBlockNode {
    /// The primitive operations contained in this basic block.
    ///
    /// The operations are broken up into batches of 8 groups, with each group containing up to 9
    /// operations, or a single immediates. Thus the maximum size of each batch is 72 operations.
    /// Multiple batches are used for blocks consisting of more than 72 operations.
    op_batches: Vec<OpBatch>,
    digest: Word,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    decorators: DecoratorList,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    before_enter: Vec<DecoratorId>,
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    after_exit: Vec<DecoratorId>,
}

// ------------------------------------------------------------------------------------------------
/// Constants
impl BasicBlockNode {
    /// The domain of the basic block node (used for control block hashing).
    pub const DOMAIN: Felt = ZERO;
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl BasicBlockNode {
    /// Returns a new [`BasicBlockNode`] instantiated with the specified operations and decorators.
    ///
    /// Returns an error if:
    /// - `operations` vector is empty.
    pub(in crate::mast) fn new(
        operations: Vec<Operation>,
        decorators: DecoratorList,
    ) -> Result<Self, MastForestError> {
        if operations.is_empty() {
            return Err(MastForestError::EmptyBasicBlock);
        }

        // Validate decorators list (only in debug mode).
        #[cfg(debug_assertions)]
        validate_decorators(operations.len(), &decorators);

        let (op_batches, digest) = batch_and_hash_ops(operations);
        // the prior line may have inserted some padding Noops in the op_batches
        // the decorator mapping should still point to the correct operation when that happens
        let reflowed_decorators = BasicBlockNode::adjust_decorators(decorators, &op_batches);

        Ok(Self {
            op_batches,
            digest,
            decorators: reflowed_decorators,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        })
    }

    // Takes a `DecoratorList` which operation indexes are defined against un-padded operations, and
    // adjusts those indexes to point into the padded `&[OpBatches]` passed as argument.
    //
    // IOW this makes its `decorators` padding-aware, or equivalently "adds" the padding to these
    // decorators
    fn adjust_decorators(decorators: DecoratorList, op_batches: &[OpBatch]) -> DecoratorList {
        let raw2pad = RawToPaddedPrefix::new(op_batches);
        decorators
            .into_iter()
            .map(|(raw_idx, dec_id)| (raw_idx + raw2pad[raw_idx], dec_id))
            .collect()
    }

    /// Returns a new [`BasicBlockNode`] from values that are assumed to be correct.
    /// Should only be used when the source of the inputs is trusted (e.g. deserialization).
    pub(in crate::mast) fn new_unsafe(
        operations: Vec<Operation>,
        decorators: DecoratorList,
        digest: Word,
    ) -> Self {
        assert!(!operations.is_empty());
        let op_batches = batch_ops(operations);
        Self {
            op_batches,
            digest,
            decorators,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
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

    /// Returns a [`DecoratorOpLinkIterator`] which allows us to iterate through the decorator list
    /// of this basic block node while executing operation batches of this basic block node.
    ///
    /// This iterator is intended for e.g. processor consumption, as such a component iterates
    /// differently through block operations: contrarily to e.g. the implementation of
    /// [`MastNodeErrorContext`] this does not include the `before_enter` or `after_exit`
    /// decorators.
    pub fn indexed_decorator_iter(&self) -> DecoratorOpLinkIterator<'_> {
        DecoratorOpLinkIterator::new(&[], &self.decorators, &[], self.num_operations() as usize)
    }

    /// Returns an iterator which allows us to iterate through the decorator list of
    /// this basic block node with op indexes aligned to the "raw" (un-padded)) op
    /// batches of the basic block node.
    ///
    /// Though this adjusts the indexation of op-indexed decorators, this iterator returns all
    /// decorators of the [`BasicBlockNode`] in the order in which they appear in the program.
    /// This includes `before_enter`, op-indexed decorators, and after_exit`.
    pub fn raw_decorator_iter(&self) -> RawDecoratorOpLinkIterator<'_> {
        RawDecoratorOpLinkIterator::new(
            &self.before_enter,
            &self.decorators,
            &self.after_exit,
            &self.op_batches,
        )
    }

    /// Returns an iterator over the operations in the order in which they appear in the program.
    pub fn operations(&self) -> impl Iterator<Item = &Operation> {
        self.op_batches.iter().flat_map(|batch| batch.ops())
    }

    /// Returns an iterator over the un-padded operations in the order in which they
    /// appear in the program.
    pub fn raw_operations(&self) -> impl Iterator<Item = &Operation> {
        self.op_batches.iter().flat_map(|batch| batch.raw_ops())
    }

    /// Returns the total number of operations and decorators in this basic block.
    pub fn num_operations_and_decorators(&self) -> u32 {
        let num_ops: usize = self.num_operations() as usize;
        let num_decorators = self.decorators.len();

        (num_ops + num_decorators)
            .try_into()
            .expect("basic block contains more than 2^32 operations and decorators")
    }

    /// Returns an iterator over all operations and decorator, in the order in which they appear in
    /// the program.
    pub fn iter(&self) -> impl Iterator<Item = OperationOrDecorator<'_>> {
        OperationOrDecoratorIterator::new(self)
    }
}

//-------------------------------------------------------------------------------------------------
/// Mutators
impl BasicBlockNode {
    /// Used to initialize decorators for the [`BasicBlockNode`]. Replaces the existing decorators
    /// with the given ['DecoratorList'].
    pub(in crate::mast) fn set_decorators(&mut self, decorator_list: DecoratorList) {
        self.decorators = decorator_list;
    }
}

impl MastNodeErrorContext for BasicBlockNode {
    /// This iterator returns all decorators of the [`BasicBlockNode`] in the order in which they
    /// appear in the program. This includes `before_enter`, op-indexed decorators, and
    /// `after_exit`.
    fn decorators(&self) -> impl Iterator<Item = DecoratedOpLink> {
        DecoratorOpLinkIterator::new(
            &self.before_enter,
            &self.decorators,
            &self.after_exit,
            self.num_operations() as usize,
        )
    }
}

// PRETTY PRINTING
// ================================================================================================

impl BasicBlockNode {
    pub(super) fn to_display<'a>(&'a self, mast_forest: &'a MastForest) -> impl fmt::Display + 'a {
        BasicBlockNodePrettyPrint { block_node: self, mast_forest }
    }

    pub(super) fn to_pretty_print<'a>(
        &'a self,
        mast_forest: &'a MastForest,
    ) -> impl PrettyPrint + 'a {
        BasicBlockNodePrettyPrint { block_node: self, mast_forest }
    }
}

// MAST NODE TRAIT IMPLEMENTATION
// ================================================================================================

impl MastNodeExt for BasicBlockNode {
    /// Returns a commitment to this basic block.
    fn digest(&self) -> Word {
        self.digest
    }

    fn before_enter(&self) -> &[DecoratorId] {
        &self.before_enter
    }

    fn after_exit(&self) -> &[DecoratorId] {
        &self.after_exit
    }

    /// Sets the provided list of decorators to be executed before this node.
    fn append_before_enter(&mut self, decorator_ids: &[DecoratorId]) {
        self.before_enter.extend_from_slice(decorator_ids);
    }

    /// Sets the provided list of decorators to be executed after this node.
    fn append_after_exit(&mut self, decorator_ids: &[DecoratorId]) {
        self.after_exit.extend_from_slice(decorator_ids);
    }

    /// Removes all decorators from this node.
    fn remove_decorators(&mut self) {
        self.decorators.truncate(0);
        self.before_enter.truncate(0);
        self.after_exit.truncate(0);
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

    fn to_builder(self) -> Self::Builder {
        let operations: Vec<Operation> = self.raw_operations().cloned().collect();
        let un_adjusted_decorators =
            RawDecoratorOpLinkIterator::new(&[], &self.decorators, &[], self.op_batches())
                .collect();

        BasicBlockNodeBuilder::new(operations, un_adjusted_decorators)
            .with_before_enter(self.before_enter)
            .with_after_exit(self.after_exit)
    }
}

struct BasicBlockNodePrettyPrint<'a> {
    block_node: &'a BasicBlockNode,
    mast_forest: &'a MastForest,
}

impl PrettyPrint for BasicBlockNodePrettyPrint<'_> {
    #[rustfmt::skip]
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        // e.g. `basic_block a b c end`
        let single_line = const_text("basic_block")
            + const_text(" ")
            + self.
                block_node
                .iter()
                .map(|op_or_dec| match op_or_dec {
                    OperationOrDecorator::Operation(op) => op.render(),
                    OperationOrDecorator::Decorator(&decorator_id) => self.mast_forest[decorator_id].render(),
                })
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
                    .block_node
                    .iter()
                    .map(|op_or_dec| match op_or_dec {
                        OperationOrDecorator::Operation(op) => op.render(),
                        OperationOrDecorator::Decorator(&decorator_id) => self.mast_forest[decorator_id].render(),
                    })
                    .reduce(|acc, doc| acc + nl() + doc)
                    .unwrap_or_default(),
        ) + nl()
            + const_text("end");

        single_line | multi_line
    }
}

impl fmt::Display for BasicBlockNodePrettyPrint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

// DECORATOR ITERATION
// ================================================================================================

/// Iterator used to iterate through the decorator list of a basic block
/// while executing operation batches of a basic block.
///
/// This lets the caller iterate through a Decorator list with indexes that match the
/// standard (padded) representation of a basic block.
pub struct DecoratorOpLinkIterator<'a> {
    before: Peekable<Iter<'a, DecoratorId>>,
    middle: Peekable<Iter<'a, (usize, DecoratorId)>>,
    after: Peekable<Iter<'a, DecoratorId>>,
    total_ops: usize,
    seg: Segment,
}

// Driver of the Iterators' state machine
enum Segment {
    Before,
    Middle,
    After,
    Done,
}

impl<'a> DecoratorOpLinkIterator<'a> {
    pub fn new(
        before_enter: &'a [DecoratorId],
        decorators: &'a DecoratorList,
        after_exit: &'a [DecoratorId],
        total_operations: usize,
    ) -> Self {
        Self {
            before: before_enter.iter().peekable(),
            middle: decorators.iter().peekable(),
            after: after_exit.iter().peekable(),
            total_ops: total_operations,
            seg: Segment::Before,
        }
    }

    /// Optional: yield only if the next item corresponds to the given op index.
    /// - before_enter items map to op 0
    /// - middle items use their stored position
    /// - after_exit items map to `total_ops`
    //
    // Some decorators are pegged on an operation index equal to the total number of
    // operations since decorators are meant to be executed before the operation
    // they are attached to. This allows them to be executed after the last
    // operation has been executed.
    #[inline]
    pub fn next_filtered(&mut self, pos: usize) -> Option<(usize, DecoratorId)> {
        let should_yield: bool;
        'segwalk: loop {
            match self.seg {
                Segment::Before => {
                    if self.before.peek().is_some() {
                        should_yield = pos == 0;
                        break 'segwalk;
                    }
                    self.seg = Segment::Middle;
                },
                Segment::Middle => {
                    if let Some(&(p, _)) = self.middle.peek() {
                        should_yield = pos == *p;
                        break 'segwalk;
                    }
                    self.seg = Segment::After;
                },
                Segment::After => {
                    if self.after.peek().is_some() {
                        should_yield = pos == self.total_ops;
                        break 'segwalk;
                    }
                    self.seg = Segment::Done;
                },
                Segment::Done => {
                    should_yield = false;
                    break 'segwalk;
                },
            }
        }
        if should_yield { self.next() } else { None }
    }
}

impl<'a> Iterator for DecoratorOpLinkIterator<'a> {
    type Item = (usize, DecoratorId);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.seg {
                Segment::Before => {
                    if let Some(&id) = self.before.next() {
                        return Some((0, id));
                    }
                    self.seg = Segment::Middle;
                },
                Segment::Middle => {
                    if let Some(&(pos, id)) = self.middle.next() {
                        return Some((pos, id));
                    }
                    self.seg = Segment::After;
                },
                Segment::After => {
                    if let Some(&id) = self.after.next() {
                        return Some((self.total_ops, id));
                    }
                    self.seg = Segment::Done;
                },
                Segment::Done => return None,
            }
        }
    }
}

impl<'a> ExactSizeIterator for DecoratorOpLinkIterator<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.before.len() + self.middle.len() + self.after.len()
    }
}

// RAW DECORATOR ITERATION
// ================================================================================================

/// Iterator used to iterate through the decorator list of a span block
/// while executing operation batches of a span block.
///
/// This lets the caller iterate through a Decorator list with indexes that match the
/// raw (unpadded) representation of a basic block.
///
/// IOW this makes its `BasicBlockNode::raw_decorator_iter` padding-unaware, or equivalently
/// "removes" the padding of these decorators
pub struct RawDecoratorOpLinkIterator<'a> {
    before: core::slice::Iter<'a, DecoratorId>,
    middle: core::slice::Iter<'a, (usize, DecoratorId)>, // (adjusted_idx, id)
    after: core::slice::Iter<'a, DecoratorId>,
    pad2raw: PaddedToRawPrefix, // indexed by padded indices
    total_raw_ops: usize,       // count of raw ops
    seg: Segment,
}

impl<'a> RawDecoratorOpLinkIterator<'a> {
    pub fn new(
        before_enter: &'a [DecoratorId],
        decorators: &'a DecoratorList, // contains adjusted indices
        after_exit: &'a [DecoratorId],
        op_batches: &'a [OpBatch],
    ) -> Self {
        let pad2raw = PaddedToRawPrefix::new(op_batches);
        let raw2pad = RawToPaddedPrefix::new(op_batches);
        let total_raw_ops = raw2pad.raw_ops();

        Self {
            before: before_enter.iter(),
            middle: decorators.iter(),
            after: after_exit.iter(),
            pad2raw,
            total_raw_ops,
            seg: Segment::Before,
        }
    }
}

impl<'a> Iterator for RawDecoratorOpLinkIterator<'a> {
    type Item = (usize, DecoratorId);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.seg {
                Segment::Before => {
                    if let Some(&id) = self.before.next() {
                        return Some((0, id));
                    }
                    self.seg = Segment::Middle;
                },
                Segment::Middle => {
                    if let Some(&(padded_idx, id)) = self.middle.next() {
                        let raw_idx = padded_idx - self.pad2raw[padded_idx];
                        return Some((raw_idx, id));
                    }
                    self.seg = Segment::After;
                },
                Segment::After => {
                    if let Some(&id) = self.after.next() {
                        // After-exit decorators attach to the sentinel raw index
                        return Some((self.total_raw_ops, id));
                    }
                    self.seg = Segment::Done;
                },
                Segment::Done => return None,
            }
        }
    }
}

// OPERATION OR DECORATOR
// ================================================================================================

/// Encodes either an [`Operation`] or a [`crate::Decorator`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationOrDecorator<'a> {
    Operation(&'a Operation),
    Decorator(&'a DecoratorId),
}

struct OperationOrDecoratorIterator<'a> {
    node: &'a BasicBlockNode,

    // extra segments
    before: core::slice::Iter<'a, DecoratorId>,
    after: core::slice::Iter<'a, DecoratorId>,

    // operation traversal
    batch_index: usize,
    op_index_in_batch: usize,
    op_index: usize, // across all batches

    // decorators inside the block (sorted by op index)
    decorator_list_next_index: usize,
    seg: Segment,
}

impl<'a> OperationOrDecoratorIterator<'a> {
    fn new(node: &'a BasicBlockNode) -> Self {
        Self {
            node,
            before: node.before_enter().iter(),
            after: node.after_exit().iter(),
            batch_index: 0,
            op_index_in_batch: 0,
            op_index: 0,
            decorator_list_next_index: 0,
            seg: Segment::Before,
        }
    }

    #[inline]
    fn next_decorator_if_due(&mut self) -> Option<OperationOrDecorator<'a>> {
        if let Some((op_idx, deco)) = self.node.decorators.get(self.decorator_list_next_index)
            && *op_idx == self.op_index
        {
            self.decorator_list_next_index += 1;
            Some(OperationOrDecorator::Decorator(deco))
        } else {
            None
        }
    }
}

impl<'a> Iterator for OperationOrDecoratorIterator<'a> {
    type Item = OperationOrDecorator<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.seg {
                Segment::Before => {
                    if let Some(id) = self.before.next() {
                        return Some(OperationOrDecorator::Decorator(id));
                    }
                    self.seg = Segment::Middle;
                },

                Segment::Middle => {
                    // 1) emit any decorators for the current op_index
                    if let Some(d) = self.next_decorator_if_due() {
                        return Some(d);
                    }

                    // 2) otherwise emit the operation at current indices
                    if let Some(batch) = self.node.op_batches.get(self.batch_index) {
                        if let Some(op) = batch.ops.get(self.op_index_in_batch) {
                            self.op_index_in_batch += 1;
                            self.op_index += 1;
                            return Some(OperationOrDecorator::Operation(op));
                        } else {
                            // advance to next batch and retry
                            self.batch_index += 1;
                            self.op_index_in_batch = 0;
                            continue;
                        }
                    } else {
                        // no more ops, decorators flushed through the operation index
                        // and next_decorator_if_due
                        self.seg = Segment::After;
                    }
                },

                Segment::After => {
                    if let Some(id) = self.after.next() {
                        return Some(OperationOrDecorator::Decorator(id));
                    }
                    self.seg = Segment::Done;
                },

                Segment::Done => return None,
            }
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Checks if a given decorators list is valid (only checked in debug mode)
/// - Assert the decorator list is in ascending order.
/// - Assert the last op index in decorator list is less than or equal to the number of operations.
#[cfg(debug_assertions)]
pub(crate) fn validate_decorators(operations_len: usize, decorators: &DecoratorList) {
    if !decorators.is_empty() {
        // check if decorator list is sorted
        for i in 0..(decorators.len() - 1) {
            debug_assert!(decorators[i + 1].0 >= decorators[i].0, "unsorted decorators list");
        }
        // assert the last index in decorator list is less than operations vector length
        debug_assert!(
            operations_len >= decorators.last().expect("empty decorators list").0,
            "last op index in decorator list should be less than or equal to the number of ops"
        );
    }
}

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

        // Sentinel for r == raw_ops
        v.push(pads_so_far);
        RawToPaddedPrefix(v)
    }

    /// Get the total number of raw operations (excluding sentinel).
    #[inline]
    pub fn raw_ops(&self) -> usize {
        self.0.len() - 1
    }
}

/// Get the number of padding operations before raw index r.
///
/// ## Sentinel Access
///
/// Some decorators have an operation index equal to the length of the
/// operations array, to ensure they are executed at the end of the block
/// (since the semantics of the decorator index is that it must be executed
/// before the operation index it points to).
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
/// Length: `padded_ops + 1` (includes sentinel entry at `p == padded_ops`)
/// Usage: `raw_idx = p - padded_to_raw[p]` (subtraction)
#[derive(Debug, Clone)]
pub struct PaddedToRawPrefix(Vec<usize>);

impl PaddedToRawPrefix {
    /// Build a padded-indexed prefix array from op batches.
    ///
    /// Simulates emission of the padded sequence, recording padding count before each position.
    /// Includes a sentinel entry at `p == padded_ops`.
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

        // Sentinel at p == padded_ops
        v.push(pads_so_far);

        PaddedToRawPrefix(v)
    }
}

/// Get the number of padding operations before padded index p.
///
/// ## Sentinel Access
///
/// Some decorators have an operation index equal to the length of the
/// operations array, to ensure they are executed at the end of the block
/// (since the semantics of the decorator index is that it must be executed
/// before the operation index it points to).
impl core::ops::Index<usize> for PaddedToRawPrefix {
    type Output = usize;
    #[inline]
    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

/// Groups the provided operations into batches and computes the hash of the block.
fn batch_and_hash_ops(ops: Vec<Operation>) -> (Vec<OpBatch>, Word) {
    // Group the operations into batches.
    let batches = batch_ops(ops);

    // Compute the hash of all operation groups.
    let op_groups: Vec<Felt> = batches.iter().flat_map(|batch| batch.groups).collect();
    let hash = hasher::hash_elements(&op_groups);

    (batches, hash)
}

/// Groups the provided operations into batches as described in the docs for this module (i.e., up
/// to 9 operations per group, and 8 groups per batch).
fn batch_ops(ops: Vec<Operation>) -> Vec<OpBatch> {
    let mut batches = Vec::<OpBatch>::new();
    let mut batch_acc = OpBatchAccumulator::new();

    for op in ops {
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
/// Builder for creating [`BasicBlockNode`] instances with decorators.
#[derive(Debug)]
pub struct BasicBlockNodeBuilder {
    operations: Vec<Operation>,
    decorators: DecoratorList,
    before_enter: Vec<DecoratorId>,
    after_exit: Vec<DecoratorId>,
}

impl BasicBlockNodeBuilder {
    /// Creates a new builder for a BasicBlockNode with the specified operations and decorators.
    pub fn new(operations: Vec<Operation>, decorators: DecoratorList) -> Self {
        Self {
            operations,
            decorators,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        }
    }

    /// Builds the BasicBlockNode with the specified decorators.
    pub fn build(self) -> Result<BasicBlockNode, MastForestError> {
        if self.operations.is_empty() {
            return Err(MastForestError::EmptyBasicBlock);
        }

        // Validate decorators list (only in debug mode).
        #[cfg(debug_assertions)]
        validate_decorators(self.operations.len(), &self.decorators);

        let (op_batches, digest) = batch_and_hash_ops(self.operations);
        // the prior line may have inserted some padding Noops in the op_batches
        // the decorator mapping should still point to the correct operation when that happens
        let reflowed_decorators = BasicBlockNode::adjust_decorators(self.decorators, &op_batches);

        Ok(BasicBlockNode {
            op_batches,
            digest,
            decorators: reflowed_decorators,
            before_enter: self.before_enter,
            after_exit: self.after_exit,
        })
    }
}

impl MastForestContributor for BasicBlockNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        forest
            .nodes
            .push(self.build()?.into())
            .map_err(|_| MastForestError::TooManyNodes)
    }

    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        _hash_by_node_id: &impl crate::LookupByIdx<MastNodeId, crate::mast::MastNodeFingerprint>,
    ) -> Result<crate::mast::MastNodeFingerprint, MastForestError> {
        // For BasicBlockNode, we need to implement custom logic because BasicBlock has special
        // decorator handling with operation indices that other nodes don't have

        // Compute digest
        let (op_batches, digest) = batch_and_hash_ops(self.operations.clone());

        // Hash before_enter decorators first
        let mut bytes_to_hash = Vec::new();
        for decorator_id in &self.before_enter {
            bytes_to_hash.extend(forest[*decorator_id].fingerprint().as_bytes());
        }

        // Hash op-indexed decorators using the same logic as node.indexed_decorator_iter()
        #[cfg(debug_assertions)]
        validate_decorators(self.operations.len(), &self.decorators);
        let adjusted_decorators =
            BasicBlockNode::adjust_decorators(self.decorators.clone(), &op_batches);
        for (raw_op_idx, decorator_id) in adjusted_decorators.iter() {
            bytes_to_hash.extend(raw_op_idx.to_le_bytes());
            bytes_to_hash.extend(forest[*decorator_id].fingerprint().as_bytes());
        }

        // Hash after_exit decorators last
        for decorator_id in &self.after_exit {
            bytes_to_hash.extend(forest[*decorator_id].fingerprint().as_bytes());
        }

        // Add any `Assert`, `U32assert2` and `MpVerify` opcodes present, since these are
        // not included in the MAST root.
        for (op_idx, op) in op_batches.iter().flat_map(|batch| batch.ops()).enumerate() {
            if let Operation::U32assert2(inner_value)
            | Operation::Assert(inner_value)
            | Operation::MpVerify(inner_value) = op
            {
                let op_idx: u32 = op_idx
                    .try_into()
                    .expect("there are more than 2^{32}-1 operations in basic block");

                // we include the opcode to differentiate between `Assert` and `U32assert2`
                bytes_to_hash.push(op.op_code());
                // we include the operation index to distinguish between basic blocks that
                // would have the same assert instructions, but in a different order
                bytes_to_hash.extend(op_idx.to_le_bytes());
                let inner_value = u64::from(*inner_value);
                bytes_to_hash.extend(inner_value.to_le_bytes());
            }
        }

        if bytes_to_hash.is_empty() {
            Ok(MastNodeFingerprint::new(digest))
        } else {
            let decorator_root = Blake3_256::hash(&bytes_to_hash);
            Ok(MastNodeFingerprint::with_decorator_root(digest, decorator_root))
        }
    }

    fn remap_children(self, _remapping: &crate::mast::Remapping) -> Self {
        // BasicBlockNode has no children to remap
        self
    }

    fn with_before_enter(mut self, decorators: impl Into<Vec<crate::mast::DecoratorId>>) -> Self {
        self.before_enter = decorators.into();
        self
    }

    fn with_after_exit(mut self, decorators: impl Into<Vec<crate::mast::DecoratorId>>) -> Self {
        self.after_exit = decorators.into();
        self
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for BasicBlockNodeBuilder {
    type Parameters = super::arbitrary::BasicBlockNodeParams;
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(params: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        use super::arbitrary::{decorator_id_strategy, op_non_control_sequence_strategy};

        (op_non_control_sequence_strategy(params.max_ops_len),)
            .prop_flat_map(move |(ops,)| {
                let ops_len = ops.len().max(1); // ensure at least 1 op
                // For builders, decorator indices must be strictly less than ops_len
                // because they reference actual operation positions
                prop::collection::vec(
                    (0..ops_len, decorator_id_strategy(params.max_decorator_id_u32)),
                    0..=params.max_pairs,
                )
                .prop_map(move |mut decorators| {
                    decorators.sort_by_key(|(i, _)| *i);
                    (ops.clone(), decorators)
                })
            })
            .prop_map(|(ops, decorators)| Self::new(ops, decorators))
            .boxed()
    }
}
