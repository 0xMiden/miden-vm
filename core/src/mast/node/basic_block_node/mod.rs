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

use crate::{
    DecoratorList, Operation,
    chiplets::hasher,
    mast::{
        DecoratedLinksIter, DecoratedOpLink, DecoratorId, MastForest, MastForestError, MastNode,
        MastNodeFingerprint, MastNodeId,
    },
};

mod op_batch;
pub use op_batch::OpBatch;
use op_batch::OpBatchAccumulator;

use super::{MastForestContributor, MastNodeErrorContext, MastNodeExt};
use crate::mast::DecoratorStore;

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
pub struct BasicBlockNode {
    /// The primitive operations contained in this basic block.
    ///
    /// The operations are broken up into batches of 8 groups, with each group containing up to 9
    /// operations, or a single immediates. Thus the maximum size of each batch is 72 operations.
    /// Multiple batches are used for blocks consisting of more than 72 operations.
    op_batches: Vec<OpBatch>,
    digest: Word,
    /// Stores both operation-level and node-level decorators
    /// Custom serialization is handled via Serialize/Deserialize impls
    decorators: DecoratorStore,
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
    /// Returns a new [`BasicBlockNode`] instantiated with the specified operations and decorators.
    ///
    /// Returns an error if:
    /// - `operations` vector is empty.
    #[cfg(any(test, feature = "arbitrary"))]
    pub(crate) fn new(
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
            decorators: DecoratorStore::Owned {
                decorators: reflowed_decorators,
                before_enter: Vec::new(),
                after_exit: Vec::new(),
            },
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
    /// This method borrows from the forest's storage, avoiding unnecessary Arc clones and providing
    /// efficient access to decorators.
    ///
    /// This iterator is intended for e.g. processor consumption, as such a component iterates
    /// differently through block operations: contrarily to e.g. the implementation of
    /// [`MastNodeErrorContext`] this does not include the `before_enter` or `after_exit`
    /// decorators.
    pub fn indexed_decorator_iter<'a>(
        &'a self,
        forest: &'a MastForest,
    ) -> DecoratorOpLinkIterator<'a> {
        match &self.decorators {
            DecoratorStore::Owned { decorators, .. } => {
                // For owned decorators, use the existing logic
                DecoratorOpLinkIterator::from_slice_iters(
                    &[],
                    decorators,
                    &[],
                    self.num_operations() as usize,
                )
            },
            DecoratorStore::Linked { id } => {
                // For linked nodes, borrow from forest storage
                // Check if the node has any decorators at all
                let has_decorators = forest
                    .decorator_links_for_node(*id)
                    .map(|links| links.into_iter().next().is_some())
                    .unwrap_or(false);

                if !has_decorators {
                    let num_ops = self.num_operations() as usize;
                    return DecoratorOpLinkIterator::from_slice_iters(&[], &[], &[], num_ops);
                }

                let view = forest.decorator_links_for_node(*id).expect(
                    "linked node decorators should be available; forest may be inconsistent",
                );

                DecoratorOpLinkIterator::from_linked(
                    &[],
                    view.into_iter(),
                    &[],
                    self.num_operations() as usize,
                )
            },
        }
    }

    /// Returns an iterator which allows us to iterate through the decorator list of
    /// this basic block node with op indexes aligned to the "raw" (un-padded)) op
    /// batches of the basic block node.
    ///
    /// Though this adjusts the indexation of op-indexed decorators, this iterator returns all
    /// decorators of the [`BasicBlockNode`] in the order in which they appear in the program.
    /// This includes `before_enter`, op-indexed decorators, and after_exit.
    ///
    /// Returns an iterator which allows us to iterate through the decorator list of
    /// this basic block node with op indexes aligned to the "raw" (un-padded)) op
    /// batches of the basic block node.
    ///
    /// This method borrows from the forest's storage, avoiding unnecessary Arc clones and
    /// providing efficient access to decorators.
    ///
    /// Though this adjusts the indexation of op-indexed decorators, this iterator returns all
    /// decorators of the [`BasicBlockNode`] in the order in which they appear in the program.
    /// This includes `before_enter`, op-indexed decorators, and after_exit`.
    pub fn raw_decorator_iter<'a>(
        &'a self,
        forest: &'a MastForest,
    ) -> RawDecoratorOpLinkIterator<'a> {
        match &self.decorators {
            DecoratorStore::Owned { decorators, before_enter, after_exit } => {
                // For owned decorators, use the existing logic
                RawDecoratorOpLinkIterator::from_slice_iters(
                    before_enter,
                    decorators,
                    after_exit,
                    &self.op_batches,
                )
            },
            DecoratorStore::Linked { id } => {
                // For linked nodes, borrow from forest storage
                // Check if the node has any decorators at all
                let has_decorators = forest
                    .decorator_links_for_node(*id)
                    .map(|links| links.into_iter().next().is_some())
                    .unwrap_or(false);

                if !has_decorators {
                    // No operation-level decorators, but still need node-level decorators
                    let before_enter = forest.node_decorator_storage.get_before_decorators(*id);
                    let after_exit = forest.node_decorator_storage.get_after_decorators(*id);
                    return RawDecoratorOpLinkIterator::from_slice_iters(
                        before_enter,
                        &[],
                        after_exit,
                        &self.op_batches,
                    );
                }

                let view = forest.decorator_links_for_node(*id).expect(
                    "linked node decorators should be available; forest may be inconsistent",
                );

                // Get node-level decorators from NodeToDecoratorIds
                let before_enter = forest.node_decorator_storage.get_before_decorators(*id);
                let after_exit = forest.node_decorator_storage.get_after_decorators(*id);

                RawDecoratorOpLinkIterator::from_linked(
                    before_enter,
                    view.into_iter(),
                    after_exit,
                    &self.op_batches,
                )
            },
        }
    }

    /// Returns only the raw op-indexed decorators (without before_enter/after_exit)
    /// with indices based on raw operations.
    ///
    /// Stores decorators with raw operation indices for serialization.
    ///
    /// Returns only the raw op-indexed decorators (without before_enter/after_exit)
    /// with indices based on raw operations.
    ///
    /// This method borrows from the forest's storage, avoiding unnecessary Arc clones and
    /// providing efficient access to decorators.
    ///
    /// Stores decorators with raw operation indices for serialization.
    pub fn raw_op_indexed_decorators(&self, forest: &MastForest) -> Vec<(usize, DecoratorId)> {
        match &self.decorators {
            DecoratorStore::Owned { decorators, .. } => {
                // For owned decorators, use the existing logic
                RawDecoratorOpLinkIterator::from_slice_iters(&[], decorators, &[], &self.op_batches)
                    .collect()
            },
            DecoratorStore::Linked { id } => {
                let pad2raw = PaddedToRawPrefix::new(self.op_batches());
                match forest.decorator_links_for_node(*id) {
                    Ok(links) => links
                        .into_iter()
                        .map(|(padded_idx, dec_id)| {
                            let raw_idx = padded_idx - pad2raw[padded_idx];
                            (raw_idx, dec_id)
                        })
                        .collect(),
                    Err(_) => Vec::new(), // Return empty if error
                }
            },
        }
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
    pub fn num_operations_and_decorators(&self, forest: &MastForest) -> u32 {
        let num_ops: usize = self.num_operations() as usize;
        let num_decorators = match &self.decorators {
            DecoratorStore::Owned { decorators, .. } => decorators.len(),
            DecoratorStore::Linked { id } => {
                // For linked nodes, count from forest storage
                forest
                    .decorator_links_for_node(*id)
                    .map(|links| links.into_iter().count())
                    .unwrap_or(0)
            },
        };

        (num_ops + num_decorators)
            .try_into()
            .expect("basic block contains more than 2^32 operations and decorators")
    }

    /// Returns an iterator over all operations and decorator, in the order in which they appear in
    /// the program.
    ///
    /// This method requires access to the forest to properly handle linked nodes.
    pub fn iter<'a>(
        &'a self,
        forest: &'a MastForest,
    ) -> impl Iterator<Item = OperationOrDecorator<'a>> + 'a {
        OperationOrDecoratorIterator::new_with_forest(self, forest)
    }

    /// Performs semantic equality comparison with another BasicBlockNode.
    ///
    /// This method compares two blocks for logical equality by comparing:
    /// - Operations (exact equality)
    /// - Before-enter decorators (by ID)
    /// - After-exit decorators (by ID)
    /// - Operation-indexed decorators (by iterating and comparing their contents)
    ///
    /// Unlike the derived PartialEq, this method works correctly with both owned and linked
    /// decorator storage by accessing the actual decorator data from the forest when needed.
    #[cfg(test)]
    pub fn semantic_eq(&self, other: &BasicBlockNode, forest: &MastForest) -> bool {
        // Compare operations by collecting and comparing
        let self_ops: Vec<_> = self.operations().collect();
        let other_ops: Vec<_> = other.operations().collect();
        if self_ops != other_ops {
            return false;
        }

        // Compare before-enter decorators
        if self.before_enter(forest) != other.before_enter(forest) {
            return false;
        }

        // Compare after-exit decorators
        if self.after_exit(forest) != other.after_exit(forest) {
            return false;
        }

        // Compare operation-indexed decorators by collecting and comparing
        let self_decorators: Vec<_> = self.indexed_decorator_iter(forest).collect();
        let other_decorators: Vec<_> = other.indexed_decorator_iter(forest).collect();

        if self_decorators != other_decorators {
            return false;
        }

        true
    }
}

#[allow(refining_impl_trait_reachable)]
impl MastNodeErrorContext for BasicBlockNode {
    /// Returns all decorators in program order: before_enter, op-indexed, after_exit.
    fn decorators<'a>(
        &'a self,
        forest: &'a MastForest,
    ) -> impl Iterator<Item = DecoratedOpLink> + 'a {
        match &self.decorators {
            DecoratorStore::Owned { decorators, before_enter, after_exit } => {
                DecoratorOpLinkIterator::from_slice_iters(
                    before_enter,
                    decorators,
                    after_exit,
                    self.num_operations() as usize,
                )
            },
            DecoratorStore::Linked { id } => {
                // For linked nodes, borrow from forest storage
                let view = forest.decorator_links_for_node(*id).expect(
                    "linked node decorators should be available; forest may be inconsistent",
                );

                // Get node-level decorators from NodeToDecoratorIds
                let before_enter = forest.node_decorator_storage.get_before_decorators(*id);
                let after_exit = forest.node_decorator_storage.get_after_decorators(*id);

                DecoratorOpLinkIterator::from_linked(
                    before_enter,
                    view.into_iter(),
                    after_exit,
                    self.num_operations() as usize,
                )
            },
        }
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

    fn before_enter<'a>(&'a self, forest: &'a MastForest) -> &'a [DecoratorId] {
        match &self.decorators {
            DecoratorStore::Owned { before_enter, .. } => before_enter,
            DecoratorStore::Linked { id } => {
                // For linked nodes, get the decorators from the forest's NodeToDecoratorIds
                forest.node_decorator_storage.get_before_decorators(*id)
            },
        }
    }

    fn after_exit<'a>(&'a self, forest: &'a MastForest) -> &'a [DecoratorId] {
        match &self.decorators {
            DecoratorStore::Owned { after_exit, .. } => after_exit,
            DecoratorStore::Linked { id } => {
                // For linked nodes, get the decorators from the forest's NodeToDecoratorIds
                forest.node_decorator_storage.get_after_decorators(*id)
            },
        }
    }

    /// Removes all decorators from this node.
    fn remove_decorators(&mut self) {
        self.decorators = DecoratorStore::Owned {
            decorators: Vec::new(),
            before_enter: Vec::new(),
            after_exit: Vec::new(),
        };
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

    fn to_builder(self, forest: &MastForest) -> Self::Builder {
        let operations: Vec<Operation> = self.raw_operations().cloned().collect();
        let un_adjusted_decorators = self.raw_op_indexed_decorators(forest);

        let (before_enter, after_exit) = match self.decorators {
            DecoratorStore::Owned { before_enter, after_exit, .. } => (before_enter, after_exit),
            DecoratorStore::Linked { id } => {
                // For linked nodes, get the decorators from the forest's NodeToDecoratorIds
                let before_enter = forest.node_decorator_storage.get_before_decorators(id).to_vec();
                let after_exit = forest.node_decorator_storage.get_after_decorators(id).to_vec();
                (before_enter, after_exit)
            },
        };

        BasicBlockNodeBuilder::new(operations, un_adjusted_decorators)
            .with_before_enter(before_enter)
            .with_after_exit(after_exit)
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
                .iter(self.mast_forest)
                .map(|op_or_dec| match op_or_dec {
                    OperationOrDecorator::Operation(op) => op.render(),
                    OperationOrDecorator::Decorator(decorator_id) => self.mast_forest[decorator_id].render(),
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
                    .iter(self.mast_forest)
                    .map(|op_or_dec| match op_or_dec {
                        OperationOrDecorator::Operation(op) => op.render(),
                        OperationOrDecorator::Decorator(decorator_id) => self.mast_forest[decorator_id].render(),
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

enum Mid<'a> {
    Slice(core::iter::Peekable<core::slice::Iter<'a, (usize, DecoratorId)>>),
    Linked(core::iter::Peekable<DecoratedLinksIter<'a>>),
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
    middle: Mid<'a>,
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
    pub fn from_slice_iters(
        before_enter: &'a [DecoratorId],
        decorators: &'a [DecoratedOpLink],
        after_exit: &'a [DecoratorId],
        total_operations: usize,
    ) -> Self {
        Self {
            before: before_enter.iter().peekable(),
            middle: Mid::Slice(decorators.iter().peekable()),
            after: after_exit.iter().peekable(),
            total_ops: total_operations,
            seg: Segment::Before,
        }
    }

    pub fn from_linked(
        before_enter: &'a [DecoratorId],
        decorators: DecoratedLinksIter<'a>,
        after_exit: &'a [DecoratorId],
        total_operations: usize,
    ) -> Self {
        Self {
            before: before_enter.iter().peekable(),
            middle: Mid::Linked(decorators.into_iter().peekable()),
            after: after_exit.iter().peekable(),
            total_ops: total_operations,
            seg: Segment::Before,
        }
    }

    fn middle_next(&mut self) -> Option<(usize, DecoratorId)> {
        match &mut self.middle {
            Mid::Slice(slice_iter) => slice_iter.next().copied(),
            Mid::Linked(linked_iter) => linked_iter.next(),
        }
    }

    fn middle_peek(&mut self) -> Option<&(usize, DecoratorId)> {
        match &mut self.middle {
            Mid::Slice(slice_iter) => slice_iter.peek().copied(),
            Mid::Linked(linked_iter) => linked_iter.peek(),
        }
    }

    fn middle_len(&self) -> usize {
        match self.middle {
            Mid::Slice(ref slice_iter) => slice_iter.len(),
            Mid::Linked(ref linked_iter) => linked_iter.len(),
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
                    if let Some(&(p, _)) = self.middle_peek() {
                        should_yield = pos == p;
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
                    if let Some((pos, id)) = self.middle_next() {
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
        self.before.len() + self.middle_len() + self.after.len()
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
    middle: RawMid<'a>,
    after: core::slice::Iter<'a, DecoratorId>,
    pad2raw: PaddedToRawPrefix, // indexed by padded indices
    total_raw_ops: usize,       // count of raw ops
    seg: Segment,
}

enum RawMid<'a> {
    Slice(core::iter::Peekable<core::slice::Iter<'a, (usize, DecoratorId)>>),
    Linked(core::iter::Peekable<DecoratedLinksIter<'a>>),
}

impl<'a> RawDecoratorOpLinkIterator<'a> {
    pub fn from_slice_iters(
        before_enter: &'a [DecoratorId],
        decorators: &'a [(usize, DecoratorId)], // contains adjusted indices
        after_exit: &'a [DecoratorId],
        op_batches: &'a [OpBatch],
    ) -> Self {
        let pad2raw = PaddedToRawPrefix::new(op_batches);
        let raw2pad = RawToPaddedPrefix::new(op_batches);
        let total_raw_ops = raw2pad.raw_ops();

        Self {
            before: before_enter.iter(),
            middle: RawMid::Slice(decorators.iter().peekable()),
            after: after_exit.iter(),
            pad2raw,
            total_raw_ops,
            seg: Segment::Before,
        }
    }

    pub fn from_linked(
        before_enter: &'a [DecoratorId],
        decorators: DecoratedLinksIter<'a>,
        after_exit: &'a [DecoratorId],
        op_batches: &'a [OpBatch],
    ) -> Self {
        let pad2raw = PaddedToRawPrefix::new(op_batches);
        let raw2pad = RawToPaddedPrefix::new(op_batches);
        let total_raw_ops = raw2pad.raw_ops();

        Self {
            before: before_enter.iter(),
            middle: RawMid::Linked(decorators.into_iter().peekable()),
            after: after_exit.iter(),
            pad2raw,
            total_raw_ops,
            seg: Segment::Before,
        }
    }

    fn middle_next(&mut self) -> Option<(usize, DecoratorId)> {
        match &mut self.middle {
            RawMid::Slice(slice_iter) => slice_iter.next().copied(),
            RawMid::Linked(linked_iter) => linked_iter.next(),
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
                    if let Some((padded_idx, id)) = self.middle_next() {
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
    Decorator(DecoratorId),
}

struct OperationOrDecoratorIterator<'a> {
    node: &'a BasicBlockNode,
    forest: Option<&'a MastForest>,

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
    fn new_with_forest(node: &'a BasicBlockNode, forest: &'a MastForest) -> Self {
        Self {
            node,
            forest: Some(forest),
            before: node.before_enter(forest).iter(),
            after: node.after_exit(forest).iter(),
            batch_index: 0,
            op_index_in_batch: 0,
            op_index: 0,
            decorator_list_next_index: 0,
            seg: Segment::Before,
        }
    }

    #[inline]
    fn next_decorator_if_due(&mut self) -> Option<OperationOrDecorator<'a>> {
        match &self.node.decorators {
            DecoratorStore::Owned { decorators, .. } => {
                // Simple case for owned decorators - use index lookup
                if let Some((op_idx, deco)) = decorators.get(self.decorator_list_next_index)
                    && *op_idx == self.op_index
                {
                    self.decorator_list_next_index += 1;
                    Some(OperationOrDecorator::Decorator(*deco))
                } else {
                    None
                }
            },
            DecoratorStore::Linked { id } => {
                // For linked nodes, use forest access if available
                if let Some(forest) = self.forest {
                    // Get decorators for the current operation from the forest
                    let decorator_ids = forest.decorator_indices_for_op(*id, self.op_index);

                    if self.decorator_list_next_index < decorator_ids.len() {
                        let decorator_id = decorator_ids[self.decorator_list_next_index];
                        self.decorator_list_next_index += 1;
                        Some(OperationOrDecorator::Decorator(decorator_id))
                    } else {
                        None
                    }
                } else {
                    // No forest access available, can't retrieve decorators
                    None
                }
            },
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
                        return Some(OperationOrDecorator::Decorator(*id));
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
                            // Reset decorator index when moving to a new operation
                            self.decorator_list_next_index = 0;
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
                        return Some(OperationOrDecorator::Decorator(*id));
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
        // assert the last index in decorator list is less than or equal to operations vector length
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
    digest: Option<Word>,
}

impl BasicBlockNodeBuilder {
    /// Creates a new builder for a BasicBlockNode with the specified operations and decorators.
    pub fn new(operations: Vec<Operation>, decorators: DecoratorList) -> Self {
        Self {
            operations,
            decorators,
            before_enter: Vec::new(),
            after_exit: Vec::new(),
            digest: None,
        }
    }

    /// Used to initialize decorators for the [`BasicBlockNodeBuilder`]. Replaces the existing
    /// decorators with the given ['DecoratorList'].
    pub(crate) fn set_decorators(&mut self, decorators: DecoratorList) {
        self.decorators = decorators;
    }

    /// Builds the BasicBlockNode with the specified decorators.
    pub fn build(self) -> Result<BasicBlockNode, MastForestError> {
        if self.operations.is_empty() {
            return Err(MastForestError::EmptyBasicBlock);
        }

        // Validate decorators list (only in debug mode).
        #[cfg(debug_assertions)]
        validate_decorators(self.operations.len(), &self.decorators);

        let (op_batches, computed_digest) = batch_and_hash_ops(self.operations);
        // the prior line may have inserted some padding Noops in the op_batches
        // the decorator mapping should still point to the correct operation when that happens
        let reflowed_decorators = BasicBlockNode::adjust_decorators(self.decorators, &op_batches);

        // Use the forced digest if provided, otherwise use the computed digest
        let digest = self.digest.unwrap_or(computed_digest);

        Ok(BasicBlockNode {
            op_batches,
            digest,
            decorators: DecoratorStore::Owned {
                decorators: reflowed_decorators,
                before_enter: self.before_enter.clone(),
                after_exit: self.after_exit.clone(),
            },
        })
    }
}

impl BasicBlockNodeBuilder {
    /// Add this node to a forest using relaxed validation.
    ///
    /// This method is used during deserialization where nodes may reference child nodes
    /// that haven't been added to the forest yet. The child node IDs have already been
    /// validated against the expected final node count during the `try_into_mast_node_builder`
    /// step, so we can safely skip validation here.
    ///
    /// Note: This is not part of the `MastForestContributor` trait because it's only
    /// intended for internal use during deserialization.
    ///
    /// For BasicBlockNode, this is equivalent to the normal `add_to_forest` since basic blocks
    /// don't have child nodes to validate.
    pub(in crate::mast) fn add_to_forest_relaxed(
        self,
        forest: &mut MastForest,
    ) -> Result<MastNodeId, MastForestError> {
        // BasicBlockNode doesn't have child dependencies, so relaxed validation is the same
        // as normal validation. We delegate to the normal method for consistency.
        self.add_to_forest(forest)
    }
}

impl MastForestContributor for BasicBlockNodeBuilder {
    fn add_to_forest(self, forest: &mut MastForest) -> Result<MastNodeId, MastForestError> {
        let basic_block = self.build()?;

        let BasicBlockNode {
            op_batches,
            digest,
            decorators:
                DecoratorStore::Owned {
                    decorators: decorators_info,
                    before_enter,
                    after_exit,
                },
        } = basic_block
        else {
            unreachable!("BasicBlockBuilder::build() should always return owned decorators");
        };

        // Determine the node ID that will be assigned
        let future_node_id = MastNodeId::new_unchecked(forest.nodes.len() as u32);

        // Add decorator info to the forest storage
        forest
            .op_decorator_storage
            .add_decorator_info_for_node(future_node_id, decorators_info)
            .map_err(MastForestError::DecoratorError)?;

        // Add node-level decorators to the centralized NodeToDecoratorIds for efficient access
        forest.node_decorator_storage.add_node_decorators(
            future_node_id,
            &before_enter,
            &after_exit,
        );

        // Create the node in the forest with Linked variant from the start
        // Move the data directly without intermediate cloning
        let node_id = forest
            .nodes
            .push(MastNode::Block(BasicBlockNode {
                op_batches,
                digest,
                decorators: DecoratorStore::Linked { id: future_node_id },
            }))
            .map_err(|_| MastForestError::TooManyNodes)?;

        // The decorator info was already added to forest storage, so we're done
        Ok(node_id)
    }

    fn fingerprint_for_node(
        &self,
        forest: &MastForest,
        _hash_by_node_id: &impl crate::LookupByIdx<MastNodeId, crate::mast::MastNodeFingerprint>,
    ) -> Result<crate::mast::MastNodeFingerprint, MastForestError> {
        // For BasicBlockNode, we need to implement custom logic because BasicBlock has special
        // decorator handling with operation indices that other nodes don't have

        // Compute digest - use forced digest if available, otherwise compute normally
        let (_op_batches, computed_digest) = batch_and_hash_ops(self.operations.clone());
        let digest = self.digest.unwrap_or(computed_digest);

        // Hash before_enter decorators first
        let mut bytes_to_hash = Vec::new();
        for decorator_id in &self.before_enter {
            bytes_to_hash.extend(forest[*decorator_id].fingerprint().as_bytes());
        }

        // Hash op-indexed decorators using the same logic as node.indexed_decorator_iter()
        #[cfg(debug_assertions)]
        {
            let decorators = self.decorators.clone();
            validate_decorators(self.operations.len(), &decorators);
        }
        // For BasicBlockNodeBuilder, convert from padded to raw indices
        let (op_batches, _) = batch_and_hash_ops(self.operations.clone());
        let pad2raw = PaddedToRawPrefix::new(&op_batches);
        let adjusted_decorators: Vec<(usize, DecoratorId)> = self
            .decorators
            .iter()
            .map(|(padded_idx, decorator_id)| {
                let raw_idx = padded_idx - pad2raw[*padded_idx];
                (raw_idx, *decorator_id)
            })
            .collect();
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

    fn remap_children(
        self,
        _remapping: &impl crate::LookupByIdx<crate::mast::MastNodeId, crate::mast::MastNodeId>,
    ) -> Self {
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

    fn append_before_enter(
        &mut self,
        decorators: impl IntoIterator<Item = crate::mast::DecoratorId>,
    ) {
        self.before_enter.extend(decorators);
    }

    fn append_after_exit(
        &mut self,
        decorators: impl IntoIterator<Item = crate::mast::DecoratorId>,
    ) {
        self.after_exit.extend(decorators);
    }

    fn with_digest(mut self, digest: crate::Word) -> Self {
        self.digest = Some(digest);
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
