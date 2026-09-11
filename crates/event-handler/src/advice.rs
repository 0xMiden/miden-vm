use alloc::{sync::Arc, vec::Vec};

use miden_core::{Felt, Word, advice::AdviceStack, crypto::merkle::InnerNodeInfo};

/// Pending advice owned by the execution engine, separate from the recorder lent to a callback.
///
/// The engine must discard this batch if the callback fails or is cancelled. On success it must
/// reject trace output, then validate the COMPLETE regular-event batch against live state and the
/// aggregate advice budget before applying anything. Validation and application must not suspend.
/// This buffer does not validate live state or apply advice itself.
#[derive(Debug, Default)]
pub struct AdviceBatch {
    stack: AdviceStack,
    map_entries: Vec<(Word, Arc<[Felt]>)>,
    nodes: Vec<InnerNodeInfo>,
}

impl AdviceBatch {
    /// Creates an empty engine-owned batch, also usable to isolate a fallible child handler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows a recorder. Dropping or replacing this recorder retains all previously staged
    /// output.
    pub fn recorder(&mut self) -> AdviceRecorder<'_> {
        AdviceRecorder { batch: self }
    }

    /// Reports whether any output was recorded, including idempotent or empty map insertions.
    /// Empty stack and Merkle iterators record nothing.
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty() && self.map_entries.is_empty() && self.nodes.is_empty()
    }

    /// Consumes the batch for engine validation and application, returning the stack in final
    /// top-to-bottom order, ALL map insertions in recording order, and Merkle nodes in insertion
    /// order. Duplicate map entries must be checked for conflicts before deduplication. Equal
    /// repeats are accepted and new equal entries are charged only once against the advice budget.
    pub fn into_parts(self) -> (AdviceStack, Vec<(Word, Arc<[Felt]>)>, Vec<InnerNodeInfo>) {
        (self.stack, self.map_entries, self.nodes)
    }
}

/// A borrowed, append-only recorder of typed pending advice.
///
/// Helpers share pending output: catching a helper error does not erase its writes. For isolated
/// failure, invoke the helper with a child [`AdviceBatch`] and import that batch only on success.
pub struct AdviceRecorder<'a> {
    batch: &'a mut AdviceBatch,
}

impl AdviceRecorder<'_> {
    /// Prepends a block ordered top-to-bottom. Recording `[a,b]` and then `[c,d]` results in
    /// `[c,d,a,b,old…]`. An empty iterator records no output.
    pub fn prepend_stack(&mut self, values: impl IntoIterator<Item = Felt>) {
        self.batch.stack.prepend_elements(values);
    }

    /// Records one map insertion, including an empty value. Conflicting values for the same key
    /// are retained for engine validation, including conflicts within child batches.
    pub fn insert_map_entry(&mut self, key: Word, values: impl Into<Arc<[Felt]>>) {
        self.batch.map_entries.push((key, values.into()));
    }

    /// Records nodes in insertion order. An empty iterator records no output.
    pub fn extend_merkle_store(&mut self, nodes: impl IntoIterator<Item = InnerNodeInfo>) {
        self.batch.nodes.extend(nodes);
    }

    /// Imports a successfully completed child batch without validation or commitment. This public
    /// engine/composition interface preserves duplicate map entries and the child's stack order;
    /// the top-level engine still validates the complete output before application.
    pub fn import(&mut self, child: AdviceBatch) {
        self.batch.stack.prepend_stack(child.stack);
        self.batch.map_entries.extend(child.map_entries);
        self.batch.nodes.extend(child.nodes);
    }
}
