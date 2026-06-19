use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_core::Felt;
use miden_debug_types::{
    DefaultSourceManager, Location, SourceFile, SourceManager, SourceManagerSync, SourceSpan,
};

use crate::{
    BaseHost, LoadedMastForest, MastForestStore, MemMastForestStore, ProcessorState, SyncHost,
    Word, advice::AdviceMutation, event::EventError, mast::MastForest,
};

/// A snapshot of the processor state for consistency checking between processors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessorStateSnapshot {
    clk: u32,
    ctx: u32,
    stack_state: Vec<Felt>,
    stack_words: [Word; 4],
    mem_state: Vec<(crate::MemoryAddress, Felt)>,
}

impl From<&ProcessorState<'_>> for ProcessorStateSnapshot {
    fn from(state: &ProcessorState) -> Self {
        ProcessorStateSnapshot {
            clk: state.clock().into(),
            ctx: state.ctx().into(),
            stack_state: state.get_stack_state(),
            stack_words: [
                state.get_stack_word(0),
                state.get_stack_word(4),
                state.get_stack_word(8),
                state.get_stack_word(12),
            ],
            mem_state: state.get_mem_state(state.ctx()),
        }
    }
}

impl ProcessorStateSnapshot {
    /// Captures the user-visible state at an `emit` checkpoint.
    ///
    /// The checkpoint pattern used by tests is `push.<event> emit drop`, so the host observes the
    /// event ID at the top of the stack. The checkpoint snapshot skips that synthetic stack item to
    /// match the state after the trailing `drop`, and to preserve the old trace-decorator test
    /// shape.
    fn from_emit_checkpoint(state: &ProcessorState) -> Self {
        let mut stack_state = state.get_stack_state();
        if !stack_state.is_empty() {
            stack_state.remove(0);
        }

        ProcessorStateSnapshot {
            clk: state.clock().into(),
            ctx: state.ctx().into(),
            stack_state,
            stack_words: [
                state.get_stack_word(1),
                state.get_stack_word(5),
                state.get_stack_word(9),
                state.get_stack_word(13),
            ],
            mem_state: state.get_mem_state(state.ctx()),
        }
    }
}

/// A unified testing host that combines event handling, debug handling, and external node
/// resolution.
#[derive(Debug, Clone)]
pub struct TestHost<S: SourceManager = DefaultSourceManager> {
    /// List of event IDs that have been received
    pub event_handler: Vec<u32>,

    /// Process state snapshots captured at emitted test checkpoints.
    snapshots: BTreeMap<u32, Vec<ProcessorStateSnapshot>>,

    /// MAST forest store for external node resolution
    store: MemMastForestStore,

    /// Source manager for debugging information
    pub source_manager: Arc<S>,
}

impl TestHost {
    /// Creates a new TestHost with minimal functionality for basic testing.
    pub fn new() -> Self {
        Self {
            event_handler: Vec::new(),
            snapshots: BTreeMap::new(),
            store: MemMastForestStore::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }

    /// Creates a new TestHost with a kernel forest for full consistency testing.
    pub fn with_kernel_forest(kernel_forest: Arc<MastForest>) -> Self {
        let mut store = MemMastForestStore::default();
        store.insert(kernel_forest);
        Self {
            event_handler: Vec::new(),
            snapshots: BTreeMap::new(),
            store,
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }

    /// Gets the processor state snapshots captured by emitted test checkpoints.
    pub fn snapshots(&self) -> &BTreeMap<u32, Vec<ProcessorStateSnapshot>> {
        &self.snapshots
    }
}

impl Default for TestHost {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> BaseHost for TestHost<S>
where
    S: SourceManagerSync,
{
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }
}

impl<S> SyncHost for TestHost<S>
where
    S: SourceManagerSync,
{
    fn get_mast_forest(&self, node_digest: &Word) -> Option<LoadedMastForest> {
        self.store.get(node_digest)
    }

    fn on_event(&mut self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let event_id: u32 = process.get_stack_item(0).as_canonical_u64().try_into().unwrap();
        self.event_handler.push(event_id);
        self.snapshots
            .entry(event_id)
            .or_default()
            .push(ProcessorStateSnapshot::from_emit_checkpoint(process));
        Ok(Vec::new())
    }
}
