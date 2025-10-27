use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_core::{DebugOptions, Felt};
use miden_debug_types::{
    DefaultSourceManager, Location, SourceFile, SourceManager, SourceManagerSync, SourceSpan,
};

use crate::{
    AdviceMutation, AsyncHost, BaseHost, DebugHandler, EventError, ExecutionError, FutureMaybeSend,
    MastForest, MastForestStore, MemMastForestStore, ProcessState, SyncHost, Word,
};

/// A snapshot of the process state for consistency checking between processors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStateSnapshot {
    clk: u32,
    ctx: u32,
    stack_state: Vec<Felt>,
    stack_words: [Word; 4],
    mem_state: Vec<(crate::MemoryAddress, Felt)>,
}

impl From<&ProcessState<'_>> for ProcessStateSnapshot {
    fn from(state: &ProcessState) -> Self {
        ProcessStateSnapshot {
            clk: state.clk().into(),
            ctx: state.ctx().into(),
            stack_state: state.get_stack_state(),
            stack_words: [
                state.get_stack_word_be(0),
                state.get_stack_word_be(4),
                state.get_stack_word_be(8),
                state.get_stack_word_be(12),
            ],
            mem_state: state.get_mem_state(state.ctx()),
        }
    }
}

/// A debug handler that collects and counts trace events from decorators.
#[derive(Default, Debug)]
pub struct TraceCollector {
    /// Counts of each trace ID that has been emitted
    trace_counts: BTreeMap<u32, u32>,
    /// Execution order of trace events with their clock cycles
    execution_order: Vec<(u32, u64)>,
}

impl TraceCollector {
    /// Creates a new empty trace collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets the count of executions for a specific trace ID.
    pub fn get_trace_count(&self, trace_id: u32) -> u32 {
        self.trace_counts.get(&trace_id).copied().unwrap_or(0)
    }

    /// Gets the execution order as a reference.
    pub fn get_execution_order(&self) -> &[(u32, u64)] {
        &self.execution_order
    }
}

impl DebugHandler for TraceCollector {
    fn on_trace(&mut self, process: &ProcessState, trace_id: u32) -> Result<(), ExecutionError> {
        // Count the trace event
        *self.trace_counts.entry(trace_id).or_insert(0) += 1;

        // Record the execution order with clock cycle
        self.execution_order.push((trace_id, process.clk().into()));

        Ok(())
    }
}

/// A unified testing host that combines trace collection and process state consistency checking.
#[derive(Debug)]
pub struct TestConsistencyHost<S: SourceManager = DefaultSourceManager> {
    /// Trace collection functionality
    trace_collector: TraceCollector,

    /// Process state snapshots for consistency checking
    snapshots: BTreeMap<u32, Vec<ProcessStateSnapshot>>,

    /// MAST forest store for external node resolution
    store: MemMastForestStore,

    /// Source manager for debugging information
    source_manager: Arc<S>,
}

impl TestConsistencyHost {
    /// Creates a new TestConsistencyHost with minimal functionality for basic trace testing.
    pub fn new() -> Self {
        Self {
            trace_collector: TraceCollector::new(),
            snapshots: BTreeMap::new(),
            store: MemMastForestStore::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }

    /// Creates a new TestConsistencyHost with a kernel forest for full consistency testing.
    pub fn with_kernel_forest(kernel_forest: Arc<MastForest>) -> Self {
        let mut store = MemMastForestStore::default();
        store.insert(kernel_forest.clone());
        Self {
            trace_collector: TraceCollector::new(),
            snapshots: BTreeMap::new(),
            store,
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }

    /// Gets the count of executions for a specific trace ID.
    pub fn get_trace_count(&self, trace_id: u32) -> u32 {
        self.trace_collector.get_trace_count(trace_id)
    }

    /// Gets the execution order as a reference.
    pub fn get_execution_order(&self) -> &[(u32, u64)] {
        self.trace_collector.get_execution_order()
    }

    /// Gets mutable access to all snapshots.
    pub fn snapshots(&self) -> &BTreeMap<u32, Vec<ProcessStateSnapshot>> {
        &self.snapshots
    }
}

impl Default for TestConsistencyHost {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> BaseHost for TestConsistencyHost<S>
where
    S: SourceManager,
{
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }

    fn on_debug(
        &mut self,
        _process: &mut ProcessState,
        _options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        Ok(())
    }

    fn on_trace(
        &mut self,
        process: &mut ProcessState,
        trace_id: u32,
    ) -> Result<(), ExecutionError> {
        // Forward to trace collector for counting
        self.trace_collector.on_trace(process, trace_id)?;

        // Also collect process state snapshot for consistency checking
        let snapshot = ProcessStateSnapshot::from(&*process);
        self.snapshots.entry(trace_id).or_default().push(snapshot);

        Ok(())
    }

    fn on_assert_failed(&mut self, _process: &ProcessState, _err_code: crate::Felt) {
        // For testing, do nothing
    }
}

impl<S> SyncHost for TestConsistencyHost<S>
where
    S: SourceManager,
{
    fn get_mast_forest(&self, node_digest: &Word) -> Option<Arc<MastForest>> {
        self.store.get(node_digest)
    }

    fn on_event(&mut self, _process: &ProcessState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new()) // For testing, return empty mutations
    }
}

impl<S> AsyncHost for TestConsistencyHost<S>
where
    S: SourceManagerSync,
{
    #[allow(clippy::manual_async_fn)]
    fn get_mast_forest(&self, node_digest: &Word) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
        let result = <Self as SyncHost>::get_mast_forest(self, node_digest);
        async move { result }
    }

    #[allow(clippy::manual_async_fn)]
    fn on_event(
        &mut self,
        _process: &ProcessState,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        async move { Ok(Vec::new()) } // For testing, return empty mutations
    }
}
