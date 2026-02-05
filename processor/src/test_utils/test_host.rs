use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_core::{Felt, field::PrimeField64, operations::DebugOptions};
use miden_debug_types::{
    DefaultSourceManager, Location, SourceFile, SourceManager, SourceManagerSync, SourceSpan,
};

use crate::{
    DebugError, DebugHandler, FutureMaybeSend, Host, MastForestStore, MemMastForestStore,
    ProcessorState, TraceError, Word, advice::AdviceMutation, event::EventError, mast::MastForest,
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

/// A debug handler that collects and counts trace events from decorators.
#[derive(Default, Debug, Clone)]
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
    fn on_trace(&mut self, process: &ProcessorState, trace_id: u32) -> Result<(), TraceError> {
        // Count the trace event
        *self.trace_counts.entry(trace_id).or_insert(0) += 1;

        // Record the execution order with clock cycle
        self.execution_order.push((trace_id, process.clock().into()));

        Ok(())
    }
}

/// A unified testing host that combines trace collection, event handling,
/// debug handling, and process state consistency checking.
#[derive(Debug, Clone)]
pub struct TestHost<S: SourceManager = DefaultSourceManager> {
    /// Trace collection functionality (counts and execution order)
    trace_collector: TraceCollector,

    /// List of event IDs that have been received
    pub event_handler: Vec<u32>,

    /// List of debug command strings that have been received
    pub debug_handler: Vec<String>,

    /// Process state snapshots for consistency checking
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
            trace_collector: TraceCollector::new(),
            event_handler: Vec::new(),
            debug_handler: Vec::new(),
            snapshots: BTreeMap::new(),
            store: MemMastForestStore::default(),
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }

    /// Creates a new TestHost with a kernel forest for full consistency testing.
    pub fn with_kernel_forest(kernel_forest: Arc<MastForest>) -> Self {
        let mut store = MemMastForestStore::default();
        store.insert(kernel_forest.clone());
        Self {
            trace_collector: TraceCollector::new(),
            event_handler: Vec::new(),
            debug_handler: Vec::new(),
            snapshots: BTreeMap::new(),
            store,
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }

    /// Gets the count of executions for a specific trace ID.
    pub fn get_trace_count(&self, trace_id: u32) -> u32 {
        self.trace_collector.get_trace_count(trace_id)
    }

    /// Gets the execution order as a reference (with clock cycles).
    pub fn get_execution_order(&self) -> &[(u32, u64)] {
        self.trace_collector.get_execution_order()
    }

    /// Gets mutable access to all snapshots.
    pub fn snapshots(&self) -> &BTreeMap<u32, Vec<ProcessorStateSnapshot>> {
        &self.snapshots
    }
}

impl Default for TestHost {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Host for TestHost<S>
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

    fn get_mast_forest(&self, node_digest: &Word) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
        let result = self.store.get(node_digest);
        async move { result }
    }

    fn on_event(
        &mut self,
        process: &ProcessorState,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        let event_id: u32 = process.get_stack_item(0).as_canonical_u64().try_into().unwrap();
        self.event_handler.push(event_id);
        async move { Ok(Vec::new()) }
    }

    fn on_debug(
        &mut self,
        _process: &ProcessorState,
        options: &DebugOptions,
    ) -> Result<(), DebugError> {
        self.debug_handler.push(options.to_string());
        Ok(())
    }

    fn on_trace(&mut self, process: &ProcessorState, trace_id: u32) -> Result<(), TraceError> {
        // Forward to trace collector for counting and execution order tracking
        self.trace_collector.on_trace(process, trace_id)?;

        // Also collect process state snapshot for consistency checking
        let snapshot = ProcessorStateSnapshot::from(process);
        self.snapshots.entry(trace_id).or_default().push(snapshot);

        Ok(())
    }
}
